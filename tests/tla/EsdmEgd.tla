------------------------------- MODULE EsdmEgd -------------------------------
(***************************************************************************)
(* The event loop of the ESDM EGD server: service-egd/server/              *)
(* esdm_egd_server.c, one worker thread serving every client of both EGD   *)
(* sockets. One step is one system call or one command; the labels name   *)
(* the C functions they come from.                                        *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - A request is one whole command (<<id, kind, units>>); kinds stand for *)
(*   the command classes: "cnt" is answered from the state (0x00, 0x04,    *)
(*   0xe3-0xe5), "nb" is a non-blocking read (0x01, 0xe0, 0xe2, 0xeb),     *)
(*   "blk" a blocking read (0x02, 0xe1), "wr" a write without response     *)
(*   (0x03), "priv" a privileged command (0xe6-0xea). conn->in holds       *)
(*   BufCmds commands; a command split across reads is left out.           *)
(* - A response goes out whole or not at all: a partial send() leaves the  *)
(*   rest pending just as EAGAIN does. The client's socket holds SndBuf    *)
(*   responses, the server's receive queue SqCap requests.                 *)
(* - Processing a command is one step: its generation, esdm_egd_write()    *)
(*   and the first send(). Nothing but the client can interleave there,    *)
(*   and a client closing before the step has the same effect.             *)
(* - The generators: until the environment turns good, one non-blocking    *)
(*   generation of n units yields any amount from 0 to n, an error with    *)
(*   GenFail, and a non-blocking read that got nothing may find the ESDM   *)
(*   operational (a reseed is awaited, the read is parked) or not. Which   *)
(*   reads can be parked depends on the command, not only on the socket    *)
(*   (0xe2 always can, 0xe0 never), so "nb" may be parked on either. Once  *)
(*   good, every generation yields all it is asked for.                    *)
(* - The calls of the worker that could wait return instead: the sockets   *)
(*   are non-blocking (EAGAIN from recv() and send()), a generation that   *)
(*   cannot deliver returns what it has. Block names the calls that wait   *)
(*   instead, for the configurations showing WorkerNeverBlocks fail. The   *)
(*   locks the ESDM takes inside a call are left to EsdmReseed and         *)
(*   EsdmAuxPool.                                                          *)
(* - epoll is level-triggered: epoll_wait() returns min(ready, MaxEvents)  *)
(*   of the ready descriptors with their flags at that moment, in any      *)
(*   order, or none after its timeout. The timeouts, deferred_progress and *)
(*   deferred_requests only set the pace and are left out, as is the park  *)
(*   time: a parked read may expire at any later attempt. The retry time   *)
(*   of a failed accept passes in an epoll_wait() that times out.          *)
(* - The write timeout may reclaim a connection whose response stayed      *)
(*   pending through a pass of the retry walk (Stall).                     *)
(* - A client has one connection; its UID is latched at accept (peer_uid,  *)
(*   the field root; Root is the truth it is checked against).             *)
(* - Not modelled: shutdown (esdm_egd_exit), the bulk insert 0xec, the     *)
(*   status buffers (out_heap behaves as out), unknown commands, failures  *)
(*   of calloc(), getsockopt() and epoll_ctl(), and what the ESDM does     *)
(*   inside a generation (EsdmReseed).                                     *)
(*                                                                         *)
(* The model is a server that does not end: the worker always has the      *)
(* timeout of epoll_wait() to go on with, so a deadlock is reached only    *)
(* when the worker waits in a call (Block) and every client is done. A     *)
(* hang short of that shows as a violation of WorkerNeverBlocks or of a    *)
(* liveness property.                                                      *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Clients,      \* client processes, one connection each
    PrClients,    \* those connected to the prediction resistance socket
    Root,         \* clients with UID 0
    Streamers,    \* clients sending write requests without end
    Script,       \* Script[c]: the requests of client c, <<kind, units>>
    BufCmds,      \* commands conn->in holds (ESDM_EGD_BUFSIZE)
    SqCap,        \* requests the socket queues before the client's send blocks
    SndBuf,       \* responses the client's socket holds unread
    MaxEvents,    \* ESDM_EGD_MAX_EVENTS
    Cap,          \* ESDM_EGD_MAX_CONNECTIONS
    ClientClose,  \* clients close at any time, not only when done
    HalfClose,    \* clients shut down their sending side after the last request
    GenFail,      \* a generation may fail with an error other than -EAGAIN
    AcceptFail,   \* accept4() may fail (EMFILE, ENFILE) until the environment
                  \* turns good
    Stall,        \* the write timeout may reclaim a connection
    NoSignal,     \* send() passes MSG_NOSIGNAL
    KeepArmed,    \* mutation: esdm_egd_conn_arm() leaves a deferred or parked
                  \* connection armed for EPOLLIN
    Block,        \* mutation: the calls that wait instead of returning
                  \* EAGAIN, of "recv", "send" and "gen" (a blocking read
                  \* generated with a call that waits)
    FixHangup,    \* fix: EPOLLHUP and EPOLLERR mark the connection
                  \* (esdm_egd_hangup) instead of closing it at once
    FixEpipe,     \* fix: so does a send() failing with EPIPE or ECONNRESET
    FixFair,      \* fix: one recv() per event
    FixRdhup,     \* fix: only the EOF of recv() closes, EPOLLRDHUP does not
    FixAccept,    \* fix: a failed accept disarms the listeners until the next
                  \* epoll_wait() timeout or a connection is closed
    FixCap,       \* fix: a listener event is skipped at the connection limit
    Liveness      \* the environment eventually turns good

Listeners == {"Lreg", "Lpr"}
Sock(c) == IF c \in PrClients THEN "Lpr" ELSE "Lreg"
NoCmd == <<>>
NoResp == <<>>
NoEv == <<>>
NoConn == "none"
Err == -1
Min(a, b) == IF a < b THEN a ELSE b

\* struct esdm_egd_conn: in, out, deferred with answer_len (ans), parked,
\* hangup, armed, peer_uid = 0 (root); fin is a ghost, the id of the last
\* command finished
Conn0 == [in |-> <<>>, out |-> NoResp, dfr |-> NoCmd, ans |-> 0,
          parked |-> FALSE, hup |-> FALSE, armed |-> "in", root |-> FALSE,
          fin |-> 0]

\* esdm_egd_cmd_has_effect()
HasEffect(k) == k \in {"wr", "priv"}

\* Request scripts, chosen by the configurations
\* a: a blocking read with a request pipelined behind it; b: privileged
SDeferred == [c \in Clients |->
                 IF c = "a" THEN <<<<"blk", 2>>, <<"cnt", 0>>>>
                 ELSE <<<<"priv", 0>>>>]
\* a: a non-blocking read, parked or answered, then a privileged command;
\* b: a blocking read
SPark == [c \in Clients |->
             IF c = "a" THEN <<<<"nb", 1>>, <<"priv", 0>>>>
             ELSE <<<<"blk", 1>>>>]
\* every client one blocking read
SBlk == [c \in Clients |-> <<<<"blk", 2>>>>]
\* every client one request answered from the state
SCnt == [c \in Clients |-> <<<<"cnt", 0>>>>]
\* a write followed by a privileged command
SWrPriv == [c \in Clients |-> <<<<"wr", 0>>, <<"priv", 0>>>>]
\* a request answered from the state, then a write
SCntWr == [c \in Clients |-> <<<<"cnt", 0>>, <<"wr", 0>>>>]
\* commands with an effect behind a request that holds up the connection:
\* a: a blocking read, then a write; b: two answers for a socket that holds
\* one, then a privileged command
SBehind == [c \in Clients |->
               IF c = "a" THEN <<<<"blk", 1>>, <<"wr", 0>>>>
               ELSE <<<<"cnt", 0>>, <<"cnt", 0>>, <<"priv", 0>>>>]

(* --algorithm EsdmEgd {
variables
    cst = [c \in Clients |-> "init"],   \* client: init, conn, wrshut, gone
    srv = [c \in Clients |-> "none"],   \* server: none, backlog, open, freed
    sq = [c \in Clients |-> <<>>],      \* requests sent, not yet received
    rq = [c \in Clients |-> <<>>],      \* responses the client has not read
    cn = [c \in Clients |-> Conn0],     \* struct esdm_egd_conn
    conns = <<>>,                       \* conn_list, in accept order
    backoff = FALSE,                    \* FixAccept: accepting failed
    good = FALSE,                       \* the generators deliver
    rv = "ok",                          \* the worker's return value
    recvd = FALSE,                      \* this event took input already
    \* ghosts: requests sent and responses read per client; the commands
    \* with an effect that reached esdm_egd_cmd_write_entropy() or
    \* esdm_egd_cmd_priv(); why each connection was closed; the listeners
    \* whose event accepted nobody in this round; properties violated
    nsent = [c \in Clients |-> 0],
    nrecv = [c \in Clients |-> 0],
    acted = [c \in Clients |-> {}],
    closed = [c \in Clients |-> "none"],
    lfail = {},
    viol = {};

define {
    NOpen == Cardinality({c \in Clients : srv[c] = "open"})
    \* esdm_egd_hangup()
    Hangup(r) == [r EXCEPT !.hup = TRUE, !.out = NoResp, !.dfr = NoCmd,
                           !.ans = 0, !.parked = FALSE,
                           !.fin = IF r.dfr # NoCmd THEN r.dfr[1] ELSE r.fin]
    \* esdm_egd_conn_arm()
    Arm(r) == IF r.out # NoResp THEN "out"
              ELSE IF (r.dfr = NoCmd /\ ~r.parked) \/ KeepArmed THEN "in"
              ELSE "none"
    \* What epoll reports for connection c armed for a; EPOLLHUP comes
    \* regardless
    Flags(c, a) ==
        (IF a = "in" /\ (sq[c] # <<>> \/ cst[c] # "conn")
         THEN {"IN"} ELSE {})
        \cup (IF a = "in" /\ cst[c] # "conn" THEN {"RDHUP"} ELSE {})
        \cup (IF a = "out" /\ (Len(rq[c]) < SndBuf \/ cst[c] = "gone")
              THEN {"OUT"} ELSE {})
        \cup (IF cst[c] = "gone" THEN {"HUP"} ELSE {})
    Backlog(l) == {c \in Clients : srv[c] = "backlog" /\ Sock(c) = l}
    \* a descriptor other than connection q is ready
    OtherReady(q) ==
        \/ \E c \in Clients \ {q} :
               srv[c] = "open" /\ Flags(c, cn[c].armed) # {}
        \/ \E l \in Listeners : NOpen < Cap /\ ~backoff /\ Backlog(l) # {}
    Ready(want) ==
        {<<c, Flags(c, cn[c].armed)>> :
            c \in {x \in Clients : srv[x] = "open"
                                   /\ Flags(x, cn[x].armed) # {}}}
        \cup {<<l, {"IN"}>> : l \in {x \in Listeners : want /\ Backlog(x) # {}}}
    Batches(S) ==
        {b \in SUBSET S : Cardinality(b) = Min(Cardinality(S), MaxEvents)}
    \* one non-blocking generation of len units
    GenOut(len) == IF good THEN {len}
                   ELSE (0..len) \cup (IF GenFail THEN {Err} ELSE {})
    \* the generation of a blocking read: esdm_egd_get_random(), or with
    \* "gen" in Block a call that waits until the generators deliver
    BlkOut(len) == IF "gen" \notin Block THEN GenOut(len)
                   ELSE IF good THEN {len} ELSE {}
    \* esdm_state_operational() for a regular generation that yields nothing
    OpOut == IF good THEN {TRUE} ELSE BOOLEAN
    \* the state an event could change
    Snap(c, r) == <<r, sq[c], rq[c], cst[c]>>
    NResp(c, j) == Cardinality({i \in 1..j : Script[c][i][1] # "wr"})
    \* the commands with an effect the client has sent
    Effects(c) == {i \in 1..nsent[c] : HasEffect(Script[c][i][1])}
    \* responses to requests sent that the client has not got
    Owed(c) == IF c \in Streamers THEN 0
               ELSE NResp(c, nsent[c]) - nrecv[c] - Len(rq[c])
    RespIds(c) == SelectSeq([i \in 1..Len(Script[c]) |-> i],
                            LAMBDA i : Script[c][i][1] # "wr")
    \* what a response to the client's request i must say
    RespOK(c, i, v) ==
        CASE Script[c][i][1] = "blk" -> v = Script[c][i][2]
          [] Script[c][i][1] = "priv" ->
                 v = IF c \in Root THEN "ok" ELSE "eperm"
          [] Script[c][i][1] = "nb" -> v \in 0..Script[c][i][2]
          [] OTHER -> v = "cnt"
}

\* esdm_egd_write() of resp with record r (the command consumed), and its
\* first send(); bv: violations found on the way
macro respond(c, r, resp, bv) {
    viol := viol \cup bv
                 \cup (IF cn[c].out # NoResp THEN {"Overflow"} ELSE {})
                 \cup (IF cst[c] = "gone" /\ ~r.hup
                       THEN {"SendClosed"} \cup
                            (IF NoSignal THEN {} ELSE {"Sigpipe"})
                       ELSE {});
    if (r.hup) {
        \* esdm_egd_flush(): nobody to deliver to, no send()
        cn[c] := r;
    } else if (cst[c] = "gone") {
        \* EPIPE: esdm_egd_hangup(); before the fix it closed
        if (FixEpipe) {
            cn[c] := Hangup(r);
        } else {
            cn[c] := r;
            rv := "pipe";
        };
    } else if (Len(rq[c]) < SndBuf) {
        cn[c] := r;
        rq[c] := Append(rq[c], resp);
    } else {
        \* EAGAIN: the response waits for EPOLLOUT; a blocking send()
        \* would wait for the client here
        await "send" \notin Block;
        cn[c] := [r EXCEPT !.out = resp];
    };
}

\* epoll_ctl(EPOLL_CTL_DEL) and esdm_egd_release_conn(); why: "eof",
\* "rdhup", "err" (a generation failed), "stall", and before the fix "hup"
\* and "pipe". A generation error and the write timeout give up the
\* connection with what is unprocessed of its input; every other close
\* comes after the commands with an effect were handled.
macro release(c, why) {
    srv[c] := "freed";
    cn[c] := Conn0;
    conns := SelectSeq(conns, LAMBDA x : x # c);
    closed[c] := why;
    viol := viol \cup (IF why \in {"eof", "rdhup"} /\ cst[c] # "gone"
                          /\ Owed(c) > 0
                       THEN {"Lost"} ELSE {})
                 \cup (IF why \notin {"err", "stall"} /\ c \notin Streamers
                          /\ ~(Effects(c) \subseteq acted[c])
                       THEN {"Dropped"} ELSE {});
    \* a descriptor became free: accepting again at once is no spin
    lfail := {};
    if (FixAccept) backoff := FALSE;
}

\* esdm_egd_process(); rv: "ok", or "err" to close
procedure egdProcess(p)
{
     \* esdm_egd_flush() of the response in flight
pr1: if (cn[p].out # NoResp) {
         viol := viol \cup (IF cst[p] = "gone"
                            THEN {"SendClosed"} \cup
                                 (IF NoSignal THEN {} ELSE {"Sigpipe"})
                            ELSE {});
         if (cst[p] = "gone") {
             \* EPIPE: esdm_egd_hangup(); before the fix it closed
             if (FixEpipe) {
                 cn[p] := Hangup(cn[p]);
             } else {
                 rv := "pipe";
             };
         } else if (Len(rq[p]) < SndBuf) {
             rq[p] := Append(rq[p], cn[p].out);
             cn[p].out := NoResp;
         };
     };
pr2: if (rv # "ok" \/ cn[p].out # NoResp) {
         return;
     } else if (cn[p].dfr # NoCmd) {
         \* esdm_egd_serve_deferred(): one generation for the rest
         with (r = cn[p], d = r.dfr, y \in BlkOut(d[3] - r.ans)) {
             if (y = Err) {
                 rv := "err";
                 return;
             } else if (r.ans + y = d[3]) {
                 respond(p, [r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]],
                         <<d[1], d[3]>>, {});
             } else {
                 \* -EAGAIN: what came out stays in conn->answer
                 cn[p].ans := r.ans + y;
                 return;
             };
         };
     };
     \* the commands in the input buffer, one per step
pr3: if (rv # "ok" \/ cn[p].out # NoResp \/ cn[p].in = <<>>) {
         return;
     } else {
         with (r = cn[p], cm = Head(r.in), id = cm[1], k = cm[2], n = cm[3],
               r1 = [r EXCEPT !.in = Tail(r.in), !.parked = FALSE,
                              !.fin = IF id > 0 THEN id ELSE r.fin],
               bv = IF id > 0 /\ r.fin # id - 1 THEN {"Bypass"} ELSE {}) {
             if (r.hup /\ ~HasEffect(k)) {
                 \* nobody to answer
                 cn[p] := r1;
                 viol := viol \cup bv;
             } else if (k = "cnt") {
                 respond(p, r1, <<id, "cnt">>, bv);
             } else if (k = "priv") {
                 \* esdm_egd_cmd_priv(): the UID latched at accept decides;
                 \* carried out for another peer than root is a violation
                 respond(p, r1, <<id, IF r.root THEN "ok" ELSE "eperm">>,
                         bv \cup (IF r.root /\ p \notin Root
                                  THEN {"PrivDone"} ELSE {}));
                 acted[p] := acted[p] \cup {id};
             } else if (k = "wr") {
                 \* esdm_egd_cmd_write_entropy(): no response
                 cn[p] := r1;
                 viol := viol \cup bv;
                 if (id > 0) acted[p] := acted[p] \cup {id};
             } else if (k = "nb") {
                 \* esdm_egd_cmd_read_nonblock(), esdm_egd_reseed_wait()
                 with (y \in GenOut(n), op \in OpOut,
                       ex \in IF r.parked THEN BOOLEAN ELSE {FALSE}) {
                     if (y = 0 /\ op /\ ~ex) {
                         \* parked at the head of the input
                         cn[p].parked := TRUE;
                         viol := viol \cup bv;
                         return;
                     } else {
                         respond(p, r1, <<id, IF y = Err THEN 0 ELSE y>>, bv);
                     };
                 };
             } else {
                 \* esdm_egd_cmd_read_block()
                 with (y \in BlkOut(n)) {
                     if (y = Err) {
                         rv := "err";
                         return;
                     } else if (y = n) {
                         respond(p, r1, <<id, n>>, bv);
                     } else {
                         \* deferred: consumed, answered in a later round
                         cn[p] := [r EXCEPT !.in = Tail(r.in), !.dfr = cm,
                                            !.ans = y];
                         viol := viol \cup bv;
                         return;
                     };
                 };
             };
         };
     };
pr4: goto pr3;
}

\* esdm_egd_read(); rv: "ok", "err", or "eof" to close
procedure egdRead(q)
{
rd1: if (cn[q].hup /\ cn[q].in # <<>>) {
         call egdProcess(q);
     };
rd2: if (rv # "ok" \/ cn[q].dfr # NoCmd \/ cn[q].parked \/ cn[q].out # NoResp
         \/ Len(cn[q].in) >= BufCmds) {
         return;
     } else if (sq[q] # <<>>) {
         \* recv() of what fits; more of one client while another waits
         with (m = Min(BufCmds - Len(cn[q].in), Len(sq[q]))) {
             cn[q].in := cn[q].in \o SubSeq(sq[q], 1, m);
             sq[q] := SubSeq(sq[q], m + 1, Len(sq[q]));
         };
         viol := viol \cup (IF recvd /\ OtherReady(q) THEN {"Starve"} ELSE {});
         recvd := TRUE;
         call egdProcess(q);
     } else if (cst[q] # "conn") {
         \* recv() returns 0, or ECONNRESET
         rv := "eof";
         return;
     } else {
         \* EAGAIN; a blocking recv() would wait for the client here
         await "recv" \notin Block;
         return;
     };
rd3: if (rv = "ok" /\ ~FixFair) {
         goto rd1;
     } else {
         return;
     };
}

\* esdm_egd_handler()
fair process (worker = "worker")
    variables evs = {}, ev = NoEv, walk = <<>>, cur = NoConn, po = NoResp,
              snap = <<>>;
{
wt: while (TRUE) {
        \* the listeners re-armed (listen_armed), epoll_wait()
        with (want = NOpen < Cap /\ ~backoff, b \in Batches(Ready(want))) {
            evs := b;
            \* a listener whose event accepted nobody, with nothing
            \* changed since, is ready again at once
            viol := viol \cup
                    (IF \E l \in lfail : <<l, {"IN"}>> \in Ready(want)
                     THEN {"Spin"} ELSE {});
            lfail := {};
            \* FixAccept: the timeout passed
            if (b = {}) backoff := FALSE;
        };
ev1:    while (evs # {}) {
            with (e \in evs) {
                ev := e;
                evs := evs \ {e};
            };
ev2:        if (ev[1] \in Listeners /\ FixCap /\ NOpen >= Cap) {
                \* at the limit: disarmed in the next round
                lfail := lfail \cup {ev[1]};
                ev := NoEv;
            } else if (ev[1] \in Listeners) {
                \* esdm_egd_accept(); the limit was checked before epoll_wait()
                either {
                    \* accept4() fails: the client stays queued
                    await AcceptFail /\ ~good;
                    lfail := lfail \cup {ev[1]};
                    \* accept_retry_at; without it the listener stays
                    \* armed and ready
                    if (FixAccept) backoff := TRUE;
                } or {
                    with (c \in Backlog(ev[1])) {
                        srv[c] := "open";
                        \* SO_PEERCRED
                        cn[c] := [Conn0 EXCEPT !.root = c \in Root];
                        conns := Append(conns, c);
                    };
                };
                ev := NoEv;
            } else {
                with (c = ev[1]) {
                    viol := viol \cup (IF srv[c] # "open"
                                       THEN {"UseAfterFree"} ELSE {});
                    snap := Snap(c, cn[c]);
                    \* gone, but its input is still to be processed; before
                    \* the fix the connection was closed at once
                    if ("HUP" \in ev[2] /\ FixHangup) cn[c] := Hangup(cn[c]);
                    rv := IF "HUP" \in ev[2] /\ ~FixHangup THEN "hup"
                          ELSE "ok";
                };
ev3:            if (rv # "ok") {
                    skip;
                } else if (cn[ev[1]].out # NoResp) {
                    call egdProcess(ev[1]);
                } else {
                    call egdRead(ev[1]);
                };
                \* the EPOLLRDHUP check, then close or esdm_egd_conn_arm()
ev4:            with (c = ev[1], r = cn[c], a = Arm(r)) {
                    if (rv # "ok" \/ ("RDHUP" \in ev[2] /\ ~FixRdhup
                                      /\ r.dfr = NoCmd /\ ~r.parked
                                      /\ r.out = NoResp)) {
                        with (why = IF rv = "ok" THEN "rdhup" ELSE rv)
                            release(c, why);
                    } else {
                        cn[c].armed := a;
                        \* nothing changed and reported again at once
                        viol := viol \cup
                            (IF snap = Snap(c, [r EXCEPT !.armed = a])
                                /\ Flags(c, a) # {}
                             THEN {"Spin"} ELSE {});
                    };
                    ev := NoEv;
                    snap := <<>>;
                    rv := "ok";
                    recvd := FALSE;
                };
            };
        };
        \* the retry walk: deferred, parked, response pending
wk0:    walk := conns;
wk1:    while (walk # <<>>) {
            with (c = Head(walk), r = cn[c]) {
                walk := Tail(walk);
                viol := viol \cup (IF srv[c] # "open"
                                   THEN {"UseAfterFree"} ELSE {});
                if (r.dfr = NoCmd /\ ~r.parked /\ r.out = NoResp) {
                    goto wk1;
                } else {
                    cur := c;
                    po := r.out;
                };
            };
wk2:        call egdProcess(cur);
wk3:        with (r = cn[cur],
                  stuck \in IF Stall /\ rv = "ok" /\ r.out # NoResp
                               /\ r.out = po
                            THEN BOOLEAN ELSE {FALSE}) {
                if (rv # "ok" \/ stuck) {
                    with (why = IF stuck THEN "stall" ELSE rv)
                        release(cur, why);
                } else {
                    cn[cur].armed := Arm(r);
                };
                cur := NoConn;
                po := NoResp;
                rv := "ok";
            };
        };
    };
}

\* an EGD client: connects, pipelines its requests, reads the responses
fair process (client \in Clients)
{
cc: cst[self] := "conn";
    srv[self] := "backlog";
c1: while (TRUE) {
        either {
            \* send() the next request
            await cst[self] = "conn" /\ Len(sq[self]) < SqCap;
            if (self \in Streamers) {
                sq[self] := Append(sq[self], <<0, "wr", 0>>);
            } else {
                await nsent[self] < Len(Script[self]);
                with (i = nsent[self] + 1) {
                    sq[self] := Append(sq[self], <<i, Script[self][i][1],
                                                   Script[self][i][2]>>);
                    nsent[self] := i;
                };
            };
        } or {
            \* recv() a response: in order, exactly once, as asked
            await rq[self] # <<>>;
            with (rs = Head(rq[self]), j = nrecv[self] + 1) {
                if (j > Len(RespIds(self))) {
                    viol := viol \cup {"Dup"};
                } else if (rs[1] # RespIds(self)[j]) {
                    viol := viol \cup {"Order"};
                } else if (~RespOK(self, rs[1], rs[2])) {
                    viol := viol \cup
                        (CASE Script[self][rs[1]][1] = "blk" -> {"Short"}
                           [] Script[self][rs[1]][1] = "priv" -> {"Priv"}
                           [] OTHER -> {"Content"});
                };
                rq[self] := Tail(rq[self]);
                nrecv[self] := j;
            };
        } or {
            \* shutdown(SHUT_WR) after the last request
            await HalfClose /\ cst[self] = "conn" /\ self \notin Streamers
                  /\ nsent[self] = Len(Script[self]);
            cst[self] := "wrshut";
        } or {
            \* close(): done, giving up, or the server closed
            await \/ ClientClose
                  \/ self \notin Streamers /\ nsent[self] = Len(Script[self])
                     /\ nrecv[self] = Len(RespIds(self))
                  \/ srv[self] = "freed" /\ rq[self] = <<>>;
            goto cx;
        };
    };
    \* what it sent stays readable for the server, its receive queue goes
cx: cst[self] := "gone";
    rq[self] := <<>>;
}

\* the generators recover for good
process (env = "env")
{
en: await Liveness;
    good := TRUE;
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, nsent, nrecv, 
          acted, closed, lfail, viol, pc, stack

(* define statement *)
NOpen == Cardinality({c \in Clients : srv[c] = "open"})

Hangup(r) == [r EXCEPT !.hup = TRUE, !.out = NoResp, !.dfr = NoCmd,
                       !.ans = 0, !.parked = FALSE,
                       !.fin = IF r.dfr # NoCmd THEN r.dfr[1] ELSE r.fin]

Arm(r) == IF r.out # NoResp THEN "out"
          ELSE IF (r.dfr = NoCmd /\ ~r.parked) \/ KeepArmed THEN "in"
          ELSE "none"


Flags(c, a) ==
    (IF a = "in" /\ (sq[c] # <<>> \/ cst[c] # "conn")
     THEN {"IN"} ELSE {})
    \cup (IF a = "in" /\ cst[c] # "conn" THEN {"RDHUP"} ELSE {})
    \cup (IF a = "out" /\ (Len(rq[c]) < SndBuf \/ cst[c] = "gone")
          THEN {"OUT"} ELSE {})
    \cup (IF cst[c] = "gone" THEN {"HUP"} ELSE {})
Backlog(l) == {c \in Clients : srv[c] = "backlog" /\ Sock(c) = l}

OtherReady(q) ==
    \/ \E c \in Clients \ {q} :
           srv[c] = "open" /\ Flags(c, cn[c].armed) # {}
    \/ \E l \in Listeners : NOpen < Cap /\ ~backoff /\ Backlog(l) # {}
Ready(want) ==
    {<<c, Flags(c, cn[c].armed)>> :
        c \in {x \in Clients : srv[x] = "open"
                               /\ Flags(x, cn[x].armed) # {}}}
    \cup {<<l, {"IN"}>> : l \in {x \in Listeners : want /\ Backlog(x) # {}}}
Batches(S) ==
    {b \in SUBSET S : Cardinality(b) = Min(Cardinality(S), MaxEvents)}

GenOut(len) == IF good THEN {len}
               ELSE (0..len) \cup (IF GenFail THEN {Err} ELSE {})


BlkOut(len) == IF "gen" \notin Block THEN GenOut(len)
               ELSE IF good THEN {len} ELSE {}

OpOut == IF good THEN {TRUE} ELSE BOOLEAN

Snap(c, r) == <<r, sq[c], rq[c], cst[c]>>
NResp(c, j) == Cardinality({i \in 1..j : Script[c][i][1] # "wr"})

Effects(c) == {i \in 1..nsent[c] : HasEffect(Script[c][i][1])}

Owed(c) == IF c \in Streamers THEN 0
           ELSE NResp(c, nsent[c]) - nrecv[c] - Len(rq[c])
RespIds(c) == SelectSeq([i \in 1..Len(Script[c]) |-> i],
                        LAMBDA i : Script[c][i][1] # "wr")

RespOK(c, i, v) ==
    CASE Script[c][i][1] = "blk" -> v = Script[c][i][2]
      [] Script[c][i][1] = "priv" ->
             v = IF c \in Root THEN "ok" ELSE "eperm"
      [] Script[c][i][1] = "nb" -> v \in 0..Script[c][i][2]
      [] OTHER -> v = "cnt"

VARIABLES p, q, evs, ev, walk, cur, po, snap

vars == << cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, nsent, 
           nrecv, acted, closed, lfail, viol, pc, stack, p, q, evs, ev, walk, 
           cur, po, snap >>

ProcSet == {"worker"} \cup (Clients) \cup {"env"}

Init == (* Global variables *)
        /\ cst = [c \in Clients |-> "init"]
        /\ srv = [c \in Clients |-> "none"]
        /\ sq = [c \in Clients |-> <<>>]
        /\ rq = [c \in Clients |-> <<>>]
        /\ cn = [c \in Clients |-> Conn0]
        /\ conns = <<>>
        /\ backoff = FALSE
        /\ good = FALSE
        /\ rv = "ok"
        /\ recvd = FALSE
        /\ nsent = [c \in Clients |-> 0]
        /\ nrecv = [c \in Clients |-> 0]
        /\ acted = [c \in Clients |-> {}]
        /\ closed = [c \in Clients |-> "none"]
        /\ lfail = {}
        /\ viol = {}
        (* Procedure egdProcess *)
        /\ p = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure egdRead *)
        /\ q = [ self \in ProcSet |-> defaultInitValue]
        (* Process worker *)
        /\ evs = {}
        /\ ev = NoEv
        /\ walk = <<>>
        /\ cur = NoConn
        /\ po = NoResp
        /\ snap = <<>>
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self = "worker" -> "wt"
                                        [] self \in Clients -> "cc"
                                        [] self = "env" -> "en"]

pr1(self) == /\ pc[self] = "pr1"
             /\ IF cn[p[self]].out # NoResp
                   THEN /\ viol' = (viol \cup (IF cst[p[self]] = "gone"
                                               THEN {"SendClosed"} \cup
                                                    (IF NoSignal THEN {} ELSE {"Sigpipe"})
                                               ELSE {}))
                        /\ IF cst[p[self]] = "gone"
                              THEN /\ IF FixEpipe
                                         THEN /\ cn' = [cn EXCEPT ![p[self]] = Hangup(cn[p[self]])]
                                              /\ rv' = rv
                                         ELSE /\ rv' = "pipe"
                                              /\ cn' = cn
                                   /\ rq' = rq
                              ELSE /\ IF Len(rq[p[self]]) < SndBuf
                                         THEN /\ rq' = [rq EXCEPT ![p[self]] = Append(rq[p[self]], cn[p[self]].out)]
                                              /\ cn' = [cn EXCEPT ![p[self]].out = NoResp]
                                         ELSE /\ TRUE
                                              /\ UNCHANGED << rq, cn >>
                                   /\ rv' = rv
                   ELSE /\ TRUE
                        /\ UNCHANGED << rq, cn, rv, viol >>
             /\ pc' = [pc EXCEPT ![self] = "pr2"]
             /\ UNCHANGED << cst, srv, sq, conns, backoff, good, recvd, nsent, 
                             nrecv, acted, closed, lfail, stack, p, q, evs, ev, 
                             walk, cur, po, snap >>

pr2(self) == /\ pc[self] = "pr2"
             /\ IF rv # "ok" \/ cn[p[self]].out # NoResp
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << rq, cn, rv, viol >>
                   ELSE /\ IF cn[p[self]].dfr # NoCmd
                              THEN /\ LET r == cn[p[self]] IN
                                        LET d == r.dfr IN
                                          \E y \in BlkOut(d[3] - r.ans):
                                            IF y = Err
                                               THEN /\ rv' = "err"
                                                    /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                    /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                                                    /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                    /\ UNCHANGED << rq, cn, 
                                                                    viol >>
                                               ELSE /\ IF r.ans + y = d[3]
                                                          THEN /\ viol' = (viol \cup ({})
                                                                                \cup (IF cn[p[self]].out # NoResp THEN {"Overflow"} ELSE {})
                                                                                \cup (IF cst[p[self]] = "gone" /\ ~([r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]).hup
                                                                                      THEN {"SendClosed"} \cup
                                                                                           (IF NoSignal THEN {} ELSE {"Sigpipe"})
                                                                                      ELSE {}))
                                                               /\ IF ([r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]).hup
                                                                     THEN /\ cn' = [cn EXCEPT ![p[self]] = [r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]]
                                                                          /\ UNCHANGED << rq, 
                                                                                          rv >>
                                                                     ELSE /\ IF cst[p[self]] = "gone"
                                                                                THEN /\ IF FixEpipe
                                                                                           THEN /\ cn' = [cn EXCEPT ![p[self]] = Hangup(([r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]))]
                                                                                                /\ rv' = rv
                                                                                           ELSE /\ cn' = [cn EXCEPT ![p[self]] = [r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]]
                                                                                                /\ rv' = "pipe"
                                                                                     /\ rq' = rq
                                                                                ELSE /\ IF Len(rq[p[self]]) < SndBuf
                                                                                           THEN /\ cn' = [cn EXCEPT ![p[self]] = [r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]]
                                                                                                /\ rq' = [rq EXCEPT ![p[self]] = Append(rq[p[self]], (<<d[1], d[3]>>))]
                                                                                           ELSE /\ "send" \notin Block
                                                                                                /\ cn' = [cn EXCEPT ![p[self]] = [([r EXCEPT !.dfr = NoCmd, !.ans = 0, !.fin = d[1]]) EXCEPT !.out = (<<d[1], d[3]>>)]]
                                                                                                /\ rq' = rq
                                                                                     /\ rv' = rv
                                                               /\ pc' = [pc EXCEPT ![self] = "pr3"]
                                                               /\ UNCHANGED << stack, 
                                                                               p >>
                                                          ELSE /\ cn' = [cn EXCEPT ![p[self]].ans = r.ans + y]
                                                               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                               /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                                                               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                               /\ UNCHANGED << rq, 
                                                                               rv, 
                                                                               viol >>
                              ELSE /\ pc' = [pc EXCEPT ![self] = "pr3"]
                                   /\ UNCHANGED << rq, cn, rv, viol, stack, p >>
             /\ UNCHANGED << cst, srv, sq, conns, backoff, good, recvd, nsent, 
                             nrecv, acted, closed, lfail, q, evs, ev, walk, 
                             cur, po, snap >>

pr3(self) == /\ pc[self] = "pr3"
             /\ IF rv # "ok" \/ cn[p[self]].out # NoResp \/ cn[p[self]].in = <<>>
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << rq, cn, rv, acted, viol >>
                   ELSE /\ LET r == cn[p[self]] IN
                             LET cm == Head(r.in) IN
                               LET id == cm[1] IN
                                 LET k == cm[2] IN
                                   LET n == cm[3] IN
                                     LET r1 == [r EXCEPT !.in = Tail(r.in), !.parked = FALSE,
                                                         !.fin = IF id > 0 THEN id ELSE r.fin] IN
                                       LET bv == IF id > 0 /\ r.fin # id - 1 THEN {"Bypass"} ELSE {} IN
                                         IF r.hup /\ ~HasEffect(k)
                                            THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                 /\ viol' = (viol \cup bv)
                                                 /\ pc' = [pc EXCEPT ![self] = "pr4"]
                                                 /\ UNCHANGED << rq, rv, acted, 
                                                                 stack, p >>
                                            ELSE /\ IF k = "cnt"
                                                       THEN /\ viol' = (viol \cup bv
                                                                             \cup (IF cn[p[self]].out # NoResp THEN {"Overflow"} ELSE {})
                                                                             \cup (IF cst[p[self]] = "gone" /\ ~r1.hup
                                                                                   THEN {"SendClosed"} \cup
                                                                                        (IF NoSignal THEN {} ELSE {"Sigpipe"})
                                                                                   ELSE {}))
                                                            /\ IF r1.hup
                                                                  THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                       /\ UNCHANGED << rq, 
                                                                                       rv >>
                                                                  ELSE /\ IF cst[p[self]] = "gone"
                                                                             THEN /\ IF FixEpipe
                                                                                        THEN /\ cn' = [cn EXCEPT ![p[self]] = Hangup(r1)]
                                                                                             /\ rv' = rv
                                                                                        ELSE /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                             /\ rv' = "pipe"
                                                                                  /\ rq' = rq
                                                                             ELSE /\ IF Len(rq[p[self]]) < SndBuf
                                                                                        THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                             /\ rq' = [rq EXCEPT ![p[self]] = Append(rq[p[self]], (<<id, "cnt">>))]
                                                                                        ELSE /\ "send" \notin Block
                                                                                             /\ cn' = [cn EXCEPT ![p[self]] = [r1 EXCEPT !.out = (<<id, "cnt">>)]]
                                                                                             /\ rq' = rq
                                                                                  /\ rv' = rv
                                                            /\ pc' = [pc EXCEPT ![self] = "pr4"]
                                                            /\ UNCHANGED << acted, 
                                                                            stack, 
                                                                            p >>
                                                       ELSE /\ IF k = "priv"
                                                                  THEN /\ viol' = (viol \cup (bv \cup (IF r.root /\ p[self] \notin Root
                                                                                                       THEN {"PrivDone"} ELSE {}))
                                                                                        \cup (IF cn[p[self]].out # NoResp THEN {"Overflow"} ELSE {})
                                                                                        \cup (IF cst[p[self]] = "gone" /\ ~r1.hup
                                                                                              THEN {"SendClosed"} \cup
                                                                                                   (IF NoSignal THEN {} ELSE {"Sigpipe"})
                                                                                              ELSE {}))
                                                                       /\ IF r1.hup
                                                                             THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                  /\ UNCHANGED << rq, 
                                                                                                  rv >>
                                                                             ELSE /\ IF cst[p[self]] = "gone"
                                                                                        THEN /\ IF FixEpipe
                                                                                                   THEN /\ cn' = [cn EXCEPT ![p[self]] = Hangup(r1)]
                                                                                                        /\ rv' = rv
                                                                                                   ELSE /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                        /\ rv' = "pipe"
                                                                                             /\ rq' = rq
                                                                                        ELSE /\ IF Len(rq[p[self]]) < SndBuf
                                                                                                   THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                        /\ rq' = [rq EXCEPT ![p[self]] = Append(rq[p[self]], (<<id, IF r.root THEN "ok" ELSE "eperm">>))]
                                                                                                   ELSE /\ "send" \notin Block
                                                                                                        /\ cn' = [cn EXCEPT ![p[self]] = [r1 EXCEPT !.out = (<<id, IF r.root THEN "ok" ELSE "eperm">>)]]
                                                                                                        /\ rq' = rq
                                                                                             /\ rv' = rv
                                                                       /\ acted' = [acted EXCEPT ![p[self]] = acted[p[self]] \cup {id}]
                                                                       /\ pc' = [pc EXCEPT ![self] = "pr4"]
                                                                       /\ UNCHANGED << stack, 
                                                                                       p >>
                                                                  ELSE /\ IF k = "wr"
                                                                             THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                  /\ viol' = (viol \cup bv)
                                                                                  /\ IF id > 0
                                                                                        THEN /\ acted' = [acted EXCEPT ![p[self]] = acted[p[self]] \cup {id}]
                                                                                        ELSE /\ TRUE
                                                                                             /\ acted' = acted
                                                                                  /\ pc' = [pc EXCEPT ![self] = "pr4"]
                                                                                  /\ UNCHANGED << rq, 
                                                                                                  rv, 
                                                                                                  stack, 
                                                                                                  p >>
                                                                             ELSE /\ IF k = "nb"
                                                                                        THEN /\ \E y \in GenOut(n):
                                                                                                  \E op \in OpOut:
                                                                                                    \E ex \in IF r.parked THEN BOOLEAN ELSE {FALSE}:
                                                                                                      IF y = 0 /\ op /\ ~ex
                                                                                                         THEN /\ cn' = [cn EXCEPT ![p[self]].parked = TRUE]
                                                                                                              /\ viol' = (viol \cup bv)
                                                                                                              /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                                                                              /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                                                                                                              /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                                                                              /\ UNCHANGED << rq, 
                                                                                                                              rv >>
                                                                                                         ELSE /\ viol' = (viol \cup bv
                                                                                                                               \cup (IF cn[p[self]].out # NoResp THEN {"Overflow"} ELSE {})
                                                                                                                               \cup (IF cst[p[self]] = "gone" /\ ~r1.hup
                                                                                                                                     THEN {"SendClosed"} \cup
                                                                                                                                          (IF NoSignal THEN {} ELSE {"Sigpipe"})
                                                                                                                                     ELSE {}))
                                                                                                              /\ IF r1.hup
                                                                                                                    THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                                         /\ UNCHANGED << rq, 
                                                                                                                                         rv >>
                                                                                                                    ELSE /\ IF cst[p[self]] = "gone"
                                                                                                                               THEN /\ IF FixEpipe
                                                                                                                                          THEN /\ cn' = [cn EXCEPT ![p[self]] = Hangup(r1)]
                                                                                                                                               /\ rv' = rv
                                                                                                                                          ELSE /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                                                               /\ rv' = "pipe"
                                                                                                                                    /\ rq' = rq
                                                                                                                               ELSE /\ IF Len(rq[p[self]]) < SndBuf
                                                                                                                                          THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                                                               /\ rq' = [rq EXCEPT ![p[self]] = Append(rq[p[self]], (<<id, IF y = Err THEN 0 ELSE y>>))]
                                                                                                                                          ELSE /\ "send" \notin Block
                                                                                                                                               /\ cn' = [cn EXCEPT ![p[self]] = [r1 EXCEPT !.out = (<<id, IF y = Err THEN 0 ELSE y>>)]]
                                                                                                                                               /\ rq' = rq
                                                                                                                                    /\ rv' = rv
                                                                                                              /\ pc' = [pc EXCEPT ![self] = "pr4"]
                                                                                                              /\ UNCHANGED << stack, 
                                                                                                                              p >>
                                                                                        ELSE /\ \E y \in BlkOut(n):
                                                                                                  IF y = Err
                                                                                                     THEN /\ rv' = "err"
                                                                                                          /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                                                                          /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                                                                                                          /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                                                                          /\ UNCHANGED << rq, 
                                                                                                                          cn, 
                                                                                                                          viol >>
                                                                                                     ELSE /\ IF y = n
                                                                                                                THEN /\ viol' = (viol \cup bv
                                                                                                                                      \cup (IF cn[p[self]].out # NoResp THEN {"Overflow"} ELSE {})
                                                                                                                                      \cup (IF cst[p[self]] = "gone" /\ ~r1.hup
                                                                                                                                            THEN {"SendClosed"} \cup
                                                                                                                                                 (IF NoSignal THEN {} ELSE {"Sigpipe"})
                                                                                                                                            ELSE {}))
                                                                                                                     /\ IF r1.hup
                                                                                                                           THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                                                /\ UNCHANGED << rq, 
                                                                                                                                                rv >>
                                                                                                                           ELSE /\ IF cst[p[self]] = "gone"
                                                                                                                                      THEN /\ IF FixEpipe
                                                                                                                                                 THEN /\ cn' = [cn EXCEPT ![p[self]] = Hangup(r1)]
                                                                                                                                                      /\ rv' = rv
                                                                                                                                                 ELSE /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                                                                      /\ rv' = "pipe"
                                                                                                                                           /\ rq' = rq
                                                                                                                                      ELSE /\ IF Len(rq[p[self]]) < SndBuf
                                                                                                                                                 THEN /\ cn' = [cn EXCEPT ![p[self]] = r1]
                                                                                                                                                      /\ rq' = [rq EXCEPT ![p[self]] = Append(rq[p[self]], (<<id, n>>))]
                                                                                                                                                 ELSE /\ "send" \notin Block
                                                                                                                                                      /\ cn' = [cn EXCEPT ![p[self]] = [r1 EXCEPT !.out = (<<id, n>>)]]
                                                                                                                                                      /\ rq' = rq
                                                                                                                                           /\ rv' = rv
                                                                                                                     /\ pc' = [pc EXCEPT ![self] = "pr4"]
                                                                                                                     /\ UNCHANGED << stack, 
                                                                                                                                     p >>
                                                                                                                ELSE /\ cn' = [cn EXCEPT ![p[self]] = [r EXCEPT !.in = Tail(r.in), !.dfr = cm,
                                                                                                                                                                !.ans = y]]
                                                                                                                     /\ viol' = (viol \cup bv)
                                                                                                                     /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                                                                                     /\ p' = [p EXCEPT ![self] = Head(stack[self]).p]
                                                                                                                     /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                                                                                     /\ UNCHANGED << rq, 
                                                                                                                                     rv >>
                                                                                  /\ acted' = acted
             /\ UNCHANGED << cst, srv, sq, conns, backoff, good, recvd, nsent, 
                             nrecv, closed, lfail, q, evs, ev, walk, cur, po, 
                             snap >>

pr4(self) == /\ pc[self] = "pr4"
             /\ pc' = [pc EXCEPT ![self] = "pr3"]
             /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, 
                             recvd, nsent, nrecv, acted, closed, lfail, viol, 
                             stack, p, q, evs, ev, walk, cur, po, snap >>

egdProcess(self) == pr1(self) \/ pr2(self) \/ pr3(self) \/ pr4(self)

rd1(self) == /\ pc[self] = "rd1"
             /\ IF cn[q[self]].hup /\ cn[q[self]].in # <<>>
                   THEN /\ /\ p' = [p EXCEPT ![self] = q[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "egdProcess",
                                                                    pc        |->  "rd2",
                                                                    p         |->  p[self] ] >>
                                                                \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "pr1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rd2"]
                        /\ UNCHANGED << stack, p >>
             /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, 
                             recvd, nsent, nrecv, acted, closed, lfail, viol, 
                             q, evs, ev, walk, cur, po, snap >>

rd2(self) == /\ pc[self] = "rd2"
             /\ IF rv # "ok" \/ cn[q[self]].dfr # NoCmd \/ cn[q[self]].parked \/ cn[q[self]].out # NoResp
                   \/ Len(cn[q[self]].in) >= BufCmds
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ q' = [q EXCEPT ![self] = Head(stack[self]).q]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << sq, cn, rv, recvd, viol, p >>
                   ELSE /\ IF sq[q[self]] # <<>>
                              THEN /\ LET m == Min(BufCmds - Len(cn[q[self]].in), Len(sq[q[self]])) IN
                                        /\ cn' = [cn EXCEPT ![q[self]].in = cn[q[self]].in \o SubSeq(sq[q[self]], 1, m)]
                                        /\ sq' = [sq EXCEPT ![q[self]] = SubSeq(sq[q[self]], m + 1, Len(sq[q[self]]))]
                                   /\ viol' = (viol \cup (IF recvd /\ OtherReady(q[self]) THEN {"Starve"} ELSE {}))
                                   /\ recvd' = TRUE
                                   /\ /\ p' = [p EXCEPT ![self] = q[self]]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "egdProcess",
                                                                               pc        |->  "rd3",
                                                                               p         |->  p[self] ] >>
                                                                           \o stack[self]]
                                   /\ pc' = [pc EXCEPT ![self] = "pr1"]
                                   /\ UNCHANGED << rv, q >>
                              ELSE /\ IF cst[q[self]] # "conn"
                                         THEN /\ rv' = "eof"
                                              /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                              /\ q' = [q EXCEPT ![self] = Head(stack[self]).q]
                                              /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                         ELSE /\ "recv" \notin Block
                                              /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                              /\ q' = [q EXCEPT ![self] = Head(stack[self]).q]
                                              /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                              /\ rv' = rv
                                   /\ UNCHANGED << sq, cn, recvd, viol, p >>
             /\ UNCHANGED << cst, srv, rq, conns, backoff, good, nsent, nrecv, 
                             acted, closed, lfail, evs, ev, walk, cur, po, 
                             snap >>

rd3(self) == /\ pc[self] = "rd3"
             /\ IF rv = "ok" /\ ~FixFair
                   THEN /\ pc' = [pc EXCEPT ![self] = "rd1"]
                        /\ UNCHANGED << stack, q >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ q' = [q EXCEPT ![self] = Head(stack[self]).q]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, 
                             recvd, nsent, nrecv, acted, closed, lfail, viol, 
                             p, evs, ev, walk, cur, po, snap >>

egdRead(self) == rd1(self) \/ rd2(self) \/ rd3(self)

wt == /\ pc["worker"] = "wt"
      /\ LET want == NOpen < Cap /\ ~backoff IN
           \E b \in Batches(Ready(want)):
             /\ evs' = b
             /\ viol' = (viol \cup
                         (IF \E l \in lfail : <<l, {"IN"}>> \in Ready(want)
                          THEN {"Spin"} ELSE {}))
             /\ lfail' = {}
             /\ IF b = {}
                   THEN /\ backoff' = FALSE
                   ELSE /\ TRUE
                        /\ UNCHANGED backoff
      /\ pc' = [pc EXCEPT !["worker"] = "ev1"]
      /\ UNCHANGED << cst, srv, sq, rq, cn, conns, good, rv, recvd, nsent, 
                      nrecv, acted, closed, stack, p, q, ev, walk, cur, po, 
                      snap >>

ev1 == /\ pc["worker"] = "ev1"
       /\ IF evs # {}
             THEN /\ \E e \in evs:
                       /\ ev' = e
                       /\ evs' = evs \ {e}
                  /\ pc' = [pc EXCEPT !["worker"] = "ev2"]
             ELSE /\ pc' = [pc EXCEPT !["worker"] = "wk0"]
                  /\ UNCHANGED << evs, ev >>
       /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, 
                       nsent, nrecv, acted, closed, lfail, viol, stack, p, q, 
                       walk, cur, po, snap >>

ev2 == /\ pc["worker"] = "ev2"
       /\ IF ev[1] \in Listeners /\ FixCap /\ NOpen >= Cap
             THEN /\ lfail' = (lfail \cup {ev[1]})
                  /\ ev' = NoEv
                  /\ pc' = [pc EXCEPT !["worker"] = "ev1"]
                  /\ UNCHANGED << srv, cn, conns, backoff, rv, viol, snap >>
             ELSE /\ IF ev[1] \in Listeners
                        THEN /\ \/ /\ AcceptFail /\ ~good
                                   /\ lfail' = (lfail \cup {ev[1]})
                                   /\ IF FixAccept
                                         THEN /\ backoff' = TRUE
                                         ELSE /\ TRUE
                                              /\ UNCHANGED backoff
                                   /\ UNCHANGED <<srv, cn, conns>>
                                \/ /\ \E c \in Backlog(ev[1]):
                                        /\ srv' = [srv EXCEPT ![c] = "open"]
                                        /\ cn' = [cn EXCEPT ![c] = [Conn0 EXCEPT !.root = c \in Root]]
                                        /\ conns' = Append(conns, c)
                                   /\ UNCHANGED <<backoff, lfail>>
                             /\ ev' = NoEv
                             /\ pc' = [pc EXCEPT !["worker"] = "ev1"]
                             /\ UNCHANGED << rv, viol, snap >>
                        ELSE /\ LET c == ev[1] IN
                                  /\ viol' = (viol \cup (IF srv[c] # "open"
                                                         THEN {"UseAfterFree"} ELSE {}))
                                  /\ snap' = Snap(c, cn[c])
                                  /\ IF "HUP" \in ev[2] /\ FixHangup
                                        THEN /\ cn' = [cn EXCEPT ![c] = Hangup(cn[c])]
                                        ELSE /\ TRUE
                                             /\ cn' = cn
                                  /\ rv' = (IF "HUP" \in ev[2] /\ ~FixHangup THEN "hup"
                                            ELSE "ok")
                             /\ pc' = [pc EXCEPT !["worker"] = "ev3"]
                             /\ UNCHANGED << srv, conns, backoff, lfail, ev >>
       /\ UNCHANGED << cst, sq, rq, good, recvd, nsent, nrecv, acted, closed, 
                       stack, p, q, evs, walk, cur, po >>

ev3 == /\ pc["worker"] = "ev3"
       /\ IF rv # "ok"
             THEN /\ TRUE
                  /\ pc' = [pc EXCEPT !["worker"] = "ev4"]
                  /\ UNCHANGED << stack, p, q >>
             ELSE /\ IF cn[ev[1]].out # NoResp
                        THEN /\ /\ p' = [p EXCEPT !["worker"] = ev[1]]
                                /\ stack' = [stack EXCEPT !["worker"] = << [ procedure |->  "egdProcess",
                                                                             pc        |->  "ev4",
                                                                             p         |->  p["worker"] ] >>
                                                                         \o stack["worker"]]
                             /\ pc' = [pc EXCEPT !["worker"] = "pr1"]
                             /\ q' = q
                        ELSE /\ /\ q' = [q EXCEPT !["worker"] = ev[1]]
                                /\ stack' = [stack EXCEPT !["worker"] = << [ procedure |->  "egdRead",
                                                                             pc        |->  "ev4",
                                                                             q         |->  q["worker"] ] >>
                                                                         \o stack["worker"]]
                             /\ pc' = [pc EXCEPT !["worker"] = "rd1"]
                             /\ p' = p
       /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, 
                       nsent, nrecv, acted, closed, lfail, viol, evs, ev, walk, 
                       cur, po, snap >>

ev4 == /\ pc["worker"] = "ev4"
       /\ LET c == ev[1] IN
            LET r == cn[c] IN
              LET a == Arm(r) IN
                /\ IF rv # "ok" \/ ("RDHUP" \in ev[2] /\ ~FixRdhup
                                    /\ r.dfr = NoCmd /\ ~r.parked
                                    /\ r.out = NoResp)
                      THEN /\ LET why == IF rv = "ok" THEN "rdhup" ELSE rv IN
                                /\ srv' = [srv EXCEPT ![c] = "freed"]
                                /\ cn' = [cn EXCEPT ![c] = Conn0]
                                /\ conns' = SelectSeq(conns, LAMBDA x : x # c)
                                /\ closed' = [closed EXCEPT ![c] = why]
                                /\ viol' = (viol \cup (IF why \in {"eof", "rdhup"} /\ cst[c] # "gone"
                                                          /\ Owed(c) > 0
                                                       THEN {"Lost"} ELSE {})
                                                 \cup (IF why \notin {"err", "stall"} /\ c \notin Streamers
                                                          /\ ~(Effects(c) \subseteq acted[c])
                                                       THEN {"Dropped"} ELSE {}))
                                /\ lfail' = {}
                                /\ IF FixAccept
                                      THEN /\ backoff' = FALSE
                                      ELSE /\ TRUE
                                           /\ UNCHANGED backoff
                      ELSE /\ cn' = [cn EXCEPT ![c].armed = a]
                           /\ viol' = (    viol \cup
                                       (IF snap = Snap(c, [r EXCEPT !.armed = a])
                                           /\ Flags(c, a) # {}
                                        THEN {"Spin"} ELSE {}))
                           /\ UNCHANGED << srv, conns, backoff, closed, lfail >>
                /\ ev' = NoEv
                /\ snap' = <<>>
                /\ rv' = "ok"
                /\ recvd' = FALSE
       /\ pc' = [pc EXCEPT !["worker"] = "ev1"]
       /\ UNCHANGED << cst, sq, rq, good, nsent, nrecv, acted, stack, p, q, 
                       evs, walk, cur, po >>

wk0 == /\ pc["worker"] = "wk0"
       /\ walk' = conns
       /\ pc' = [pc EXCEPT !["worker"] = "wk1"]
       /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, 
                       nsent, nrecv, acted, closed, lfail, viol, stack, p, q, 
                       evs, ev, cur, po, snap >>

wk1 == /\ pc["worker"] = "wk1"
       /\ IF walk # <<>>
             THEN /\ LET c == Head(walk) IN
                       LET r == cn[c] IN
                         /\ walk' = Tail(walk)
                         /\ viol' = (viol \cup (IF srv[c] # "open"
                                                THEN {"UseAfterFree"} ELSE {}))
                         /\ IF r.dfr = NoCmd /\ ~r.parked /\ r.out = NoResp
                               THEN /\ pc' = [pc EXCEPT !["worker"] = "wk1"]
                                    /\ UNCHANGED << cur, po >>
                               ELSE /\ cur' = c
                                    /\ po' = r.out
                                    /\ pc' = [pc EXCEPT !["worker"] = "wk2"]
             ELSE /\ pc' = [pc EXCEPT !["worker"] = "wt"]
                  /\ UNCHANGED << viol, walk, cur, po >>
       /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, 
                       nsent, nrecv, acted, closed, lfail, stack, p, q, evs, 
                       ev, snap >>

wk2 == /\ pc["worker"] = "wk2"
       /\ /\ p' = [p EXCEPT !["worker"] = cur]
          /\ stack' = [stack EXCEPT !["worker"] = << [ procedure |->  "egdProcess",
                                                       pc        |->  "wk3",
                                                       p         |->  p["worker"] ] >>
                                                   \o stack["worker"]]
       /\ pc' = [pc EXCEPT !["worker"] = "pr1"]
       /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, good, rv, recvd, 
                       nsent, nrecv, acted, closed, lfail, viol, q, evs, ev, 
                       walk, cur, po, snap >>

wk3 == /\ pc["worker"] = "wk3"
       /\ LET r == cn[cur] IN
            \E stuck \in IF Stall /\ rv = "ok" /\ r.out # NoResp
                            /\ r.out = po
                         THEN BOOLEAN ELSE {FALSE}:
              /\ IF rv # "ok" \/ stuck
                    THEN /\ LET why == IF stuck THEN "stall" ELSE rv IN
                              /\ srv' = [srv EXCEPT ![cur] = "freed"]
                              /\ cn' = [cn EXCEPT ![cur] = Conn0]
                              /\ conns' = SelectSeq(conns, LAMBDA x : x # cur)
                              /\ closed' = [closed EXCEPT ![cur] = why]
                              /\ viol' = (viol \cup (IF why \in {"eof", "rdhup"} /\ cst[cur] # "gone"
                                                        /\ Owed(cur) > 0
                                                     THEN {"Lost"} ELSE {})
                                               \cup (IF why \notin {"err", "stall"} /\ cur \notin Streamers
                                                        /\ ~(Effects(cur) \subseteq acted[cur])
                                                     THEN {"Dropped"} ELSE {}))
                              /\ lfail' = {}
                              /\ IF FixAccept
                                    THEN /\ backoff' = FALSE
                                    ELSE /\ TRUE
                                         /\ UNCHANGED backoff
                    ELSE /\ cn' = [cn EXCEPT ![cur].armed = Arm(r)]
                         /\ UNCHANGED << srv, conns, backoff, closed, lfail, 
                                         viol >>
              /\ cur' = NoConn
              /\ po' = NoResp
              /\ rv' = "ok"
       /\ pc' = [pc EXCEPT !["worker"] = "wk1"]
       /\ UNCHANGED << cst, sq, rq, good, recvd, nsent, nrecv, acted, stack, p, 
                       q, evs, ev, walk, snap >>

worker == wt \/ ev1 \/ ev2 \/ ev3 \/ ev4 \/ wk0 \/ wk1 \/ wk2 \/ wk3

cc(self) == /\ pc[self] = "cc"
            /\ cst' = [cst EXCEPT ![self] = "conn"]
            /\ srv' = [srv EXCEPT ![self] = "backlog"]
            /\ pc' = [pc EXCEPT ![self] = "c1"]
            /\ UNCHANGED << sq, rq, cn, conns, backoff, good, rv, recvd, nsent, 
                            nrecv, acted, closed, lfail, viol, stack, p, q, 
                            evs, ev, walk, cur, po, snap >>

c1(self) == /\ pc[self] = "c1"
            /\ \/ /\ cst[self] = "conn" /\ Len(sq[self]) < SqCap
                  /\ IF self \in Streamers
                        THEN /\ sq' = [sq EXCEPT ![self] = Append(sq[self], <<0, "wr", 0>>)]
                             /\ nsent' = nsent
                        ELSE /\ nsent[self] < Len(Script[self])
                             /\ LET i == nsent[self] + 1 IN
                                  /\ sq' = [sq EXCEPT ![self] = Append(sq[self], <<i, Script[self][i][1],
                                                                                   Script[self][i][2]>>)]
                                  /\ nsent' = [nsent EXCEPT ![self] = i]
                  /\ pc' = [pc EXCEPT ![self] = "c1"]
                  /\ UNCHANGED <<cst, rq, nrecv, viol>>
               \/ /\ rq[self] # <<>>
                  /\ LET rs == Head(rq[self]) IN
                       LET j == nrecv[self] + 1 IN
                         /\ IF j > Len(RespIds(self))
                               THEN /\ viol' = (viol \cup {"Dup"})
                               ELSE /\ IF rs[1] # RespIds(self)[j]
                                          THEN /\ viol' = (viol \cup {"Order"})
                                          ELSE /\ IF ~RespOK(self, rs[1], rs[2])
                                                     THEN /\ viol' = (    viol \cup
                                                                      (CASE Script[self][rs[1]][1] = "blk" -> {"Short"}
                                                                         [] Script[self][rs[1]][1] = "priv" -> {"Priv"}
                                                                         [] OTHER -> {"Content"}))
                                                     ELSE /\ TRUE
                                                          /\ viol' = viol
                         /\ rq' = [rq EXCEPT ![self] = Tail(rq[self])]
                         /\ nrecv' = [nrecv EXCEPT ![self] = j]
                  /\ pc' = [pc EXCEPT ![self] = "c1"]
                  /\ UNCHANGED <<cst, sq, nsent>>
               \/ /\ HalfClose /\ cst[self] = "conn" /\ self \notin Streamers
                     /\ nsent[self] = Len(Script[self])
                  /\ cst' = [cst EXCEPT ![self] = "wrshut"]
                  /\ pc' = [pc EXCEPT ![self] = "c1"]
                  /\ UNCHANGED <<sq, rq, nsent, nrecv, viol>>
               \/ /\ \/ ClientClose
                     \/ self \notin Streamers /\ nsent[self] = Len(Script[self])
                        /\ nrecv[self] = Len(RespIds(self))
                     \/ srv[self] = "freed" /\ rq[self] = <<>>
                  /\ pc' = [pc EXCEPT ![self] = "cx"]
                  /\ UNCHANGED <<cst, sq, rq, nsent, nrecv, viol>>
            /\ UNCHANGED << srv, cn, conns, backoff, good, rv, recvd, acted, 
                            closed, lfail, stack, p, q, evs, ev, walk, cur, po, 
                            snap >>

cx(self) == /\ pc[self] = "cx"
            /\ cst' = [cst EXCEPT ![self] = "gone"]
            /\ rq' = [rq EXCEPT ![self] = <<>>]
            /\ pc' = [pc EXCEPT ![self] = "Done"]
            /\ UNCHANGED << srv, sq, cn, conns, backoff, good, rv, recvd, 
                            nsent, nrecv, acted, closed, lfail, viol, stack, p, 
                            q, evs, ev, walk, cur, po, snap >>

client(self) == cc(self) \/ c1(self) \/ cx(self)

en == /\ pc["env"] = "en"
      /\ Liveness
      /\ good' = TRUE
      /\ pc' = [pc EXCEPT !["env"] = "Done"]
      /\ UNCHANGED << cst, srv, sq, rq, cn, conns, backoff, rv, recvd, nsent, 
                      nrecv, acted, closed, lfail, viol, stack, p, q, evs, ev, 
                      walk, cur, po, snap >>

env == en

Next == worker \/ env
           \/ (\E self \in ProcSet: egdProcess(self) \/ egdRead(self))
           \/ (\E self \in Clients: client(self))

Spec == /\ Init /\ [][Next]_vars
        /\ /\ WF_vars(worker)
           /\ WF_vars(egdProcess("worker"))
           /\ WF_vars(egdRead("worker"))
        /\ \A self \in Clients : WF_vars(client(self))

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ cst \in [Clients -> {"init", "conn", "wrshut", "gone"}]
    /\ srv \in [Clients -> {"none", "backlog", "open", "freed"}]
    /\ closed \in [Clients -> {"none", "eof", "rdhup", "err", "stall", "hup",
                               "pipe"}]
    /\ \A c \in Clients : (closed[c] = "none") = (srv[c] # "freed")
    /\ \A c \in Clients : acted[c] \subseteq 1..nsent[c]
    /\ lfail \subseteq Listeners
    /\ \A c \in Clients : Len(cn[c].in) <= BufCmds /\ Len(rq[c]) <= SndBuf
    /\ NOpen <= Cap + Cardinality(Listeners) - 1

\* The worker never waits: it has a step in every state. The steps that
\* could wait are the recv(), the send() and the generation of a blocking
\* read; they wait with the call in Block and return otherwise, as the
\* non-blocking sockets and generator calls of the code do.
WorkerNeverBlocks ==
    ENABLED (worker \/ egdProcess("worker") \/ egdRead("worker"))

\* At every epoll_wait(), each connection is armed for what it can make
\* progress on: EPOLLOUT while a response is pending, nothing while a
\* request is deferred or parked, EPOLLIN otherwise.
ArmedRight ==
    pc["worker"] = "wt" =>
        \A c \in Clients : srv[c] = "open" =>
            LET r == cn[c] IN
            r.armed = IF r.out # NoResp THEN "out"
                      ELSE IF r.dfr = NoCmd /\ ~r.parked THEN "in"
                      ELSE "none"

\* The state of a deferred request: what was collected is short of what was
\* asked for; neither a response nor a parked read stands beside it; a
\* connection whose client is gone owes nothing.
DeferredState ==
    \A c \in Clients : srv[c] = "open" =>
        LET r == cn[c] IN
        /\ r.dfr = NoCmd => r.ans = 0
        /\ r.dfr # NoCmd => r.ans < r.dfr[3] /\ r.out = NoResp /\ ~r.parked
        /\ r.hup => r.out = NoResp /\ r.dfr = NoCmd /\ ~r.parked

\* No more than ESDM_EGD_MAX_CONNECTIONS connections are served.
WithinCap == NOpen <= Cap

\* No connection is used after esdm_egd_release_conn().
NoUseAfterFree == "UseAfterFree" \notin viol

\* The client gets its responses in the order of its requests, each once.
InOrder == viol \cap {"Order", "Dup"} = {}

\* A blocking read is answered with all it asked for.
FullAnswer == "Short" \notin viol

\* A privileged command succeeds only for a peer with UID 0, and is refused
\* with -EPERM otherwise: as the client sees it in the response ("Priv"),
\* and as the server carries it out, answered or not ("PrivDone").
PrivOnlyRoot == viol \cap {"Priv", "PrivDone"} = {}

\* Answers say what the protocol says for them.
ContentOK == "Content" \notin viol

\* No command is carried out while an earlier one of its connection waits.
NoBypass == "Bypass" \notin viol

\* The worker does not go back to one client's socket for more input while
\* another descriptor is ready: it never blocks on one client while another
\* is ready.
NoStarve == "Starve" \notin viol

\* esdm_egd_write() never finds a response in flight.
OneResponse == "Overflow" \notin viol

\* The server closes a connection by itself (EOF, EPOLLRDHUP) only once
\* the client has all its responses.
NoLoss == "Lost" \notin viol

\* The commands with an effect are not discarded: when the server closes a
\* connection for the end of its input or a hang-up, every write and every
\* privileged command the client sent has reached its handler. A connection
\* closed for a failed generation or by the write timeout is exempt: it is
\* given up with its input.
NoDrop == "Dropped" \notin viol

\* No event is handled without changing anything while its descriptor stays
\* ready: level-triggered epoll would report it again at once. For a
\* listener: after an event that accepted nobody, for a failed accept or
\* at the connection limit, it is not ready at the next epoll_wait() unless
\* a connection was closed in between.
NoSpin == "Spin" \notin viol

\* No send() to a peer that is gone raises SIGPIPE.
NoSigpipe == "Sigpipe" \notin viol

\* No send() reaches a peer that is gone. Not a property of the code: a
\* peer may close at any time, see NoSigpipe.
NoSendToClosed == "SendClosed" \notin viol

-----------------------------------------------------------------------------
(* Liveness, once the generators deliver *)

\* Every client that does not stream is served to its end.
Served ==
    <>[]good => \A c \in Clients \ Streamers : <>(pc[c] = "Done")

\* A client that is gone is cleaned up.
CleanedUp ==
    <>[]good => \A c \in Clients : [](cst[c] = "gone" => <>(srv[c] = "freed"))

-----------------------------------------------------------------------------
(* Liveness, whatever the generators do *)

\* The connection of a client that is gone is closed, with or without
\* output of the generators; with NoDrop, what it sent before is handled.
\* No fairness of epoll_wait() among the ready descriptors is needed for
\* it: the clients here are finite, and every event handled makes progress
\* (NoSpin).
Reclaimed ==
    \A c \in Clients : [](cst[c] = "gone" => <>(srv[c] = "freed"))
=============================================================================
