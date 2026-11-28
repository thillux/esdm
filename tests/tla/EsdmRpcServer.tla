---------------------------- MODULE EsdmRpcServer ----------------------------
(***************************************************************************)
(* Request handling and lifecycle of the ESDM RPC server:                  *)
(* service-rpc/server/esdm_rpc_server.c with the thread pool of            *)
(* common/threading_support.c it runs on. One step is one atomic variable  *)
(* access, one system call or one critical section; the labels name the C  *)
(* functions they come from.                                               *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - Every worker has the shared listening socket of its interface in its  *)
(*   own epoll set, level-triggered; a connection stays with the worker    *)
(*   that accepted it. epoll_wait() returns every ready descriptor, the    *)
(*   loop serves them in any order.                                        *)
(* - A request is one SOCK_SEQPACKET message, numbered per connection.     *)
(*   With BadReq a client may send an invalid one (short, oversized, an    *)
(*   unknown method, not unpackable): esdm_rpcs_process() fails and        *)
(*   esdm_rpcs_conn_event() closes the connection without a reply. A valid *)
(*   request is served in two steps, the handler up to its authorization   *)
(*   (hsP) and its effect with the reply (hsT): all handlers call          *)
(*   esdm_get_random_bytes*() without blocking and reply exactly once.     *)
(* - Every handler of the privileged interface asks                        *)
(*   esdm_rpc_client_is_privileged() first; the worker keeps the answer    *)
(*   (auth) and the call takes effect (applied) only with it. The          *)
(*   unprivileged interface has no such call.                              *)
(* - The server closes a connection with a request unanswered in these     *)
(*   cases only: the request is invalid; its reply cannot be delivered     *)
(*   (below); the client hung up; accept4() succeeded but memory or the    *)
(*   epoll set had no room for the connection; the server shuts down.      *)
(* - A write either delivers, fails with EPIPE (the client closed), or,    *)
(*   with SndBuf unread responses queued, waits for the client or times    *)
(*   out. Write retries are part of that wait.                             *)
(* - With Idle, the idle timer fires whenever a worker holds connections   *)
(*   or the exit flag is set; a pass closes the connections not read since *)
(*   the previous pass. Without Idle it never fires, so that a worker      *)
(*   blocked in epoll_wait() learns of a shutdown from its eventfd only.   *)
(* - esdm_rpcs_close_idle_conn() closes such a connection in three steps:  *)
(*   shutdown(SHUT_RD), after which a write() of the client fails with     *)
(*   EPIPE - it closes its end and connects anew - while the requests it   *)
(*   wrote before stay readable; esdm_rpcs_read() until nothing is left,   *)
(*   each request served as any other; the close, a step of its own after  *)
(*   the read that found nothing. The shutdown and the first read are one  *)
(*   step. A pass takes the connections in any order. Before the fix       *)
(*   (FixIdle = FALSE) the pass closed them in one step with what they     *)
(*   held: a request written since epoll_wait() returned was dropped.      *)
(* - With FdFull, accept4() may fail for want of descriptors while a       *)
(*   client is queued; a pending accept retry falls due at any time. The   *)
(*   connection may also be accepted and released at once: calloc() failed *)
(*   or epoll_ctl(ADD) reported ENOMEM or ENOSPC.                          *)
(* - With FailEpoll, the set-up of a worker's epoll set and timer,         *)
(*   epoll_wait() and the epoll_ctl(ADD) of an accepted connection may     *)
(*   fail: the worker leaves its loop, and ends the server with the fix.   *)
(* - A worker woken for the listener at its connection cap does not        *)
(*   accept; without CapDisarm the listener stays armed there.             *)
(* - A hang-up is seen when the connection is served, not when             *)
(*   epoll_wait() returned: both end in esdm_rpcs_close_conn().            *)
(* - Each worker has a pool slot of its own: thread_start() takes it       *)
(*   unless thread_wait_all() has flagged it for shutdown; the special     *)
(*   slot of esdm_rpcs_unpriv_init() is held until it returns. The         *)
(*   shutdown runs thread_wait_all(false) in esdm_rpc_server_fini() and    *)
(*   thread_wait_all(true) in esdm_fini(). Freed memory is the threads     *)
(*   array of esdm_rpcs_workerloop() (targs), the frame holding the        *)
(*   interface's struct esdm_rpcs (frame), and connections.                *)
(* - The Fix* switches select the code after the fixes; a configuration of *)
(*   the code before a fix turns its switch off. Mutant seeds a defect the *)
(*   code never had, to show a property able to fail: "NoReply", a handler *)
(*   that closes instead of replying, and "NoPrivCheck", a handler of the  *)
(*   privileged interface without the authorization.                       *)
(* - The model ends or idles explicitly, so that TLC's deadlock check      *)
(*   reports every other state without a step: after main() returned every *)
(*   process ends (a client's connect() fails, a pool thread never used    *)
(*   ends, the signal source ends last); while the server runs, the signal *)
(*   source stutters in the states of Idling, in which both interfaces     *)
(*   serve, every client is done and no connection is open or queued.      *)
(* - Not modelled: the ES monitor's rounds (it reports the privileged      *)
(*   initialization once), the EGD server, systemd socket activation, a    *)
(*   failing epoll_ctl(MOD) of the listener, EINTR, the PR reservation of  *)
(*   esdm_rpc_get_random_bytes_pr(), and the process exit killing threads  *)
(*   still running after main() returned.                                  *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    PW,           \* the privileged worker, esdm_rpcs_workerloop() starts one
    UW,           \* unprivileged workers, one per online node
    Clients,
    PrivClients,  \* clients of the privileged socket, the others unprivileged
    Root,         \* clients with UID 0
    DropUid,      \* root clients that drop their privileges once connected
    PrivSockOpen, \* the privileged socket admits all (systemd SocketMode=)
    MaxConn,      \* connections each client opens
    MaxReq,       \* requests per connection
    Pipe,         \* requests a client has in flight; 1 is the ESDM client
    SndBuf,       \* unread responses a connection holds before write() blocks
    Cap,          \* ESDM_RPCS_MAX_CONN_PER_WORKER
    ClientClose,  \* clients close at any time (timeout, exit), not only done
    Idle,         \* the idle timer fires
    Signal,       \* a termination signal arrives
    FailUnpriv,   \* the unprivileged socket set-up may fail
    FailDrop,     \* drop_privileges_permanent() may fail
    FailEfd,      \* eventfd() may fail in esdm_rpcs_workerloop()
    FailStart,    \* thread_start() may fail there
    FdFull,       \* accept4() may fail for want of descriptors
    BadReq,       \* clients may send invalid requests
    FailEpoll,    \* a worker's epoll set-up, epoll_wait() or epoll_ctl(ADD)
                  \* of a connection may fail
    CapDisarm,    \* the listener is disarmed at the connection cap
    Mutant,       \* a seeded defect: "none", "NoReply" or "NoPrivCheck"
    FixLoop,      \* fix: all eventfds before a worker starts, a failed
                  \* thread_start() or interface ends the server
    FixSpin,      \* fix: a failed accept4() disarms the listener for a while
    FixLostReply, \* fix: every failed write marks the connection broken
    FixJoin,      \* fix: esdm_rpc_server_fini() waits for the unprivileged
                  \* interface thread before thread_wait_all()
    FixWorkerExit, \* fix: a worker that leaves on a failure ends the server
    FixIdle       \* fix: the idle pass stops the client's writes and serves
                  \* what it wrote before, then closes

ASSUME Mutant \in {"none", "NoReply", "NoPrivCheck"}

Socks == {"priv", "unpriv"}
Workers == PW \cup UW
NoW == "none"
NoConn == <<"none", 0>>
\* the other descriptors in an epoll set, shaped like connections
Listen == <<"listen", 0>>
Efd == <<"efd", 0>>
Timer == <<"timer", 0>>
ConnIds == Clients \X (1..MaxConn)
Enum(S) == CHOOSE s \in [1..Cardinality(S) -> S] :
               \A i, j \in DOMAIN s : i # j => s[i] # s[j]
PSeq == Enum(PW)
USeq == Enum(UW)
\* esdm_rpcs_workerloop() starts them in this order
WSeq(m) == IF m = "priv" THEN PSeq ELSE USeq
\* thread_wait_all() walks the slots in this order
WAll == PSeq \o USeq
Mine(m) == IF m = "priv" THEN PW ELSE UW
Sock(w) == IF w \in PW THEN "priv" ELSE "unpriv"
Target(c) == IF c \in PrivClients THEN "priv" ELSE "unpriv"
Client(k) == k[1]

(* --algorithm EsdmRpcServer {
variables
    initState = "uninit",               \* esdm_rpc_init_state
    serverExit = 0,                     \* server_exit
    unpStarted = FALSE,                 \* esdm_rpcs_unpriv_init() started
    unpDone = FALSE,                    \* ... and returned
    dropped = FALSE,                    \* privileges dropped
    fin = FALSE,                        \* esdm_fini() ran
    exited = FALSE,                     \* main() returned
    lsock = [s \in Socks |-> "none"],   \* server_listening_fd
    backlog = [s \in Socks |-> <<>>],
    frame = [s \in Socks |-> "none"],   \* priv_proto, unpriv_proto
    targs = [s \in Socks |-> "none"],   \* threads of esdm_rpcs_workerloop()
    efd = [w \in Workers |-> "none"],   \* esdm_rpc_thread.eventfd
    thr = [w \in Workers |-> "none"],   \* the worker's pool thread
    shut = [w \in Workers |-> FALSE],   \* thread_ctx.shutdown
    joinMe = [w \in Workers |-> FALSE], \* thread_wait_all(): join_me
    num = [w \in Workers |-> 0],        \* num_connections
    owner = [k \in ConnIds |-> NoW],    \* whose epoll set and list hold it
    srv = [k \in ConnIds |-> "none"],   \* backlog, open, closed or refused
    fresh = [k \in ConnIds |-> FALSE],  \* read since the last idle pass
    peerRoot = [k \in ConnIds |-> FALSE], \* SO_PEERCRED: UID 0 at connect()
    cclosed = [k \in ConnIds |-> FALSE],  \* the client closed its end
    inq = [k \in ConnIds |-> <<>>],     \* requests queued at the server
    rdshut = [k \in ConnIds |-> FALSE], \* shutdown(SHUT_RD) by the idle pass
    outq = [k \in ConnIds |-> <<>>],    \* responses queued at the client
    rootNow = [c \in Clients |-> c \in Root],
    rv = [p \in {"main", "unp"} |-> 0],
    wfailed = [w \in Workers |-> FALSE], \* the worker left on a failure
    \* ghosts: the ES monitor reported, the unprivileged worker loop failed,
    \* wakeups for the listener without an accept since it was last
    \* re-armed, and the properties violated
    monDone = FALSE,
    unpFailed = FALSE,
    spins = [w \in Workers |-> 0],
    viol = {},
    \* ghosts of the requests: sent, sent invalid, read by a worker, answered,
    \* reply not delivered, privileged call carried out; the responses
    \* written per connection; the connections the idle timer closed and
    \* the ones released at accept
    asked = {},
    bad = {},
    taken = {},
    answered = {},
    undeliv = {},
    applied = {},
    sent = [k \in ConnIds |-> 0],
    reaped = {},
    rejected = {};

define {
    Owned(w) == {k \in ConnIds : owner[k] = w}
    Gone(k) == srv[k] \in {"closed", "refused"} \/ exited
    Permitted(c) == Target(c) = "unpriv" \/ rootNow[c] \/ PrivSockOpen
    \* what epoll_wait() reports, the listener armed below the cap
    Ready(w, armed) ==
        (IF armed /\ lsock[Sock(w)] = "listen" /\ backlog[Sock(w)] # <<>>
         THEN {Listen} ELSE {})
        \cup (IF efd[w] = "set" THEN {Efd} ELSE {})
        \cup {k \in Owned(w) : inq[k] # <<>> \/ cclosed[k]}
    UAF(b) == IF b THEN {"UseAfterFree"} ELSE {}
    ArgsGone(w) == targs[Sock(w)] # "alloc"
    ProtoGone(w) == frame[Sock(w)] # "live"
    \* the server runs and has nothing to do: both interfaces serve, every
    \* client is done, no connection is open or queued
    Idling ==
        /\ serverExit = 0
        /\ pc["main"] = "wl3"
        /\ pc["unp"] \in {"wl3", "Done"}
        /\ \A c \in Clients : pc[c] = "Done"
        /\ \A k \in ConnIds : srv[k] \notin {"backlog", "open"}
    \* main() returned and every other process ended
    Finished ==
        /\ exited
        /\ \A p \in {"main", "unp", "mon"} \cup Workers \cup Clients :
               pc[p] = "Done"
}

\* esdm_rpcs_close_conn(): out of the epoll set and the list, freed
macro closeConn(kk) {
    owner[kk] := NoW;
    srv[kk] := "closed";
    inq[kk] := <<>>;
    num[self] := num[self] - 1;
    \* a descriptor became free
    retry := FALSE;
    spins[self] := 0;
}

\* eesdm_rpcs_stop(): the queued connections are reset
macro stopSock(s) {
    if (lsock[s] = "listen") {
        lsock[s] := "closed";
        srv := [k \in ConnIds |->
                IF \E j \in DOMAIN backlog[s] : backlog[s][j] = k
                THEN "refused" ELSE srv[k]];
        backlog[s] := <<>>;
    };
}

\* esdm_rpcs_workerloop(): one eventfd and pool job per worker, then wait
\* for the exit flag, wake the workers and wait for them
procedure workerloop(ifc)
    variables t = 1, startErr = FALSE;
{
wl0: targs[ifc] := "alloc";
     if (FixLoop) {
wlF:     while (t <= Len(WSeq(ifc))) {
             either { efd[WSeq(ifc)[t]] := "open"; t := t + 1; }
             or { await FailEfd; goto wlE; };
         };
         t := 1;
     };
wl1: while (t <= Len(WSeq(ifc))) {
         if (~FixLoop) {
             either { efd[WSeq(ifc)[t]] := "open"; }
             or { await FailEfd; goto wlE; };
         };
         \* thread_start(): retried while thread_wait_all() holds the slot
wl2:     either {
             await ~shut[WSeq(ifc)[t]];
             thr[WSeq(ifc)[t]] := "sched";
             t := t + 1;
         } or {
             await FailStart;
             if (FixLoop) {
                 \* the server ends, the started workers are waited for
                 serverExit := 1;
                 startErr := TRUE;
                 goto wl3;
             } else {
                 \* ignored: the worker is missing
                 t := t + 1;
             };
         };
     };
     \* thread_wait_event(), then the eventfds written
wl3: await serverExit # 0;
     efd := [w \in Workers |->
             IF w \in Mine(ifc) /\ efd[w] = "open" THEN "set" ELSE efd[w]];
     \* thread_wait(true): the jobs of this thread
wl4: await \A w \in Mine(ifc) : thr[w] \notin {"sched", "run"};
     efd := [w \in Workers |-> IF w \in Mine(ifc) THEN "closed" ELSE efd[w]];
     targs[ifc] := "freed";
     \* thread_wait() collects the results of the jobs
     rv[self] := IF startErr
                    \/ (FixWorkerExit /\ \E w \in Mine(ifc) : wfailed[w])
                 THEN -1 ELSE 0;
     return;
     \* out: on a failed eventfd()
wlE: targs[ifc] := "freed";
     rv[self] := -1;
     return;
}

\* esdm_rpc_server_init(), esdm_rpcs_interfaces_init() serving the
\* privileged interface, then esdm_rpc_server_fini() and esdm_fini()
fair process (pmain = "main")
    variables wi = 1;
{
ma0: if (serverExit # 0) goto maF;
     \* thread_wait_event() for the ES monitor, then the root-only socket
ma1: await initState = "privdone" \/ serverExit # 0;
     frame["priv"] := "live";
     lsock["priv"] := "listen";
ma2: unpStarted := TRUE;
     if (serverExit # 0) goto maS;
ma3: await initState \in {"unpdone", "unpfail"} \/ serverExit # 0;
     if (initState = "unpfail" \/ serverExit # 0) goto maS;
     \* drop_privileges_permanent()
ma4: either { dropped := TRUE; } or { await FailDrop; goto maS; };
ma5: initState := "dropped";
     call workerloop("priv");
ma6: if (rv["main"] # 0) goto maS else goto maR;
maS: stopSock("priv");
maR: frame["priv"] := "dead";
     rv["main"] := 0;
     \* esdm_rpc_server_fini()
maF: serverExit := 1;
     \* the fix: wait for esdm_rpcs_unpriv_init() to return first
maW: if (FixJoin) await ~unpStarted \/ unpDone;
     \* thread_wait_all(false): flag every slot under its inuse lock, which a
     \* running job holds, then join the threads that existed
maA: while (wi <= Len(WAll)) {
         await thr[WAll[wi]] # "run";
         joinMe[WAll[wi]] := thr[WAll[wi]] # "none";
         shut[WAll[wi]] := TRUE;
         wi := wi + 1;
     };
     wi := 1;
maJ: while (wi <= Len(WAll)) {
         if (joinMe[WAll[wi]]) {
             await thr[WAll[wi]] = "exit";
             thr[WAll[wi]] := "none";
             joinMe[WAll[wi]] := FALSE;
         };
         wi := wi + 1;
     };
     shut := [w \in Workers |-> FALSE];
     wi := 1;
     \* esdm_fini(): esdm_es_mgr_finalize() runs thread_wait_all(true), the
     \* worker slots again and then the special slots, among them that of
     \* esdm_rpcs_unpriv_init(), whose inuse lock is held until it returns
maB: while (wi <= Len(WAll)) {
         await thr[WAll[wi]] # "run";
         joinMe[WAll[wi]] := thr[WAll[wi]] # "none";
         shut[WAll[wi]] := TRUE;
         wi := wi + 1;
     };
     wi := 1;
maU: await ~unpStarted \/ unpDone;
maK: while (wi <= Len(WAll)) {
         if (joinMe[WAll[wi]]) {
             await thr[WAll[wi]] = "exit";
             thr[WAll[wi]] := "none";
             joinMe[WAll[wi]] := FALSE;
         };
         wi := wi + 1;
     };
     shut := [w \in Workers |-> FALSE];
     wi := 1;
     \* the entropy sources and the DRNGs are released
maZ: fin := TRUE;
maX: exited := TRUE;
}

\* esdm_rpcs_unpriv_init()
fair process (punp = "unp")
{
un0: await unpStarted \/ exited;
     \* never started
     if (~unpStarted) goto unZ;
un4: frame["unpriv"] := "live";
     either { lsock["unpriv"] := "listen"; }
     or { await FailUnpriv; goto unF; };
un1: initState := "unpdone";
     if (serverExit # 0) goto unS;
un2: await initState = "dropped" \/ serverExit # 0;
     if (serverExit # 0) {
         goto unS;
     } else {
         call workerloop("unpriv");
     };
un3: if (rv["unp"] # 0) {
         \* failed while serving: with the fix, the server ends
         unpFailed := TRUE;
         if (FixLoop) serverExit := 1;
         goto unS;
     } else if (FixLoop) {
         goto unS;
     } else {
         goto unR;
     };
     \* out: a failure is reported only before unpriv_init
unF: if (initState \in {"uninit", "privdone"}) initState := "unpfail";
     goto unR;
unS: stopSock("unpriv");
unR: frame["unpriv"] := "dead";
     rv["unp"] := 0;
     unpDone := TRUE;
unZ: skip;
}

\* esdm_rpc_priv_init_complete(), called once by the ES monitor
fair process (pmon = "mon")
{
mo1: if (initState # "uninit") goto moZ;
mo2: initState := "privdone";
     monDone := TRUE;
moZ: skip;
}

\* esdm_rpc_server_signal_exit_safe() from the signal handler
fair process (penv = "env")
{
en0: if (Signal) serverExit := 1;
     \* nothing more to come: the server idles, or everything ended
enI: while (~Finished) {
         await Idling;
         skip;
     };
}

\* thread_worker() running esdm_rpcs_handler()
fair process (wk \in Workers)
    variables batch = {}, reap = FALSE, cur = NoConn, rq = 0, retry = FALSE,
              auth = FALSE, due = {};
{
hs0: await thr[self] = "sched" \/ exited;
     if (thr[self] # "sched") {
         \* a pool thread never used
         goto hsZ;
     } else if (shut[self]) {
         \* the shutdown flag comes before the job
         thr[self] := "exit";
         goto hsZ;
     } else {
         thr[self] := "run";
     };
     \* epoll set: the listener, thread->eventfd; thread->proto kept
hs1: viol := viol \cup UAF(ArgsGone(self) \/ ProtoGone(self));
     if (lsock[Sock(self)] # "listen") {
         \* epoll_ctl(ADD) of a closed listener fails
         goto hsF;
     } else {
         \* epoll_create1(), the timer or an epoll_ctl(ADD) may fail
         either { skip; } or { await FailEpoll; goto hsF; };
     };
hsL: while (serverExit = 0) {
         \* the listener armed below the cap, then epoll_wait(): blocked
         \* until a descriptor is ready, server_exit alone does not wake it
hsW:     with (rdy = Ready(self, (num[self] < Cap \/ ~CapDisarm) /\ ~retry)) {
             either { await rdy # {}; batch := rdy; }
             or {
                 \* epoll_wait() fails
                 await FailEpoll;
                 goto hsF;
             } or {
                 await Idle /\ (Owned(self) # {} \/ serverExit # 0);
                 batch := rdy \cup {Timer};
             } or {
                 \* the accept retry is due: the timeout of epoll_wait()
                 await retry;
                 retry := FALSE;
                 spins[self] := 0;
                 batch := rdy;
             };
         };
hsE:     while (batch # {}) {
             with (x \in batch) {
                 if (x = Timer) {
                     reap := TRUE;
                     batch := batch \ {x};
                 } else if (x = Efd) {
                     \* termination event: read(thread->eventfd), break
                     viol := viol \cup UAF(ArgsGone(self));
                     efd[self] := "open";
                     batch := {};
                 } else if (x = Listen) {
                     \* esdm_rpcs_accept(): EAGAIN if another worker was faster
                     viol := viol \cup UAF(ProtoGone(self));
                     if (num[self] >= Cap) {
                         \* at the cap: not accepted, the client stays queued
                         spins[self] := IF spins[self] < 2
                                        THEN spins[self] + 1 ELSE 2;
                     } else if (backlog[Sock(self)] # <<>>) {
                         either {
                             with (kk = Head(backlog[Sock(self)])) {
                                 backlog[Sock(self)] :=
                                     Tail(backlog[Sock(self)]);
                                 owner[kk] := self;
                                 srv[kk] := "open";
                                 fresh[kk] := TRUE;
                             };
                             num[self] := num[self] + 1;
                             spins[self] := 0;
                         } or {
                             \* EMFILE: the client stays queued
                             await FdFull;
                             spins[self] := IF spins[self] < 2
                                            THEN spins[self] + 1 ELSE 2;
                             if (FixSpin) retry := TRUE;
                         } or {
                             \* accepted and released: no memory, or the
                             \* epoll set is full (ENOMEM, ENOSPC); with
                             \* another failure of epoll_ctl(ADD) the
                             \* worker leaves
                             await FdFull \/ FailEpoll;
                             with (kk = Head(backlog[Sock(self)])) {
                                 backlog[Sock(self)] :=
                                     Tail(backlog[Sock(self)]);
                                 srv[kk] := "closed";
                                 inq[kk] := <<>>;
                                 rejected := rejected \cup {kk};
                             };
                             either { await FdFull; }
                             or { await FailEpoll; wfailed[self] := TRUE; };
                         };
                     };
                     batch := batch \ {x};
                 } else if (cclosed[x] \/ inq[x] = <<>>) {
                     \* esdm_rpcs_conn_event(): EPOLLRDHUP, or read() gave 0
                     viol := viol \cup UAF(owner[x] # self);
                     closeConn(x);
                     batch := batch \ {x};
                 } else {
                     \* esdm_rpcs_read(): one message, the worker's buffer
                     viol := viol \cup UAF(owner[x] # self);
                     rq := Head(inq[x]);
                     taken := taken \cup {<<x, Head(inq[x])>>};
                     inq[x] := Tail(inq[x]);
                     fresh[x] := TRUE;
                     cur := x;
                     batch := batch \ {x};
                 };
             };
             if (wfailed[self]) {
                 goto hsF;
             } else if (cur # NoConn) {
                 \* esdm_rpcs_process(), esdm_rpcs_unpack():
                 \* rpc_conn->proto->service invoked
hsP:             viol := viol
                     \cup UAF(ProtoGone(self) \/ owner[cur] # self)
                     \cup (IF ~dropped THEN {"ServedPrivileged"} ELSE {})
                     \cup (IF fin THEN {"ServedAfterFini"} ELSE {});
                 if (<<cur, rq>> \in bad) {
                     \* -EINVAL, -ENOMEM: closed "on error", no reply
                     closeConn(cur);
                     cur := NoConn;
                     rq := 0;
                 } else {
                     \* a handler of the privileged interface:
                     \* esdm_rpc_client_is_privileged() reads SO_PEERCRED
                     auth := Sock(self) = "priv"
                             /\ (peerRoot[cur] \/ Mutant = "NoPrivCheck");
                     \* the call takes effect, then esdm_rpcs_pack() and
                     \* esdm_rpcs_write_data()
hsT:                 if (auth) {
                         applied := applied \cup {<<cur, rq>>};
                         viol := viol \cup (IF ~rootNow[Client(cur)]
                                            THEN {"PrivAtCall"} ELSE {});
                     };
                     auth := FALSE;
                     either {
                         await cclosed[cur] \/ Len(outq[cur]) < SndBuf;
                         if (cclosed[cur]) {
                             \* EPIPE: broken, the event loop closes it
                             undeliv := undeliv \cup {<<cur, rq>>};
                             closeConn(cur);
                         } else if (Mutant = "NoReply") {
                             closeConn(cur);
                         } else {
                             outq[cur] := Append(outq[cur], rq);
                             answered := answered \cup {<<cur, rq>>};
                             sent[cur] := sent[cur] + 1;
                         };
                     } or {
                         \* the client does not read: ppoll() times out
                         await ~cclosed[cur] /\ Len(outq[cur]) >= SndBuf;
                         undeliv := undeliv \cup {<<cur, rq>>};
                         if (FixLostReply) closeConn(cur);
                     };
                     if (rdshut[cur] /\ srv[cur] = "open") {
                         \* the idle pass goes on with this connection
                         goto hsD;
                     } else {
                         cur := NoConn;
                         rq := 0;
                     };
                 };
             };
         };
         \* the idle timer: what was not read since the last pass falls due
hsC:     if (reap /\ FixIdle) {
             due := {k \in Owned(self) : ~fresh[k]};
             fresh := [k \in ConnIds |->
                       IF k \in Owned(self) THEN FALSE ELSE fresh[k]];
         } else if (reap) {
             \* before the fix: closed with the requests it holds
             with (idle = {k \in Owned(self) : ~fresh[k]}) {
                 owner := [k \in ConnIds |->
                           IF k \in idle THEN NoW ELSE owner[k]];
                 srv := [k \in ConnIds |->
                         IF k \in idle THEN "closed" ELSE srv[k]];
                 inq := [k \in ConnIds |->
                         IF k \in idle THEN <<>> ELSE inq[k]];
                 fresh := [k \in ConnIds |->
                           IF k \in Owned(self) THEN FALSE ELSE fresh[k]];
                 num[self] := num[self] - Cardinality(idle);
                 reaped := reaped \cup idle;
                 if (idle # {}) {
                     retry := FALSE;
                     spins[self] := 0;
                 };
             };
         };
         reap := FALSE;
         \* no connection is due, or none is left: the loop goes on
         if (due = {}) goto hsL;
         \* esdm_rpcs_close_idle_conn(): shutdown(SHUT_RD), esdm_rpcs_read()
hsR:     while (due # {}) {
             with (k \in due) {
                 viol := viol \cup UAF(owner[k] # self);
                 rdshut[k] := TRUE;
                 due := due \ {k};
                 cur := k;
                 if (inq[k] # <<>>) {
                     \* a request written before the shutdown: served
                     rq := Head(inq[k]);
                     taken := taken \cup {<<k, Head(inq[k])>>};
                     inq[k] := Tail(inq[k]);
                 };
             };
             if (rq # 0) {
                 goto hsP;
             } else {
                 goto hsK;
             };
             \* after a reply: esdm_rpcs_read() again, until EOF
hsD:         if (inq[cur] # <<>>) {
                 rq := Head(inq[cur]);
                 taken := taken \cup {<<cur, Head(inq[cur])>>};
                 inq[cur] := Tail(inq[cur]);
                 goto hsP;
             };
             \* EOF: esdm_rpcs_close_conn() " after timeout"
hsK:         closeConn(cur);
             reaped := reaped \cup {cur};
             cur := NoConn;
             rq := 0;
         };
     };
     goto hsX;
     \* out, with an error: the fix ends the server, as for a failed start
hsF: wfailed[self] := TRUE;
     batch := {};
     reap := FALSE;
     due := {};
     if (FixWorkerExit) serverExit := 1;
     \* out: every connection closed, the job ends
hsX: with (mine = Owned(self)) {
         owner := [k \in ConnIds |-> IF k \in mine THEN NoW ELSE owner[k]];
         srv := [k \in ConnIds |-> IF k \in mine THEN "closed" ELSE srv[k]];
         inq := [k \in ConnIds |-> IF k \in mine THEN <<>> ELSE inq[k]];
     };
     num[self] := 0;
     thr[self] := "idle";
     \* idle in the pool until thread_wait_all() shuts it down
hsI: await shut[self];
     thr[self] := "exit";
hsZ: skip;
}

\* an RPC client: connects, pipelines up to Pipe requests and matches the
\* responses by order, as the ESDM client does
fair process (cl \in Clients)
    variables ck = NoConn, cn = 0, cgot = 0, ci = 0;
{
cl0: while (ci < MaxConn) {
         \* connect(): queued in the backlog of a listening socket
         \* or refused: no socket, the server gone, or no permission
         await lsock[Target(self)] # "none" \/ exited;
         if (lsock[Target(self)] = "listen" /\ Permitted(self)) {
             with (kk = <<self, ci + 1>>) {
                 backlog[Target(self)] := Append(backlog[Target(self)], kk);
                 srv[kk] := "backlog";
                 peerRoot[kk] := rootNow[self];
                 ck := kk;
             };
             ci := ci + 1;
         } else {
             goto clZ;
         };
cl1:     while (TRUE) {
             either {
                 await cn < MaxReq /\ cn - cgot < Pipe /\ ~Gone(ck)
                       /\ ~rdshut[ck];
                 inq[ck] := Append(inq[ck], cn + 1);
                 asked := asked \cup {<<ck, cn + 1>>};
                 either { skip; }
                 or { await BadReq; bad := bad \cup {<<ck, cn + 1>>}; };
                 cn := cn + 1;
             } or {
                 await outq[ck] # <<>>;
                 viol := viol \cup (IF Head(outq[ck]) # cgot + 1
                                    THEN {"OutOfStep"} ELSE {});
                 outq[ck] := Tail(outq[ck]);
                 cgot := cgot + 1;
             } or {
                 \* write() fails with EPIPE, the server reads no more: the
                 \* client closes its end and connects anew
                 await cn < MaxReq /\ cn - cgot < Pipe /\ ~Gone(ck)
                       /\ rdshut[ck];
                 cclosed[ck] := TRUE;
                 outq[ck] := <<>>;
                 goto clN;
             } or {
                 \* EOF: closed by the server, all read
                 await Gone(ck) /\ outq[ck] = <<>>;
                 goto clN;
             } or {
                 \* done, or a timeout or exit
                 await ClientClose \/ (cn = MaxReq /\ cgot = cn);
                 cclosed[ck] := TRUE;
                 outq[ck] := <<>>;
                 goto clN;
             } or {
                 \* setuid(): the connection keeps its SO_PEERCRED
                 await self \in DropUid /\ rootNow[self];
                 rootNow[self] := FALSE;
             };
         };
clN:     ck := NoConn;
         cn := 0;
         cgot := 0;
     };
clZ: skip;
}
} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES initState, serverExit, unpStarted, unpDone, dropped, fin, exited, 
          lsock, backlog, frame, targs, efd, thr, shut, joinMe, num, owner, 
          srv, fresh, peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
          wfailed, monDone, unpFailed, spins, viol, asked, bad, taken, 
          answered, undeliv, applied, sent, reaped, rejected, pc, stack

(* define statement *)
Owned(w) == {k \in ConnIds : owner[k] = w}
Gone(k) == srv[k] \in {"closed", "refused"} \/ exited
Permitted(c) == Target(c) = "unpriv" \/ rootNow[c] \/ PrivSockOpen

Ready(w, armed) ==
    (IF armed /\ lsock[Sock(w)] = "listen" /\ backlog[Sock(w)] # <<>>
     THEN {Listen} ELSE {})
    \cup (IF efd[w] = "set" THEN {Efd} ELSE {})
    \cup {k \in Owned(w) : inq[k] # <<>> \/ cclosed[k]}
UAF(b) == IF b THEN {"UseAfterFree"} ELSE {}
ArgsGone(w) == targs[Sock(w)] # "alloc"
ProtoGone(w) == frame[Sock(w)] # "live"


Idling ==
    /\ serverExit = 0
    /\ pc["main"] = "wl3"
    /\ pc["unp"] \in {"wl3", "Done"}
    /\ \A c \in Clients : pc[c] = "Done"
    /\ \A k \in ConnIds : srv[k] \notin {"backlog", "open"}

Finished ==
    /\ exited
    /\ \A p \in {"main", "unp", "mon"} \cup Workers \cup Clients :
           pc[p] = "Done"

VARIABLES ifc, t, startErr, wi, batch, reap, cur, rq, retry, auth, due, ck, 
          cn, cgot, ci

vars == << initState, serverExit, unpStarted, unpDone, dropped, fin, exited, 
           lsock, backlog, frame, targs, efd, thr, shut, joinMe, num, owner, 
           srv, fresh, peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
           wfailed, monDone, unpFailed, spins, viol, asked, bad, taken, 
           answered, undeliv, applied, sent, reaped, rejected, pc, stack, ifc, 
           t, startErr, wi, batch, reap, cur, rq, retry, auth, due, ck, cn, 
           cgot, ci >>

ProcSet == {"main"} \cup {"unp"} \cup {"mon"} \cup {"env"} \cup (Workers) \cup (Clients)

Init == (* Global variables *)
        /\ initState = "uninit"
        /\ serverExit = 0
        /\ unpStarted = FALSE
        /\ unpDone = FALSE
        /\ dropped = FALSE
        /\ fin = FALSE
        /\ exited = FALSE
        /\ lsock = [s \in Socks |-> "none"]
        /\ backlog = [s \in Socks |-> <<>>]
        /\ frame = [s \in Socks |-> "none"]
        /\ targs = [s \in Socks |-> "none"]
        /\ efd = [w \in Workers |-> "none"]
        /\ thr = [w \in Workers |-> "none"]
        /\ shut = [w \in Workers |-> FALSE]
        /\ joinMe = [w \in Workers |-> FALSE]
        /\ num = [w \in Workers |-> 0]
        /\ owner = [k \in ConnIds |-> NoW]
        /\ srv = [k \in ConnIds |-> "none"]
        /\ fresh = [k \in ConnIds |-> FALSE]
        /\ peerRoot = [k \in ConnIds |-> FALSE]
        /\ cclosed = [k \in ConnIds |-> FALSE]
        /\ inq = [k \in ConnIds |-> <<>>]
        /\ rdshut = [k \in ConnIds |-> FALSE]
        /\ outq = [k \in ConnIds |-> <<>>]
        /\ rootNow = [c \in Clients |-> c \in Root]
        /\ rv = [p \in {"main", "unp"} |-> 0]
        /\ wfailed = [w \in Workers |-> FALSE]
        /\ monDone = FALSE
        /\ unpFailed = FALSE
        /\ spins = [w \in Workers |-> 0]
        /\ viol = {}
        /\ asked = {}
        /\ bad = {}
        /\ taken = {}
        /\ answered = {}
        /\ undeliv = {}
        /\ applied = {}
        /\ sent = [k \in ConnIds |-> 0]
        /\ reaped = {}
        /\ rejected = {}
        (* Procedure workerloop *)
        /\ ifc = [ self \in ProcSet |-> defaultInitValue]
        /\ t = [ self \in ProcSet |-> 1]
        /\ startErr = [ self \in ProcSet |-> FALSE]
        (* Process pmain *)
        /\ wi = 1
        (* Process wk *)
        /\ batch = [self \in Workers |-> {}]
        /\ reap = [self \in Workers |-> FALSE]
        /\ cur = [self \in Workers |-> NoConn]
        /\ rq = [self \in Workers |-> 0]
        /\ retry = [self \in Workers |-> FALSE]
        /\ auth = [self \in Workers |-> FALSE]
        /\ due = [self \in Workers |-> {}]
        (* Process cl *)
        /\ ck = [self \in Clients |-> NoConn]
        /\ cn = [self \in Clients |-> 0]
        /\ cgot = [self \in Clients |-> 0]
        /\ ci = [self \in Clients |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self = "main" -> "ma0"
                                        [] self = "unp" -> "un0"
                                        [] self = "mon" -> "mo1"
                                        [] self = "env" -> "en0"
                                        [] self \in Workers -> "hs0"
                                        [] self \in Clients -> "cl0"]

wl0(self) == /\ pc[self] = "wl0"
             /\ targs' = [targs EXCEPT ![ifc[self]] = "alloc"]
             /\ IF FixLoop
                   THEN /\ pc' = [pc EXCEPT ![self] = "wlF"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "wl1"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, efd, 
                             thr, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, t, startErr, wi, 
                             batch, reap, cur, rq, retry, auth, due, ck, cn, 
                             cgot, ci >>

wlF(self) == /\ pc[self] = "wlF"
             /\ IF t[self] <= Len(WSeq(ifc[self]))
                   THEN /\ \/ /\ efd' = [efd EXCEPT ![WSeq(ifc[self])[t[self]]] = "open"]
                              /\ t' = [t EXCEPT ![self] = t[self] + 1]
                              /\ pc' = [pc EXCEPT ![self] = "wlF"]
                           \/ /\ FailEfd
                              /\ pc' = [pc EXCEPT ![self] = "wlE"]
                              /\ UNCHANGED <<efd, t>>
                   ELSE /\ t' = [t EXCEPT ![self] = 1]
                        /\ pc' = [pc EXCEPT ![self] = "wl1"]
                        /\ efd' = efd
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, thr, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, startErr, wi, batch, 
                             reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

wl1(self) == /\ pc[self] = "wl1"
             /\ IF t[self] <= Len(WSeq(ifc[self]))
                   THEN /\ IF ~FixLoop
                              THEN /\ \/ /\ efd' = [efd EXCEPT ![WSeq(ifc[self])[t[self]]] = "open"]
                                         /\ pc' = [pc EXCEPT ![self] = "wl2"]
                                      \/ /\ FailEfd
                                         /\ pc' = [pc EXCEPT ![self] = "wlE"]
                                         /\ efd' = efd
                              ELSE /\ pc' = [pc EXCEPT ![self] = "wl2"]
                                   /\ efd' = efd
                   ELSE /\ pc' = [pc EXCEPT ![self] = "wl3"]
                        /\ efd' = efd
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, thr, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, t, startErr, wi, 
                             batch, reap, cur, rq, retry, auth, due, ck, cn, 
                             cgot, ci >>

wl2(self) == /\ pc[self] = "wl2"
             /\ \/ /\ ~shut[WSeq(ifc[self])[t[self]]]
                   /\ thr' = [thr EXCEPT ![WSeq(ifc[self])[t[self]]] = "sched"]
                   /\ t' = [t EXCEPT ![self] = t[self] + 1]
                   /\ pc' = [pc EXCEPT ![self] = "wl1"]
                   /\ UNCHANGED <<serverExit, startErr>>
                \/ /\ FailStart
                   /\ IF FixLoop
                         THEN /\ serverExit' = 1
                              /\ startErr' = [startErr EXCEPT ![self] = TRUE]
                              /\ pc' = [pc EXCEPT ![self] = "wl3"]
                              /\ t' = t
                         ELSE /\ t' = [t EXCEPT ![self] = t[self] + 1]
                              /\ pc' = [pc EXCEPT ![self] = "wl1"]
                              /\ UNCHANGED << serverExit, startErr >>
                   /\ thr' = thr
             /\ UNCHANGED << initState, unpStarted, unpDone, dropped, fin, 
                             exited, lsock, backlog, frame, targs, efd, shut, 
                             joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                             inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                             unpFailed, spins, viol, asked, bad, taken, 
                             answered, undeliv, applied, sent, reaped, 
                             rejected, stack, ifc, wi, batch, reap, cur, rq, 
                             retry, auth, due, ck, cn, cgot, ci >>

wl3(self) == /\ pc[self] = "wl3"
             /\ serverExit # 0
             /\ efd' = [w \in Workers |->
                        IF w \in Mine(ifc[self]) /\ efd[w] = "open" THEN "set" ELSE efd[w]]
             /\ pc' = [pc EXCEPT ![self] = "wl4"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, thr, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, t, startErr, wi, 
                             batch, reap, cur, rq, retry, auth, due, ck, cn, 
                             cgot, ci >>

wl4(self) == /\ pc[self] = "wl4"
             /\ \A w \in Mine(ifc[self]) : thr[w] \notin {"sched", "run"}
             /\ efd' = [w \in Workers |-> IF w \in Mine(ifc[self]) THEN "closed" ELSE efd[w]]
             /\ targs' = [targs EXCEPT ![ifc[self]] = "freed"]
             /\ rv' = [rv EXCEPT ![self] = IF startErr[self]
                                              \/ (FixWorkerExit /\ \E w \in Mine(ifc[self]) : wfailed[w])
                                           THEN -1 ELSE 0]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ t' = [t EXCEPT ![self] = Head(stack[self]).t]
             /\ startErr' = [startErr EXCEPT ![self] = Head(stack[self]).startErr]
             /\ ifc' = [ifc EXCEPT ![self] = Head(stack[self]).ifc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, thr, 
                             shut, joinMe, num, owner, srv, fresh, peerRoot, 
                             cclosed, inq, rdshut, outq, rootNow, wfailed, 
                             monDone, unpFailed, spins, viol, asked, bad, 
                             taken, answered, undeliv, applied, sent, reaped, 
                             rejected, wi, batch, reap, cur, rq, retry, auth, 
                             due, ck, cn, cgot, ci >>

wlE(self) == /\ pc[self] = "wlE"
             /\ targs' = [targs EXCEPT ![ifc[self]] = "freed"]
             /\ rv' = [rv EXCEPT ![self] = -1]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ t' = [t EXCEPT ![self] = Head(stack[self]).t]
             /\ startErr' = [startErr EXCEPT ![self] = Head(stack[self]).startErr]
             /\ ifc' = [ifc EXCEPT ![self] = Head(stack[self]).ifc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, efd, 
                             thr, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, wi, batch, reap, cur, rq, retry, 
                             auth, due, ck, cn, cgot, ci >>

workerloop(self) == wl0(self) \/ wlF(self) \/ wl1(self) \/ wl2(self)
                       \/ wl3(self) \/ wl4(self) \/ wlE(self)

ma0 == /\ pc["main"] = "ma0"
       /\ IF serverExit # 0
             THEN /\ pc' = [pc EXCEPT !["main"] = "maF"]
             ELSE /\ pc' = [pc EXCEPT !["main"] = "ma1"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

ma1 == /\ pc["main"] = "ma1"
       /\ initState = "privdone" \/ serverExit # 0
       /\ frame' = [frame EXCEPT !["priv"] = "live"]
       /\ lsock' = [lsock EXCEPT !["priv"] = "listen"]
       /\ pc' = [pc EXCEPT !["main"] = "ma2"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, backlog, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

ma2 == /\ pc["main"] = "ma2"
       /\ unpStarted' = TRUE
       /\ IF serverExit # 0
             THEN /\ pc' = [pc EXCEPT !["main"] = "maS"]
             ELSE /\ pc' = [pc EXCEPT !["main"] = "ma3"]
       /\ UNCHANGED << initState, serverExit, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

ma3 == /\ pc["main"] = "ma3"
       /\ initState \in {"unpdone", "unpfail"} \/ serverExit # 0
       /\ IF initState = "unpfail" \/ serverExit # 0
             THEN /\ pc' = [pc EXCEPT !["main"] = "maS"]
             ELSE /\ pc' = [pc EXCEPT !["main"] = "ma4"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

ma4 == /\ pc["main"] = "ma4"
       /\ \/ /\ dropped' = TRUE
             /\ pc' = [pc EXCEPT !["main"] = "ma5"]
          \/ /\ FailDrop
             /\ pc' = [pc EXCEPT !["main"] = "maS"]
             /\ UNCHANGED dropped
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

ma5 == /\ pc["main"] = "ma5"
       /\ initState' = "dropped"
       /\ /\ ifc' = [ifc EXCEPT !["main"] = "priv"]
          /\ stack' = [stack EXCEPT !["main"] = << [ procedure |->  "workerloop",
                                                     pc        |->  "ma6",
                                                     t         |->  t["main"],
                                                     startErr  |->  startErr["main"],
                                                     ifc       |->  ifc["main"] ] >>
                                                 \o stack["main"]]
       /\ t' = [t EXCEPT !["main"] = 1]
       /\ startErr' = [startErr EXCEPT !["main"] = FALSE]
       /\ pc' = [pc EXCEPT !["main"] = "wl0"]
       /\ UNCHANGED << serverExit, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, wi, batch, reap, cur, rq, retry, 
                       auth, due, ck, cn, cgot, ci >>

ma6 == /\ pc["main"] = "ma6"
       /\ IF rv["main"] # 0
             THEN /\ pc' = [pc EXCEPT !["main"] = "maS"]
             ELSE /\ pc' = [pc EXCEPT !["main"] = "maR"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

maS == /\ pc["main"] = "maS"
       /\ IF lsock["priv"] = "listen"
             THEN /\ lsock' = [lsock EXCEPT !["priv"] = "closed"]
                  /\ srv' = [k \in ConnIds |->
                             IF \E j \in DOMAIN backlog["priv"] : backlog["priv"][j] = k
                             THEN "refused" ELSE srv[k]]
                  /\ backlog' = [backlog EXCEPT !["priv"] = <<>>]
             ELSE /\ TRUE
                  /\ UNCHANGED << lsock, backlog, srv >>
       /\ pc' = [pc EXCEPT !["main"] = "maR"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, frame, targs, efd, thr, shut, joinMe, num, 
                       owner, fresh, peerRoot, cclosed, inq, rdshut, outq, 
                       rootNow, rv, wfailed, monDone, unpFailed, spins, viol, 
                       asked, bad, taken, answered, undeliv, applied, sent, 
                       reaped, rejected, stack, ifc, t, startErr, wi, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

maR == /\ pc["main"] = "maR"
       /\ frame' = [frame EXCEPT !["priv"] = "dead"]
       /\ rv' = [rv EXCEPT !["main"] = 0]
       /\ pc' = [pc EXCEPT !["main"] = "maF"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, targs, efd, thr, shut, 
                       joinMe, num, owner, srv, fresh, peerRoot, cclosed, inq, 
                       rdshut, outq, rootNow, wfailed, monDone, unpFailed, 
                       spins, viol, asked, bad, taken, answered, undeliv, 
                       applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

maF == /\ pc["main"] = "maF"
       /\ serverExit' = 1
       /\ pc' = [pc EXCEPT !["main"] = "maW"]
       /\ UNCHANGED << initState, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

maW == /\ pc["main"] = "maW"
       /\ IF FixJoin
             THEN /\ ~unpStarted \/ unpDone
             ELSE /\ TRUE
       /\ pc' = [pc EXCEPT !["main"] = "maA"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

maA == /\ pc["main"] = "maA"
       /\ IF wi <= Len(WAll)
             THEN /\ thr[WAll[wi]] # "run"
                  /\ joinMe' = [joinMe EXCEPT ![WAll[wi]] = thr[WAll[wi]] # "none"]
                  /\ shut' = [shut EXCEPT ![WAll[wi]] = TRUE]
                  /\ wi' = wi + 1
                  /\ pc' = [pc EXCEPT !["main"] = "maA"]
             ELSE /\ wi' = 1
                  /\ pc' = [pc EXCEPT !["main"] = "maJ"]
                  /\ UNCHANGED << shut, joinMe >>
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

maJ == /\ pc["main"] = "maJ"
       /\ IF wi <= Len(WAll)
             THEN /\ IF joinMe[WAll[wi]]
                        THEN /\ thr[WAll[wi]] = "exit"
                             /\ thr' = [thr EXCEPT ![WAll[wi]] = "none"]
                             /\ joinMe' = [joinMe EXCEPT ![WAll[wi]] = FALSE]
                        ELSE /\ TRUE
                             /\ UNCHANGED << thr, joinMe >>
                  /\ wi' = wi + 1
                  /\ pc' = [pc EXCEPT !["main"] = "maJ"]
                  /\ shut' = shut
             ELSE /\ shut' = [w \in Workers |-> FALSE]
                  /\ wi' = 1
                  /\ pc' = [pc EXCEPT !["main"] = "maB"]
                  /\ UNCHANGED << thr, joinMe >>
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, num, 
                       owner, srv, fresh, peerRoot, cclosed, inq, rdshut, outq, 
                       rootNow, rv, wfailed, monDone, unpFailed, spins, viol, 
                       asked, bad, taken, answered, undeliv, applied, sent, 
                       reaped, rejected, stack, ifc, t, startErr, batch, reap, 
                       cur, rq, retry, auth, due, ck, cn, cgot, ci >>

maB == /\ pc["main"] = "maB"
       /\ IF wi <= Len(WAll)
             THEN /\ thr[WAll[wi]] # "run"
                  /\ joinMe' = [joinMe EXCEPT ![WAll[wi]] = thr[WAll[wi]] # "none"]
                  /\ shut' = [shut EXCEPT ![WAll[wi]] = TRUE]
                  /\ wi' = wi + 1
                  /\ pc' = [pc EXCEPT !["main"] = "maB"]
             ELSE /\ wi' = 1
                  /\ pc' = [pc EXCEPT !["main"] = "maU"]
                  /\ UNCHANGED << shut, joinMe >>
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

maU == /\ pc["main"] = "maU"
       /\ ~unpStarted \/ unpDone
       /\ pc' = [pc EXCEPT !["main"] = "maK"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

maK == /\ pc["main"] = "maK"
       /\ IF wi <= Len(WAll)
             THEN /\ IF joinMe[WAll[wi]]
                        THEN /\ thr[WAll[wi]] = "exit"
                             /\ thr' = [thr EXCEPT ![WAll[wi]] = "none"]
                             /\ joinMe' = [joinMe EXCEPT ![WAll[wi]] = FALSE]
                        ELSE /\ TRUE
                             /\ UNCHANGED << thr, joinMe >>
                  /\ wi' = wi + 1
                  /\ pc' = [pc EXCEPT !["main"] = "maK"]
                  /\ shut' = shut
             ELSE /\ shut' = [w \in Workers |-> FALSE]
                  /\ wi' = 1
                  /\ pc' = [pc EXCEPT !["main"] = "maZ"]
                  /\ UNCHANGED << thr, joinMe >>
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, num, 
                       owner, srv, fresh, peerRoot, cclosed, inq, rdshut, outq, 
                       rootNow, rv, wfailed, monDone, unpFailed, spins, viol, 
                       asked, bad, taken, answered, undeliv, applied, sent, 
                       reaped, rejected, stack, ifc, t, startErr, batch, reap, 
                       cur, rq, retry, auth, due, ck, cn, cgot, ci >>

maZ == /\ pc["main"] = "maZ"
       /\ fin' = TRUE
       /\ pc' = [pc EXCEPT !["main"] = "maX"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       exited, lsock, backlog, frame, targs, efd, thr, shut, 
                       joinMe, num, owner, srv, fresh, peerRoot, cclosed, inq, 
                       rdshut, outq, rootNow, rv, wfailed, monDone, unpFailed, 
                       spins, viol, asked, bad, taken, answered, undeliv, 
                       applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

maX == /\ pc["main"] = "maX"
       /\ exited' = TRUE
       /\ pc' = [pc EXCEPT !["main"] = "Done"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, lsock, backlog, frame, targs, efd, thr, shut, 
                       joinMe, num, owner, srv, fresh, peerRoot, cclosed, inq, 
                       rdshut, outq, rootNow, rv, wfailed, monDone, unpFailed, 
                       spins, viol, asked, bad, taken, answered, undeliv, 
                       applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

pmain == ma0 \/ ma1 \/ ma2 \/ ma3 \/ ma4 \/ ma5 \/ ma6 \/ maS \/ maR \/ maF
            \/ maW \/ maA \/ maJ \/ maB \/ maU \/ maK \/ maZ \/ maX

un0 == /\ pc["unp"] = "un0"
       /\ unpStarted \/ exited
       /\ IF ~unpStarted
             THEN /\ pc' = [pc EXCEPT !["unp"] = "unZ"]
             ELSE /\ pc' = [pc EXCEPT !["unp"] = "un4"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

un4 == /\ pc["unp"] = "un4"
       /\ frame' = [frame EXCEPT !["unpriv"] = "live"]
       /\ \/ /\ lsock' = [lsock EXCEPT !["unpriv"] = "listen"]
             /\ pc' = [pc EXCEPT !["unp"] = "un1"]
          \/ /\ FailUnpriv
             /\ pc' = [pc EXCEPT !["unp"] = "unF"]
             /\ lsock' = lsock
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, backlog, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

un1 == /\ pc["unp"] = "un1"
       /\ initState' = "unpdone"
       /\ IF serverExit # 0
             THEN /\ pc' = [pc EXCEPT !["unp"] = "unS"]
             ELSE /\ pc' = [pc EXCEPT !["unp"] = "un2"]
       /\ UNCHANGED << serverExit, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

un2 == /\ pc["unp"] = "un2"
       /\ initState = "dropped" \/ serverExit # 0
       /\ IF serverExit # 0
             THEN /\ pc' = [pc EXCEPT !["unp"] = "unS"]
                  /\ UNCHANGED << stack, ifc, t, startErr >>
             ELSE /\ /\ ifc' = [ifc EXCEPT !["unp"] = "unpriv"]
                     /\ stack' = [stack EXCEPT !["unp"] = << [ procedure |->  "workerloop",
                                                               pc        |->  "un3",
                                                               t         |->  t["unp"],
                                                               startErr  |->  startErr["unp"],
                                                               ifc       |->  ifc["unp"] ] >>
                                                           \o stack["unp"]]
                  /\ t' = [t EXCEPT !["unp"] = 1]
                  /\ startErr' = [startErr EXCEPT !["unp"] = FALSE]
                  /\ pc' = [pc EXCEPT !["unp"] = "wl0"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, wi, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

un3 == /\ pc["unp"] = "un3"
       /\ IF rv["unp"] # 0
             THEN /\ unpFailed' = TRUE
                  /\ IF FixLoop
                        THEN /\ serverExit' = 1
                        ELSE /\ TRUE
                             /\ UNCHANGED serverExit
                  /\ pc' = [pc EXCEPT !["unp"] = "unS"]
             ELSE /\ IF FixLoop
                        THEN /\ pc' = [pc EXCEPT !["unp"] = "unS"]
                        ELSE /\ pc' = [pc EXCEPT !["unp"] = "unR"]
                  /\ UNCHANGED << serverExit, unpFailed >>
       /\ UNCHANGED << initState, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, spins, viol, asked, 
                       bad, taken, answered, undeliv, applied, sent, reaped, 
                       rejected, stack, ifc, t, startErr, wi, batch, reap, cur, 
                       rq, retry, auth, due, ck, cn, cgot, ci >>

unF == /\ pc["unp"] = "unF"
       /\ IF initState \in {"uninit", "privdone"}
             THEN /\ initState' = "unpfail"
             ELSE /\ TRUE
                  /\ UNCHANGED initState
       /\ pc' = [pc EXCEPT !["unp"] = "unR"]
       /\ UNCHANGED << serverExit, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

unS == /\ pc["unp"] = "unS"
       /\ IF lsock["unpriv"] = "listen"
             THEN /\ lsock' = [lsock EXCEPT !["unpriv"] = "closed"]
                  /\ srv' = [k \in ConnIds |->
                             IF \E j \in DOMAIN backlog["unpriv"] : backlog["unpriv"][j] = k
                             THEN "refused" ELSE srv[k]]
                  /\ backlog' = [backlog EXCEPT !["unpriv"] = <<>>]
             ELSE /\ TRUE
                  /\ UNCHANGED << lsock, backlog, srv >>
       /\ pc' = [pc EXCEPT !["unp"] = "unR"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, frame, targs, efd, thr, shut, joinMe, num, 
                       owner, fresh, peerRoot, cclosed, inq, rdshut, outq, 
                       rootNow, rv, wfailed, monDone, unpFailed, spins, viol, 
                       asked, bad, taken, answered, undeliv, applied, sent, 
                       reaped, rejected, stack, ifc, t, startErr, wi, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

unR == /\ pc["unp"] = "unR"
       /\ frame' = [frame EXCEPT !["unpriv"] = "dead"]
       /\ rv' = [rv EXCEPT !["unp"] = 0]
       /\ unpDone' = TRUE
       /\ pc' = [pc EXCEPT !["unp"] = "unZ"]
       /\ UNCHANGED << initState, serverExit, unpStarted, dropped, fin, exited, 
                       lsock, backlog, targs, efd, thr, shut, joinMe, num, 
                       owner, srv, fresh, peerRoot, cclosed, inq, rdshut, outq, 
                       rootNow, wfailed, monDone, unpFailed, spins, viol, 
                       asked, bad, taken, answered, undeliv, applied, sent, 
                       reaped, rejected, stack, ifc, t, startErr, wi, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

unZ == /\ pc["unp"] = "unZ"
       /\ TRUE
       /\ pc' = [pc EXCEPT !["unp"] = "Done"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

punp == un0 \/ un4 \/ un1 \/ un2 \/ un3 \/ unF \/ unS \/ unR \/ unZ

mo1 == /\ pc["mon"] = "mo1"
       /\ IF initState # "uninit"
             THEN /\ pc' = [pc EXCEPT !["mon"] = "moZ"]
             ELSE /\ pc' = [pc EXCEPT !["mon"] = "mo2"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

mo2 == /\ pc["mon"] = "mo2"
       /\ initState' = "privdone"
       /\ monDone' = TRUE
       /\ pc' = [pc EXCEPT !["mon"] = "moZ"]
       /\ UNCHANGED << serverExit, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, unpFailed, spins, viol, 
                       asked, bad, taken, answered, undeliv, applied, sent, 
                       reaped, rejected, stack, ifc, t, startErr, wi, batch, 
                       reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

moZ == /\ pc["mon"] = "moZ"
       /\ TRUE
       /\ pc' = [pc EXCEPT !["mon"] = "Done"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

pmon == mo1 \/ mo2 \/ moZ

en0 == /\ pc["env"] = "en0"
       /\ IF Signal
             THEN /\ serverExit' = 1
             ELSE /\ TRUE
                  /\ UNCHANGED serverExit
       /\ pc' = [pc EXCEPT !["env"] = "enI"]
       /\ UNCHANGED << initState, unpStarted, unpDone, dropped, fin, exited, 
                       lsock, backlog, frame, targs, efd, thr, shut, joinMe, 
                       num, owner, srv, fresh, peerRoot, cclosed, inq, rdshut, 
                       outq, rootNow, rv, wfailed, monDone, unpFailed, spins, 
                       viol, asked, bad, taken, answered, undeliv, applied, 
                       sent, reaped, rejected, stack, ifc, t, startErr, wi, 
                       batch, reap, cur, rq, retry, auth, due, ck, cn, cgot, 
                       ci >>

enI == /\ pc["env"] = "enI"
       /\ IF ~Finished
             THEN /\ Idling
                  /\ TRUE
                  /\ pc' = [pc EXCEPT !["env"] = "enI"]
             ELSE /\ pc' = [pc EXCEPT !["env"] = "Done"]
       /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, dropped, 
                       fin, exited, lsock, backlog, frame, targs, efd, thr, 
                       shut, joinMe, num, owner, srv, fresh, peerRoot, cclosed, 
                       inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                       unpFailed, spins, viol, asked, bad, taken, answered, 
                       undeliv, applied, sent, reaped, rejected, stack, ifc, t, 
                       startErr, wi, batch, reap, cur, rq, retry, auth, due, 
                       ck, cn, cgot, ci >>

penv == en0 \/ enI

hs0(self) == /\ pc[self] = "hs0"
             /\ thr[self] = "sched" \/ exited
             /\ IF thr[self] # "sched"
                   THEN /\ pc' = [pc EXCEPT ![self] = "hsZ"]
                        /\ thr' = thr
                   ELSE /\ IF shut[self]
                              THEN /\ thr' = [thr EXCEPT ![self] = "exit"]
                                   /\ pc' = [pc EXCEPT ![self] = "hsZ"]
                              ELSE /\ thr' = [thr EXCEPT ![self] = "run"]
                                   /\ pc' = [pc EXCEPT ![self] = "hs1"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, t, startErr, wi, 
                             batch, reap, cur, rq, retry, auth, due, ck, cn, 
                             cgot, ci >>

hs1(self) == /\ pc[self] = "hs1"
             /\ viol' = (viol \cup UAF(ArgsGone(self) \/ ProtoGone(self)))
             /\ IF lsock[Sock(self)] # "listen"
                   THEN /\ pc' = [pc EXCEPT ![self] = "hsF"]
                   ELSE /\ \/ /\ TRUE
                              /\ pc' = [pc EXCEPT ![self] = "hsL"]
                           \/ /\ FailEpoll
                              /\ pc' = [pc EXCEPT ![self] = "hsF"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, inq, rdshut, outq, 
                             rootNow, rv, wfailed, monDone, unpFailed, spins, 
                             asked, bad, taken, answered, undeliv, applied, 
                             sent, reaped, rejected, stack, ifc, t, startErr, 
                             wi, batch, reap, cur, rq, retry, auth, due, ck, 
                             cn, cgot, ci >>

hsL(self) == /\ pc[self] = "hsL"
             /\ IF serverExit = 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "hsW"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hsX"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, inq, rdshut, outq, 
                             rootNow, rv, wfailed, monDone, unpFailed, spins, 
                             viol, asked, bad, taken, answered, undeliv, 
                             applied, sent, reaped, rejected, stack, ifc, t, 
                             startErr, wi, batch, reap, cur, rq, retry, auth, 
                             due, ck, cn, cgot, ci >>

hsW(self) == /\ pc[self] = "hsW"
             /\ LET rdy == Ready(self, (num[self] < Cap \/ ~CapDisarm) /\ ~retry[self]) IN
                  \/ /\ rdy # {}
                     /\ batch' = [batch EXCEPT ![self] = rdy]
                     /\ pc' = [pc EXCEPT ![self] = "hsE"]
                     /\ UNCHANGED <<spins, retry>>
                  \/ /\ FailEpoll
                     /\ pc' = [pc EXCEPT ![self] = "hsF"]
                     /\ UNCHANGED <<spins, batch, retry>>
                  \/ /\ Idle /\ (Owned(self) # {} \/ serverExit # 0)
                     /\ batch' = [batch EXCEPT ![self] = rdy \cup {Timer}]
                     /\ pc' = [pc EXCEPT ![self] = "hsE"]
                     /\ UNCHANGED <<spins, retry>>
                  \/ /\ retry[self]
                     /\ retry' = [retry EXCEPT ![self] = FALSE]
                     /\ spins' = [spins EXCEPT ![self] = 0]
                     /\ batch' = [batch EXCEPT ![self] = rdy]
                     /\ pc' = [pc EXCEPT ![self] = "hsE"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, inq, rdshut, outq, 
                             rootNow, rv, wfailed, monDone, unpFailed, viol, 
                             asked, bad, taken, answered, undeliv, applied, 
                             sent, reaped, rejected, stack, ifc, t, startErr, 
                             wi, reap, cur, rq, auth, due, ck, cn, cgot, ci >>

hsE(self) == /\ pc[self] = "hsE"
             /\ IF batch[self] # {}
                   THEN /\ \E x \in batch[self]:
                             IF x = Timer
                                THEN /\ reap' = [reap EXCEPT ![self] = TRUE]
                                     /\ batch' = [batch EXCEPT ![self] = batch[self] \ {x}]
                                     /\ UNCHANGED << backlog, efd, num, owner, 
                                                     srv, fresh, inq, wfailed, 
                                                     spins, viol, taken, 
                                                     rejected, cur, rq, retry >>
                                ELSE /\ IF x = Efd
                                           THEN /\ viol' = (viol \cup UAF(ArgsGone(self)))
                                                /\ efd' = [efd EXCEPT ![self] = "open"]
                                                /\ batch' = [batch EXCEPT ![self] = {}]
                                                /\ UNCHANGED << backlog, num, 
                                                                owner, srv, 
                                                                fresh, inq, 
                                                                wfailed, spins, 
                                                                taken, 
                                                                rejected, cur, 
                                                                rq, retry >>
                                           ELSE /\ IF x = Listen
                                                      THEN /\ viol' = (viol \cup UAF(ProtoGone(self)))
                                                           /\ IF num[self] >= Cap
                                                                 THEN /\ spins' = [spins EXCEPT ![self] = IF spins[self] < 2
                                                                                                          THEN spins[self] + 1 ELSE 2]
                                                                      /\ UNCHANGED << backlog, 
                                                                                      num, 
                                                                                      owner, 
                                                                                      srv, 
                                                                                      fresh, 
                                                                                      inq, 
                                                                                      wfailed, 
                                                                                      rejected, 
                                                                                      retry >>
                                                                 ELSE /\ IF backlog[Sock(self)] # <<>>
                                                                            THEN /\ \/ /\ LET kk == Head(backlog[Sock(self)]) IN
                                                                                            /\ backlog' = [backlog EXCEPT ![Sock(self)] = Tail(backlog[Sock(self)])]
                                                                                            /\ owner' = [owner EXCEPT ![kk] = self]
                                                                                            /\ srv' = [srv EXCEPT ![kk] = "open"]
                                                                                            /\ fresh' = [fresh EXCEPT ![kk] = TRUE]
                                                                                       /\ num' = [num EXCEPT ![self] = num[self] + 1]
                                                                                       /\ spins' = [spins EXCEPT ![self] = 0]
                                                                                       /\ UNCHANGED <<inq, wfailed, rejected, retry>>
                                                                                    \/ /\ FdFull
                                                                                       /\ spins' = [spins EXCEPT ![self] = IF spins[self] < 2
                                                                                                                           THEN spins[self] + 1 ELSE 2]
                                                                                       /\ IF FixSpin
                                                                                             THEN /\ retry' = [retry EXCEPT ![self] = TRUE]
                                                                                             ELSE /\ TRUE
                                                                                                  /\ retry' = retry
                                                                                       /\ UNCHANGED <<backlog, num, owner, srv, fresh, inq, wfailed, rejected>>
                                                                                    \/ /\ FdFull \/ FailEpoll
                                                                                       /\ LET kk == Head(backlog[Sock(self)]) IN
                                                                                            /\ backlog' = [backlog EXCEPT ![Sock(self)] = Tail(backlog[Sock(self)])]
                                                                                            /\ srv' = [srv EXCEPT ![kk] = "closed"]
                                                                                            /\ inq' = [inq EXCEPT ![kk] = <<>>]
                                                                                            /\ rejected' = (rejected \cup {kk})
                                                                                       /\ \/ /\ FdFull
                                                                                             /\ UNCHANGED wfailed
                                                                                          \/ /\ FailEpoll
                                                                                             /\ wfailed' = [wfailed EXCEPT ![self] = TRUE]
                                                                                       /\ UNCHANGED <<num, owner, fresh, spins, retry>>
                                                                            ELSE /\ TRUE
                                                                                 /\ UNCHANGED << backlog, 
                                                                                                 num, 
                                                                                                 owner, 
                                                                                                 srv, 
                                                                                                 fresh, 
                                                                                                 inq, 
                                                                                                 wfailed, 
                                                                                                 spins, 
                                                                                                 rejected, 
                                                                                                 retry >>
                                                           /\ batch' = [batch EXCEPT ![self] = batch[self] \ {x}]
                                                           /\ UNCHANGED << taken, 
                                                                           cur, 
                                                                           rq >>
                                                      ELSE /\ IF cclosed[x] \/ inq[x] = <<>>
                                                                 THEN /\ viol' = (viol \cup UAF(owner[x] # self))
                                                                      /\ owner' = [owner EXCEPT ![x] = NoW]
                                                                      /\ srv' = [srv EXCEPT ![x] = "closed"]
                                                                      /\ inq' = [inq EXCEPT ![x] = <<>>]
                                                                      /\ num' = [num EXCEPT ![self] = num[self] - 1]
                                                                      /\ retry' = [retry EXCEPT ![self] = FALSE]
                                                                      /\ spins' = [spins EXCEPT ![self] = 0]
                                                                      /\ batch' = [batch EXCEPT ![self] = batch[self] \ {x}]
                                                                      /\ UNCHANGED << fresh, 
                                                                                      taken, 
                                                                                      cur, 
                                                                                      rq >>
                                                                 ELSE /\ viol' = (viol \cup UAF(owner[x] # self))
                                                                      /\ rq' = [rq EXCEPT ![self] = Head(inq[x])]
                                                                      /\ taken' = (taken \cup {<<x, Head(inq[x])>>})
                                                                      /\ inq' = [inq EXCEPT ![x] = Tail(inq[x])]
                                                                      /\ fresh' = [fresh EXCEPT ![x] = TRUE]
                                                                      /\ cur' = [cur EXCEPT ![self] = x]
                                                                      /\ batch' = [batch EXCEPT ![self] = batch[self] \ {x}]
                                                                      /\ UNCHANGED << num, 
                                                                                      owner, 
                                                                                      srv, 
                                                                                      spins, 
                                                                                      retry >>
                                                           /\ UNCHANGED << backlog, 
                                                                           wfailed, 
                                                                           rejected >>
                                                /\ efd' = efd
                                     /\ reap' = reap
                        /\ IF wfailed'[self]
                              THEN /\ pc' = [pc EXCEPT ![self] = "hsF"]
                              ELSE /\ IF cur'[self] # NoConn
                                         THEN /\ pc' = [pc EXCEPT ![self] = "hsP"]
                                         ELSE /\ pc' = [pc EXCEPT ![self] = "hsE"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hsC"]
                        /\ UNCHANGED << backlog, efd, num, owner, srv, fresh, 
                                        inq, wfailed, spins, viol, taken, 
                                        rejected, batch, reap, cur, rq, retry >>
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, frame, targs, thr, 
                             shut, joinMe, peerRoot, cclosed, rdshut, outq, 
                             rootNow, rv, monDone, unpFailed, asked, bad, 
                             answered, undeliv, applied, sent, reaped, stack, 
                             ifc, t, startErr, wi, auth, due, ck, cn, cgot, ci >>

hsP(self) == /\ pc[self] = "hsP"
             /\ viol' =     viol
                        \cup UAF(ProtoGone(self) \/ owner[cur[self]] # self)
                        \cup (IF ~dropped THEN {"ServedPrivileged"} ELSE {})
                        \cup (IF fin THEN {"ServedAfterFini"} ELSE {})
             /\ IF <<cur[self], rq[self]>> \in bad
                   THEN /\ owner' = [owner EXCEPT ![cur[self]] = NoW]
                        /\ srv' = [srv EXCEPT ![cur[self]] = "closed"]
                        /\ inq' = [inq EXCEPT ![cur[self]] = <<>>]
                        /\ num' = [num EXCEPT ![self] = num[self] - 1]
                        /\ retry' = [retry EXCEPT ![self] = FALSE]
                        /\ spins' = [spins EXCEPT ![self] = 0]
                        /\ cur' = [cur EXCEPT ![self] = NoConn]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "hsE"]
                        /\ auth' = auth
                   ELSE /\ auth' = [auth EXCEPT ![self] = Sock(self) = "priv"
                                                          /\ (peerRoot[cur[self]] \/ Mutant = "NoPrivCheck")]
                        /\ pc' = [pc EXCEPT ![self] = "hsT"]
                        /\ UNCHANGED << num, owner, srv, inq, spins, cur, rq, 
                                        retry >>
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, fresh, peerRoot, 
                             cclosed, rdshut, outq, rootNow, rv, wfailed, 
                             monDone, unpFailed, asked, bad, taken, answered, 
                             undeliv, applied, sent, reaped, rejected, stack, 
                             ifc, t, startErr, wi, batch, reap, due, ck, cn, 
                             cgot, ci >>

hsT(self) == /\ pc[self] = "hsT"
             /\ IF auth[self]
                   THEN /\ applied' = (applied \cup {<<cur[self], rq[self]>>})
                        /\ viol' = (viol \cup (IF ~rootNow[Client(cur[self])]
                                               THEN {"PrivAtCall"} ELSE {}))
                   ELSE /\ TRUE
                        /\ UNCHANGED << viol, applied >>
             /\ auth' = [auth EXCEPT ![self] = FALSE]
             /\ \/ /\ cclosed[cur[self]] \/ Len(outq[cur[self]]) < SndBuf
                   /\ IF cclosed[cur[self]]
                         THEN /\ undeliv' = (undeliv \cup {<<cur[self], rq[self]>>})
                              /\ owner' = [owner EXCEPT ![cur[self]] = NoW]
                              /\ srv' = [srv EXCEPT ![cur[self]] = "closed"]
                              /\ inq' = [inq EXCEPT ![cur[self]] = <<>>]
                              /\ num' = [num EXCEPT ![self] = num[self] - 1]
                              /\ retry' = [retry EXCEPT ![self] = FALSE]
                              /\ spins' = [spins EXCEPT ![self] = 0]
                              /\ UNCHANGED << outq, answered, sent >>
                         ELSE /\ IF Mutant = "NoReply"
                                    THEN /\ owner' = [owner EXCEPT ![cur[self]] = NoW]
                                         /\ srv' = [srv EXCEPT ![cur[self]] = "closed"]
                                         /\ inq' = [inq EXCEPT ![cur[self]] = <<>>]
                                         /\ num' = [num EXCEPT ![self] = num[self] - 1]
                                         /\ retry' = [retry EXCEPT ![self] = FALSE]
                                         /\ spins' = [spins EXCEPT ![self] = 0]
                                         /\ UNCHANGED << outq, answered, sent >>
                                    ELSE /\ outq' = [outq EXCEPT ![cur[self]] = Append(outq[cur[self]], rq[self])]
                                         /\ answered' = (answered \cup {<<cur[self], rq[self]>>})
                                         /\ sent' = [sent EXCEPT ![cur[self]] = sent[cur[self]] + 1]
                                         /\ UNCHANGED << num, owner, srv, inq, 
                                                         spins, retry >>
                              /\ UNCHANGED undeliv
                \/ /\ ~cclosed[cur[self]] /\ Len(outq[cur[self]]) >= SndBuf
                   /\ undeliv' = (undeliv \cup {<<cur[self], rq[self]>>})
                   /\ IF FixLostReply
                         THEN /\ owner' = [owner EXCEPT ![cur[self]] = NoW]
                              /\ srv' = [srv EXCEPT ![cur[self]] = "closed"]
                              /\ inq' = [inq EXCEPT ![cur[self]] = <<>>]
                              /\ num' = [num EXCEPT ![self] = num[self] - 1]
                              /\ retry' = [retry EXCEPT ![self] = FALSE]
                              /\ spins' = [spins EXCEPT ![self] = 0]
                         ELSE /\ TRUE
                              /\ UNCHANGED << num, owner, srv, inq, spins, 
                                              retry >>
                   /\ UNCHANGED <<outq, answered, sent>>
             /\ IF rdshut[cur[self]] /\ srv'[cur[self]] = "open"
                   THEN /\ pc' = [pc EXCEPT ![self] = "hsD"]
                        /\ UNCHANGED << cur, rq >>
                   ELSE /\ cur' = [cur EXCEPT ![self] = NoConn]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "hsE"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, fresh, peerRoot, 
                             cclosed, rdshut, rootNow, rv, wfailed, monDone, 
                             unpFailed, asked, bad, taken, reaped, rejected, 
                             stack, ifc, t, startErr, wi, batch, reap, due, ck, 
                             cn, cgot, ci >>

hsC(self) == /\ pc[self] = "hsC"
             /\ IF reap[self] /\ FixIdle
                   THEN /\ due' = [due EXCEPT ![self] = {k \in Owned(self) : ~fresh[k]}]
                        /\ fresh' = [k \in ConnIds |->
                                     IF k \in Owned(self) THEN FALSE ELSE fresh[k]]
                        /\ UNCHANGED << num, owner, srv, inq, spins, reaped, 
                                        retry >>
                   ELSE /\ IF reap[self]
                              THEN /\ LET idle == {k \in Owned(self) : ~fresh[k]} IN
                                        /\ owner' = [k \in ConnIds |->
                                                     IF k \in idle THEN NoW ELSE owner[k]]
                                        /\ srv' = [k \in ConnIds |->
                                                   IF k \in idle THEN "closed" ELSE srv[k]]
                                        /\ inq' = [k \in ConnIds |->
                                                   IF k \in idle THEN <<>> ELSE inq[k]]
                                        /\ fresh' = [k \in ConnIds |->
                                                     IF k \in Owned(self) THEN FALSE ELSE fresh[k]]
                                        /\ num' = [num EXCEPT ![self] = num[self] - Cardinality(idle)]
                                        /\ reaped' = (reaped \cup idle)
                                        /\ IF idle # {}
                                              THEN /\ retry' = [retry EXCEPT ![self] = FALSE]
                                                   /\ spins' = [spins EXCEPT ![self] = 0]
                                              ELSE /\ TRUE
                                                   /\ UNCHANGED << spins, 
                                                                   retry >>
                              ELSE /\ TRUE
                                   /\ UNCHANGED << num, owner, srv, fresh, inq, 
                                                   spins, reaped, retry >>
                        /\ due' = due
             /\ reap' = [reap EXCEPT ![self] = FALSE]
             /\ IF due'[self] = {}
                   THEN /\ pc' = [pc EXCEPT ![self] = "hsL"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hsR"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, peerRoot, cclosed, 
                             rdshut, outq, rootNow, rv, wfailed, monDone, 
                             unpFailed, viol, asked, bad, taken, answered, 
                             undeliv, applied, sent, rejected, stack, ifc, t, 
                             startErr, wi, batch, cur, rq, auth, ck, cn, cgot, 
                             ci >>

hsR(self) == /\ pc[self] = "hsR"
             /\ IF due[self] # {}
                   THEN /\ \E k \in due[self]:
                             /\ viol' = (viol \cup UAF(owner[k] # self))
                             /\ rdshut' = [rdshut EXCEPT ![k] = TRUE]
                             /\ due' = [due EXCEPT ![self] = due[self] \ {k}]
                             /\ cur' = [cur EXCEPT ![self] = k]
                             /\ IF inq[k] # <<>>
                                   THEN /\ rq' = [rq EXCEPT ![self] = Head(inq[k])]
                                        /\ taken' = (taken \cup {<<k, Head(inq[k])>>})
                                        /\ inq' = [inq EXCEPT ![k] = Tail(inq[k])]
                                   ELSE /\ TRUE
                                        /\ UNCHANGED << inq, taken, rq >>
                        /\ IF rq'[self] # 0
                              THEN /\ pc' = [pc EXCEPT ![self] = "hsP"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "hsK"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hsL"]
                        /\ UNCHANGED << inq, rdshut, viol, taken, cur, rq, due >>
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, asked, bad, 
                             answered, undeliv, applied, sent, reaped, 
                             rejected, stack, ifc, t, startErr, wi, batch, 
                             reap, retry, auth, ck, cn, cgot, ci >>

hsD(self) == /\ pc[self] = "hsD"
             /\ IF inq[cur[self]] # <<>>
                   THEN /\ rq' = [rq EXCEPT ![self] = Head(inq[cur[self]])]
                        /\ taken' = (taken \cup {<<cur[self], Head(inq[cur[self]])>>})
                        /\ inq' = [inq EXCEPT ![cur[self]] = Tail(inq[cur[self]])]
                        /\ pc' = [pc EXCEPT ![self] = "hsP"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "hsK"]
                        /\ UNCHANGED << inq, taken, rq >>
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, rdshut, outq, rootNow, 
                             rv, wfailed, monDone, unpFailed, spins, viol, 
                             asked, bad, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, t, startErr, wi, 
                             batch, reap, cur, retry, auth, due, ck, cn, cgot, 
                             ci >>

hsK(self) == /\ pc[self] = "hsK"
             /\ owner' = [owner EXCEPT ![cur[self]] = NoW]
             /\ srv' = [srv EXCEPT ![cur[self]] = "closed"]
             /\ inq' = [inq EXCEPT ![cur[self]] = <<>>]
             /\ num' = [num EXCEPT ![self] = num[self] - 1]
             /\ retry' = [retry EXCEPT ![self] = FALSE]
             /\ spins' = [spins EXCEPT ![self] = 0]
             /\ reaped' = (reaped \cup {cur[self]})
             /\ cur' = [cur EXCEPT ![self] = NoConn]
             /\ rq' = [rq EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "hsR"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, fresh, peerRoot, 
                             cclosed, rdshut, outq, rootNow, rv, wfailed, 
                             monDone, unpFailed, viol, asked, bad, taken, 
                             answered, undeliv, applied, sent, rejected, stack, 
                             ifc, t, startErr, wi, batch, reap, auth, due, ck, 
                             cn, cgot, ci >>

hsF(self) == /\ pc[self] = "hsF"
             /\ wfailed' = [wfailed EXCEPT ![self] = TRUE]
             /\ batch' = [batch EXCEPT ![self] = {}]
             /\ reap' = [reap EXCEPT ![self] = FALSE]
             /\ due' = [due EXCEPT ![self] = {}]
             /\ IF FixWorkerExit
                   THEN /\ serverExit' = 1
                   ELSE /\ TRUE
                        /\ UNCHANGED serverExit
             /\ pc' = [pc EXCEPT ![self] = "hsX"]
             /\ UNCHANGED << initState, unpStarted, unpDone, dropped, fin, 
                             exited, lsock, backlog, frame, targs, efd, thr, 
                             shut, joinMe, num, owner, srv, fresh, peerRoot, 
                             cclosed, inq, rdshut, outq, rootNow, rv, monDone, 
                             unpFailed, spins, viol, asked, bad, taken, 
                             answered, undeliv, applied, sent, reaped, 
                             rejected, stack, ifc, t, startErr, wi, cur, rq, 
                             retry, auth, ck, cn, cgot, ci >>

hsX(self) == /\ pc[self] = "hsX"
             /\ LET mine == Owned(self) IN
                  /\ owner' = [k \in ConnIds |-> IF k \in mine THEN NoW ELSE owner[k]]
                  /\ srv' = [k \in ConnIds |-> IF k \in mine THEN "closed" ELSE srv[k]]
                  /\ inq' = [k \in ConnIds |-> IF k \in mine THEN <<>> ELSE inq[k]]
             /\ num' = [num EXCEPT ![self] = 0]
             /\ thr' = [thr EXCEPT ![self] = "idle"]
             /\ pc' = [pc EXCEPT ![self] = "hsI"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, shut, joinMe, fresh, peerRoot, 
                             cclosed, rdshut, outq, rootNow, rv, wfailed, 
                             monDone, unpFailed, spins, viol, asked, bad, 
                             taken, answered, undeliv, applied, sent, reaped, 
                             rejected, stack, ifc, t, startErr, wi, batch, 
                             reap, cur, rq, retry, auth, due, ck, cn, cgot, ci >>

hsI(self) == /\ pc[self] = "hsI"
             /\ shut[self]
             /\ thr' = [thr EXCEPT ![self] = "exit"]
             /\ pc' = [pc EXCEPT ![self] = "hsZ"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, shut, joinMe, num, owner, srv, fresh, 
                             peerRoot, cclosed, inq, rdshut, outq, rootNow, rv, 
                             wfailed, monDone, unpFailed, spins, viol, asked, 
                             bad, taken, answered, undeliv, applied, sent, 
                             reaped, rejected, stack, ifc, t, startErr, wi, 
                             batch, reap, cur, rq, retry, auth, due, ck, cn, 
                             cgot, ci >>

hsZ(self) == /\ pc[self] = "hsZ"
             /\ TRUE
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, inq, rdshut, outq, 
                             rootNow, rv, wfailed, monDone, unpFailed, spins, 
                             viol, asked, bad, taken, answered, undeliv, 
                             applied, sent, reaped, rejected, stack, ifc, t, 
                             startErr, wi, batch, reap, cur, rq, retry, auth, 
                             due, ck, cn, cgot, ci >>

wk(self) == hs0(self) \/ hs1(self) \/ hsL(self) \/ hsW(self) \/ hsE(self)
               \/ hsP(self) \/ hsT(self) \/ hsC(self) \/ hsR(self)
               \/ hsD(self) \/ hsK(self) \/ hsF(self) \/ hsX(self)
               \/ hsI(self) \/ hsZ(self)

cl0(self) == /\ pc[self] = "cl0"
             /\ IF ci[self] < MaxConn
                   THEN /\ lsock[Target(self)] # "none" \/ exited
                        /\ IF lsock[Target(self)] = "listen" /\ Permitted(self)
                              THEN /\ LET kk == <<self, ci[self] + 1>> IN
                                        /\ backlog' = [backlog EXCEPT ![Target(self)] = Append(backlog[Target(self)], kk)]
                                        /\ srv' = [srv EXCEPT ![kk] = "backlog"]
                                        /\ peerRoot' = [peerRoot EXCEPT ![kk] = rootNow[self]]
                                        /\ ck' = [ck EXCEPT ![self] = kk]
                                   /\ ci' = [ci EXCEPT ![self] = ci[self] + 1]
                                   /\ pc' = [pc EXCEPT ![self] = "cl1"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "clZ"]
                                   /\ UNCHANGED << backlog, srv, peerRoot, ck, 
                                                   ci >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = "clZ"]
                        /\ UNCHANGED << backlog, srv, peerRoot, ck, ci >>
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, frame, targs, efd, 
                             thr, shut, joinMe, num, owner, fresh, cclosed, 
                             inq, rdshut, outq, rootNow, rv, wfailed, monDone, 
                             unpFailed, spins, viol, asked, bad, taken, 
                             answered, undeliv, applied, sent, reaped, 
                             rejected, stack, ifc, t, startErr, wi, batch, 
                             reap, cur, rq, retry, auth, due, cn, cgot >>

cl1(self) == /\ pc[self] = "cl1"
             /\ \/ /\ cn[self] < MaxReq /\ cn[self] - cgot[self] < Pipe /\ ~Gone(ck[self])
                      /\ ~rdshut[ck[self]]
                   /\ inq' = [inq EXCEPT ![ck[self]] = Append(inq[ck[self]], cn[self] + 1)]
                   /\ asked' = (asked \cup {<<ck[self], cn[self] + 1>>})
                   /\ \/ /\ TRUE
                         /\ bad' = bad
                      \/ /\ BadReq
                         /\ bad' = (bad \cup {<<ck[self], cn[self] + 1>>})
                   /\ cn' = [cn EXCEPT ![self] = cn[self] + 1]
                   /\ pc' = [pc EXCEPT ![self] = "cl1"]
                   /\ UNCHANGED <<cclosed, outq, rootNow, viol, cgot>>
                \/ /\ outq[ck[self]] # <<>>
                   /\ viol' = (viol \cup (IF Head(outq[ck[self]]) # cgot[self] + 1
                                          THEN {"OutOfStep"} ELSE {}))
                   /\ outq' = [outq EXCEPT ![ck[self]] = Tail(outq[ck[self]])]
                   /\ cgot' = [cgot EXCEPT ![self] = cgot[self] + 1]
                   /\ pc' = [pc EXCEPT ![self] = "cl1"]
                   /\ UNCHANGED <<cclosed, inq, rootNow, asked, bad, cn>>
                \/ /\ cn[self] < MaxReq /\ cn[self] - cgot[self] < Pipe /\ ~Gone(ck[self])
                      /\ rdshut[ck[self]]
                   /\ cclosed' = [cclosed EXCEPT ![ck[self]] = TRUE]
                   /\ outq' = [outq EXCEPT ![ck[self]] = <<>>]
                   /\ pc' = [pc EXCEPT ![self] = "clN"]
                   /\ UNCHANGED <<inq, rootNow, viol, asked, bad, cn, cgot>>
                \/ /\ Gone(ck[self]) /\ outq[ck[self]] = <<>>
                   /\ pc' = [pc EXCEPT ![self] = "clN"]
                   /\ UNCHANGED <<cclosed, inq, outq, rootNow, viol, asked, bad, cn, cgot>>
                \/ /\ ClientClose \/ (cn[self] = MaxReq /\ cgot[self] = cn[self])
                   /\ cclosed' = [cclosed EXCEPT ![ck[self]] = TRUE]
                   /\ outq' = [outq EXCEPT ![ck[self]] = <<>>]
                   /\ pc' = [pc EXCEPT ![self] = "clN"]
                   /\ UNCHANGED <<inq, rootNow, viol, asked, bad, cn, cgot>>
                \/ /\ self \in DropUid /\ rootNow[self]
                   /\ rootNow' = [rootNow EXCEPT ![self] = FALSE]
                   /\ pc' = [pc EXCEPT ![self] = "cl1"]
                   /\ UNCHANGED <<cclosed, inq, outq, viol, asked, bad, cn, cgot>>
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, rdshut, rv, wfailed, monDone, 
                             unpFailed, spins, taken, answered, undeliv, 
                             applied, sent, reaped, rejected, stack, ifc, t, 
                             startErr, wi, batch, reap, cur, rq, retry, auth, 
                             due, ck, ci >>

clN(self) == /\ pc[self] = "clN"
             /\ ck' = [ck EXCEPT ![self] = NoConn]
             /\ cn' = [cn EXCEPT ![self] = 0]
             /\ cgot' = [cgot EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "cl0"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, inq, rdshut, outq, 
                             rootNow, rv, wfailed, monDone, unpFailed, spins, 
                             viol, asked, bad, taken, answered, undeliv, 
                             applied, sent, reaped, rejected, stack, ifc, t, 
                             startErr, wi, batch, reap, cur, rq, retry, auth, 
                             due, ci >>

clZ(self) == /\ pc[self] = "clZ"
             /\ TRUE
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << initState, serverExit, unpStarted, unpDone, 
                             dropped, fin, exited, lsock, backlog, frame, 
                             targs, efd, thr, shut, joinMe, num, owner, srv, 
                             fresh, peerRoot, cclosed, inq, rdshut, outq, 
                             rootNow, rv, wfailed, monDone, unpFailed, spins, 
                             viol, asked, bad, taken, answered, undeliv, 
                             applied, sent, reaped, rejected, stack, ifc, t, 
                             startErr, wi, batch, reap, cur, rq, retry, auth, 
                             due, ck, cn, cgot, ci >>

cl(self) == cl0(self) \/ cl1(self) \/ clN(self) \/ clZ(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == pmain \/ punp \/ pmon \/ penv
           \/ (\E self \in ProcSet: workerloop(self))
           \/ (\E self \in Workers: wk(self))
           \/ (\E self \in Clients: cl(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(pmain) /\ WF_vars(workerloop("main"))
        /\ WF_vars(punp) /\ WF_vars(workerloop("unp"))
        /\ WF_vars(pmon)
        /\ WF_vars(penv)
        /\ \A self \in Workers : WF_vars(wk(self))
        /\ \A self \in Clients : WF_vars(cl(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ initState \in {"uninit", "privdone", "unpdone", "unpfail", "dropped"}
    /\ thr \in [Workers -> {"none", "sched", "run", "idle", "exit"}]
    /\ owner \in [ConnIds -> Workers \cup {NoW}]
    /\ srv \in [ConnIds -> {"none", "backlog", "open", "closed", "refused"}]
    /\ num \in [Workers -> 0..Cap]

\* A connection is open exactly while one worker's list and epoll set hold it.
ConnOwned == \A k \in ConnIds : (owner[k] # NoW) <=> (srv[k] = "open")

\* num_connections counts the worker's list, and stays within the cap.
CountsConsistent ==
    \A w \in Workers : num[w] = Cardinality(Owned(w)) /\ num[w] <= Cap

\* A job that ended left no connection behind.
NoConnLeak == \A w \in Workers : thr[w] \in {"none", "idle", "exit"} => num[w] = 0

\* No worker touches a freed connection, the freed threads array of its
\* esdm_rpcs_workerloop(), or the struct esdm_rpcs of a returned frame.
NoUseAfterFree == "UseAfterFree" \notin viol

\* The request a worker has read and not yet answered.
InService(x) == \E w \in Workers : cur[w] = x[1] /\ rq[w] = x[2]

\* Each response answers a request of its connection, once: the responses
\* written on a connection are as many as its requests answered, and all of
\* them were sent. It holds by the structure of the model, in which a worker
\* serves one request at a time and every handler replies once.
ExactlyOnce ==
    /\ answered \subseteq asked
    /\ \A k \in ConnIds :
           sent[k] = Cardinality({x \in answered : x[1] = k})

\* A request a worker has read is answered, unless it is invalid or its
\* reply could not be delivered: the client closed, or left SndBuf responses
\* unread until the write timed out.
RepliedOrBroken ==
    \A x \in taken : \/ x \in answered
                     \/ x \in bad
                     \/ x \in undeliv
                     \/ InService(x)

\* ... and then its connection is closed (struct esdm_rpcs_connection: "A
\* reply was lost and the client is out of step: the event loop closes it").
AnsweredOrClosed ==
    \A x \in undeliv \cup (bad \cap taken) :
        InService(x) \/ srv[x[1]] # "open"

\* A connection is closed with a request unread only for a cause: the client
\* closed it, an earlier request was invalid or its reply lost, it was
\* released at accept, or the server shuts down. The idle timer is no cause:
\* what the client wrote before the pass shut the connection is served.
Broken(k) == \E y \in undeliv \cup (bad \cap taken) : y[1] = k
ClosedForCause ==
    \A x \in asked \ taken :
        srv[x[1]] = "closed"
            => \/ cclosed[x[1]]
               \/ Broken(x[1])
               \/ x[1] \in rejected
               \/ serverExit # 0

\* A connection the idle pass shut for reading does not stay open: its worker
\* serves what is left in it and closes it.
ShutIsClosed ==
    \A k \in ConnIds :
        rdshut[k] /\ srv[k] = "open" => \E w \in Workers : cur[w] = k

\* A client matching responses by order gets the answer to its request.
InStep == "OutOfStep" \notin viol

\* A privileged call takes effect on the privileged interface, for a client
\* that was root ...
PrivAuthorized ==
    \A x \in applied : Target(Client(x[1])) = "priv" /\ peerRoot[x[1]]

\* ... but at connect(), not at the call (esdm_rpc_server.h on
\* esdm_rpc_client_is_privileged()).
PrivAtCall == "PrivAtCall" \notin viol

\* A worker that left on a failure has ended the server: no interface keeps
\* listening short of a worker.
WorkersServe ==
    \A w \in Workers :
        (wfailed[w] /\ thr[w] \notin {"sched", "run"}) => serverExit # 0

\* Nothing is served before the permanent privilege drop, or after
\* esdm_fini().
ServeAfterDrop == "ServedPrivileged" \notin viol
NoServeAfterFini == "ServedAfterFini" \notin viol

\* Privileges are dropped only once the ES monitor reported the privileged
\* initialization complete.
DropAfterPrivInit == dropped => monDone

\* A failed accept disarms the listener until the retry is due or a
\* connection closed, and the cap disarms it: no worker is woken twice in a
\* row for a backlog it does not accept from.
NoAcceptSpin == \A w \in Workers : spins[w] <= 1

\* thread_wait_all(true) of esdm_fini() never waits for the unprivileged
\* interface thread while that waits in thread_start() for a slot it flagged.
NoCircularWait ==
    ~(pc["main"] = "maU" /\ pc["unp"] = "wl2" /\ shut[USeq[t["unp"]]])

\* Once the exit flag is set, a worker blocked in epoll_wait() has its
\* eventfd written, or the thread that started it is yet to write it: the
\* shutdown does not wait for the idle timer ("eventfd for fast termination").
LoopProc(w) == IF w \in PW THEN "main" ELSE "unp"
PromptShutdown ==
    \A w \in Workers :
        (serverExit # 0 /\ thr[w] = "run" /\ pc[w] = "hsW")
            => \/ efd[w] = "set"
               \/ pc[LoopProc(w)] \in {"wl0", "wlF", "wl1", "wl2", "wl3"}

-----------------------------------------------------------------------------
(* Liveness *)

\* A shutdown, signalled or after a failed start, ends main().
ShutdownTerminates == <>exited

\* A failed unprivileged worker loop ends the server.
FailureEnds == unpFailed ~> exited

\* A worker that left on a failure ends main(). wfailed only grows.
WorkerFailureEnds == []<>(exited \/ \A w \in Workers : ~wfailed[w])

\* ... and every worker job ends.
WorkersTerminate == <>[](\A w \in Workers : thr[w] # "run")

\* asked, answered, cclosed and a closed or refused connection only grow, so
\* each property below equals its leads-to form for every connection or
\* request, e.g. \A x : (x \in asked) ~> (x \in answered \/ Gone(x[1])),
\* and costs TLC one branch instead of one per connection.

\* A request sent is answered, or its connection closed or refused.
RequestsAnswered ==
    []<>(\A x \in asked : x \in answered \/ Gone(x[1]))

\* A connection the client closed is freed by the server.
CleanedUp ==
    []<>(\A kk \in ConnIds : cclosed[kk] => srv[kk] # "open")

\* A queued connection is accepted or reset.
AcceptedOrRefused ==
    []<>(exited \/ \A kk \in ConnIds : srv[kk] # "backlog")
=============================================================================
