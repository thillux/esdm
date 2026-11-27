---------------------------- MODULE EsdmRpcClient ----------------------------
(***************************************************************************)
(* The ESDM RPC client library: the connection pool, esdm_client_invoke()  *)
(* and the random-bytes wrappers of service-rpc/client, at the granularity *)
(* of their locks and socket operations. One step is one atomic variable   *)
(* access, one lock operation or one read() or write(); the labels name    *)
(* the C functions they come from.                                         *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - A socket is the state of one connection: the client's fd, the server *)
(*   end, the requests the server has not answered, the responses the      *)
(*   client has not read, and a pending ECONNRESET. Closing the client end *)
(*   discards all of it: a late answer goes to a dead socket, never to the *)
(*   next one.                                                             *)
(* - The server is nondeterministic within what esdm_rpc_server.c does: it *)
(*   answers a request with data or -EAGAIN, loses an answer (write        *)
(*   timeout), closes a connection (idle reaper, error, cap) with or       *)
(*   without a request unread, restarts, and refuses connects. Reading a   *)
(*   request and answering it are one step: the client cannot tell them    *)
(*   apart but by ECONNRESET versus EOF, which a close chooses freely.     *)
(*   Once the environment is good the server answers every request with   *)
(*   data within the client's receive timeout and closes nothing.          *)
(* - Time is left out. A read() that finds nothing is one SO_RCVTIMEO      *)
(*   slice, and the server is silent only while it is not good or on a     *)
(*   request whose answer it lost. The invoke bound (esdm_rpcc_expired())  *)
(*   may pass at any re-send, at the latest after MaxRounds of them; a     *)
(*   receive budget is Slices slices.                                      *)
(* - The connect loop of esdm_connect_proto_service() is one step that    *)
(*   succeeds if the server listens. The write loop reconnects after EPIPE *)
(*   once. The reconnect after half the server's idle timeout is left out: *)
(*   it only drops a socket with no request in flight.                     *)
(* - rpc_conn->lock is taken with the connect, and the reader side of     *)
(*   esdm_rpcc_conn_lock with the pointer load and released with the       *)
(*   claim: nothing else touches what they guard in between.               *)
(* - A request is a tag <<thread, bit>>, the bit flipped per write; the    *)
(*   server echoes it. The real protocol has no tag (request_id is 0):     *)
(*   responses are matched by order, which the tag lets us check.          *)
(* - The calls: "nb" esdm_rpcc_get_random_bytes(), "full"                 *)
(*   esdm_rpcc_get_random_bytes_full() and _pr() (same client logic),      *)
(*   "fullnb" _full_noblock() and _pr_noblock(), "timeout"                 *)
(*   _full_timeout(), "once" esdm_rpcc_rnd_add_entropy(), which is not     *)
(*   re-sendable. A request asks for 1 or 2 chunks, an answer carries one. *)
(*   The size negotiation (answers below -255) is left out.               *)
(* - An interrupt function is a flag the environment raises in a call; a  *)
(*   sticky one stays raised until the call returns (CUSE, the timeout     *)
(*   chain), a one-shot one is cleared when it reports.                    *)
(* - Locks are pthread mutexes, assumed strongly fair (fair+). The robust  *)
(*   ones hand a lock whose owner died to the next locker. A thread can   *)
(*   die (pthread_cancel) only in read(), the point where it matters.     *)
(* - The fix switches ResetOnErr, IntrUnknown and TimedGet are the code as *)
(*   it is; the configurations that show a finding turn one off.           *)
(* - Not modelled: the fork handlers, a second init/fini pair (the init    *)
(*   reference count), the privileged service (identical code), the last  *)
(*   served time of the connect loop, the per-thread buffers.              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Threads,      \* client threads
    NC,           \* connections in the pool
    Kinds,        \* calls the threads make: "nb", "full", "fullnb",
                  \* "timeout", "once"
    Sizes,        \* request sizes in chunks
    MaxCalls,     \* calls per thread
    MaxRounds,    \* re-sends of one invoke before its bound passes
    Slices,       \* SO_RCVTIMEO slices of one receive budget
    Drops,        \* the server may lose an answer
    Closes,       \* the server may close connections and refuse connects
    MaxRestarts,  \* server restarts
    Interrupts,   \* the threads have interrupt functions
    Sticky,       \* ... which stay raised until the call returns
    InvokeRetry,  \* esdm_invoke() repeats a call failing with -EINTR
    MaxDeaths,    \* threads cancelled in read()
    Fini,         \* esdm_rpcc_fini_unpriv_service() while in use
    Heal,         \* the environment may turn good for good
    ReadErr,      \* read() may fail with another errno than EAGAIN, EINTR
                  \* and ECONNRESET
    ResetOnErr,   \* fix: such a failure drops the socket
    IntrUnknown,  \* fix: an interrupted "once" request reports -ETIMEDOUT
    TimedGet,     \* fix: _full_timeout waits for a connection until its
                  \* deadline only
    Hog,          \* a caller holds the one connection longer than any
                  \* deadline
    NoReset,      \* mutation: an abandoned request's socket is kept
    NoOwnerDeadReset \* mutation: EOWNERDEAD on the lock keeps the socket

Conns == 1..NC
NoProc == "none"
SrvName == <<"s1", "s2", "s3">>
SrvProcs == {SrvName[c] : c \in Conns}
ConnOf(s) == CHOOSE c \in Conns : SrvName[c] = s
FiniProcs == IF Fini THEN {"fini"} ELSE {}
HogProcs == IF Hog THEN {"hog"} ELSE {}
\* the order esdm_rpcc_get_service() tries the connections in
Slot(nd, i) == ((nd + i - 1) % NC) + 1
\* esdm_rpcc_last_error(): -EAGAIN (an interrupt) is not reported
LastErr(v) == v \in {"err", "tmo", "reset"}

(* --algorithm EsdmRpcClient {
variables
    \* the connection pool
    ref = [c \in Conns |-> NoProc],       \* rpc_conn->ref_cnt
    lk = [c \in Conns |-> NoProc],        \* rpc_conn->lock
    waiters = [c \in Conns |-> 0],        \* rpc_conn->waiters
    cstate = [c \in Conns |-> "init"],    \* rpc_conn->state
    destroyed = [c \in Conns |-> FALSE],  \* esdm_fini_proto_service() ran
    published = TRUE,                     \* unpriv_rpc_conn is set
    freed = FALSE,                        \* the array is freed
    rdrs = {},                            \* esdm_rpcc_conn_lock readers
    wtr = NoProc,                         \* ... its writer
    wantW = FALSE,                        \* ... a writer waits
    \* the socket of each connection
    cfd = [c \in Conns |-> FALSE],        \* rpc_conn->fd >= 0
    sopen = [c \in Conns |-> FALSE],      \* the server's end is open
    toSrv = [c \in Conns |-> <<>>],       \* requests not answered
    toCli = [c \in Conns |-> <<>>],       \* responses the client has not read
    rst = [c \in Conns |-> FALSE],        \* ECONNRESET pending (sk_err)
    up = TRUE,                            \* the server listens
    restarts = 0,
    good = FALSE,
    \* per thread
    held = [t \in Threads |-> 0],         \* the connection checked out
    kind = [t \in Threads |-> "none"],    \* the call in progress
    intr = [t \in Threads |-> FALSE],     \* the interrupt function reports
    dl = [t \in Threads |-> FALSE],       \* the _full_timeout deadline passed
    gr = [t \in Threads |-> "none"],      \* esdm_rpcc_get_service() result
    ivr = [t \in Threads |-> "none"],     \* rpc_conn->last_error
    cres = [t \in Threads |-> "none"],    \* buffer.ret, set by the closure
    dead = {},
    \* ghosts: tag bit of the last request, writes of a "once" call and
    \* its runs by the server, the call started while good, properties
    \* violated
    bit = [t \in Threads |-> 0],
    sent = [t \in Threads |-> 0],
    ran = [t \in Threads |-> 0],
    sg = [t \in Threads |-> FALSE],
    viol = {};

define {
    Free == {NoProc} \cup dead
    \* esdm_rpcc_interrupted(), with the deadline chained in front
    Intr(t) == intr[t] \/ (kind[t] = "timeout" /\ dl[t])
    AllDone == \A t \in Threads : pc[t] = "Done"
}

\* reset_conn_socket(): the client end closed, the socket gone
macro resetSock(c) {
    cfd[c] := FALSE;
    sopen[c] := FALSE;
    toSrv[c] := <<>>;
    toCli[c] := <<>>;
    rst[c] := FALSE;
}

\* a fresh socket, accepted by the server
macro connectSock(c) {
    cfd[c] := TRUE;
    sopen[c] := TRUE;
    toSrv[c] := <<>>;
    toCli[c] := <<>>;
    rst[c] := FALSE;
}

macro consumeIntr() {
    if (~Sticky) intr[self] := FALSE;
}

\* the server runs a "once" request when it reads it, whether the answer
\* goes out or is lost
macro run(q) {
    if (kind[q[1]] = "once") {
        if (ran[q[1]] > 0) viol := viol \cup {"RanTwice"};
        ran[q[1]] := ran[q[1]] + 1;
    };
}

\* esdm_rpcc_get_service() with esdm_rpcc_claim_service(); gr: "ok",
\* "efault" (no array), "eshutdown" (being torn down)
procedure getService()
    variables gi = 0, node = 1;
{
gs0: await wtr = NoProc /\ ~wantW;
     if (~published) {
         gr[self] := "efault";
         return;
     } else {
         rdrs := rdrs \cup {self};
         \* esdm_rpcc_curr_node()
         with (nd \in Conns) node := nd;
     };
     \* the optimistic pass: mutex_w_trylock(), the claim under the lock
gs2: while (gi < NC) {
         if (ref[Slot(node, gi)] \in Free) {
             if (cstate[Slot(node, gi)] = "init") {
                 ref[Slot(node, gi)] := self;
                 held[self] := Slot(node, gi);
                 gr[self] := "ok";
             } else {
                 ref[Slot(node, gi)] := NoProc;
                 gr[self] := "eshutdown";
             };
             rdrs := rdrs \ {self};
             return;
         } else {
             gi := gi + 1;
         };
     };
     \* wait for the home node outside the connection lock
gs3: waiters[node] := waiters[node] + 1;
     rdrs := rdrs \ {self};
gs4: either {
         await ref[node] \in Free;
         ref[node] := self;
     } or {
         \* mutex_w_timedlock() up to the deadline of _full_timeout
         await TimedGet /\ kind[self] = "timeout" /\ dl[self];
         gr[self] := "tmo";
         goto gs6;
     };
gs5: if (cstate[node] = "init") {
         held[self] := node;
         gr[self] := "ok";
     } else {
         ref[node] := NoProc;
         gr[self] := "eshutdown";
     };
gs6: waiters[node] := waiters[node] - 1;
     return;
}

\* esdm_client_invoke() with esdm_connect_proto_service(),
\* esdm_rpc_client_write_data_fd() and esdm_rpc_client_read_handler() on
\* the connection held. ivr: "ok", "intr" (-EAGAIN), "err", "tmo"
\* (-ETIMEDOUT), "reset" (-ECONNRESET); cres as the closure leaves it.
procedure invoke(once)
    variables rounds = 0, resets = 0, sl = 0, wr = 0, r = "none";
{
     \* mutex_w_lock(): EOWNERDEAD drops the socket of the died owner;
     \* esdm_connect_proto_service() if there is no socket
iv0: await lk[held[self]] \in Free;
     with (gone = lk[held[self]] \in dead /\ ~NoOwnerDeadReset) {
         lk[held[self]] := self;
         if (~gone /\ cfd[held[self]]) {
             goto iv2;
         } else if (up) {
             either {
                 connectSock(held[self]);
                 goto iv2;
             } or {
                 \* the server's connection cap, a full backlog
                 await Closes /\ ~good;
                 resetSock(held[self]);
                 r := "err";
                 goto ivOut;
             };
         } else {
             resetSock(held[self]);
             r := "err";
             goto ivOut;
         };
     };
     \* esdm_rpc_client_write_data_fd(): the interrupt check, write()
iv2: if (Intr(self)) {
         consumeIntr();
         r := "intr";
         goto ivOut;
     } else if (~sopen[held[self]] /\ rst[held[self]]) {
         \* sk_err is reported by write() as well: not EPIPE, no retry
         rst[held[self]] := FALSE;
         r := "err";
         goto ivOut;
     } else if (~sopen[held[self]]) {
         \* EPIPE: reconnect and write again
         if (wr > 0 \/ ~up) {
             resetSock(held[self]);
             r := "err";
             goto ivOut;
         } else {
             connectSock(held[self]);
             wr := wr + 1;
             goto iv2;
         };
     } else {
         with (b = 1 - bit[self]) {
             bit[self] := b;
             toSrv[held[self]] := Append(toSrv[held[self]], <<self, b>>);
         };
         if (once) sent[self] := sent[self] + 1;
     };
     \* esdm_rpc_client_read_handler(): the interrupt check, read()
rh:  if (Intr(self)) {
         consumeIntr();
         \* the answer is still to come
         if (~NoReset) resetSock(held[self]);
         cres[self] := IF once /\ IntrUnknown THEN "tmo" ELSE "eintr";
         r := "ok";
         goto ivOut;
     } else {
         either {
             \* cancelled in read(), owning ref_cnt and the lock
             await Cardinality(dead) < MaxDeaths;
             dead := dead \cup {self};
             goto ivDie;
         } or {
             if (toCli[held[self]] # <<>>) {
                 if (Head(toCli[held[self]])[1] # <<self, bit[self]>>)
                     viol := viol \cup {"Mismatch"};
                 cres[self] := Head(toCli[held[self]])[2];
                 toCli[held[self]] := Tail(toCli[held[self]]);
                 r := "ok";
                 goto ivOut;
             } else if (~sopen[held[self]]) {
                 \* EOF or ECONNRESET: closed without an answer
                 rst[held[self]] := FALSE;
                 r := "reset";
             } else {
                 \* EAGAIN: nothing within SO_RCVTIMEO; a good server is
                 \* silent only on a request whose answer it lost
                 await ~good \/ toSrv[held[self]] = <<>>;
                 either {
                     await sl + 1 < Slices;
                     sl := sl + 1;
                     goto rh;
                 } or {
                     \* the receive budget or the invoke bound is spent
                     r := "eagain";
                 } or {
                     \* any other errno: the closure gets -EPROTO
                     await ReadErr;
                     if (ResetOnErr) resetSock(held[self]);
                     cres[self] := "err";
                     r := "err";
                     goto ivOut;
                 };
             };
         };
     };
     \* -EAGAIN and -ECONNRESET: drop the socket, ask again within bounds
ivR: if (once) {
         if (~NoReset) resetSock(held[self]);
         r := IF r = "eagain" THEN "tmo" ELSE r;
         goto ivOut;
     } else {
         either {
             await rounds < MaxRounds /\ ~(r = "reset" /\ resets >= 2);
             rounds := rounds + 1;
             resets := IF r = "reset" THEN resets + 1 ELSE resets;
             sl := 0;
             wr := 0;
             if (NoReset) {
                 goto iv2;
             } else if (up) {
                 either {
                     connectSock(held[self]);
                     goto iv2;
                 } or {
                     await Closes /\ ~good;
                     resetSock(held[self]);
                     r := "err";
                     goto ivOut;
                 };
             } else {
                 resetSock(held[self]);
                 r := "err";
                 goto ivOut;
             };
         } or {
             \* expired, or the resets used up
             if (~NoReset) resetSock(held[self]);
             r := IF r = "eagain" THEN "tmo" ELSE r;
             goto ivOut;
         };
     };
ivOut: ivr[self] := r;
     lk[held[self]] := NoProc;
     return;
ivDie: return;
}

fair+ process (cl \in Threads)
    variables calls = 0, n = 0, done = 0, tries = 0, res = "none";
{
c0: while (calls < MaxCalls) {
        with (k \in Kinds, s \in Sizes) {
            kind[self] := k;
            n := IF k \in {"fullnb", "once"} THEN 1 ELSE s;
        };
        calls := calls + 1;
        intr[self] := FALSE;
        dl[self] := FALSE;
        sent[self] := 0;
        ran[self] := 0;
        sg[self] := good;
        \* esdm_rpcc_get_unpriv_service(), esdm_rpcc_timeout_get()
c1:     call getService();
c2:     if (gr[self] # "ok") {
            gr[self] := "none";
            res := "err";
            goto c9;
        } else {
            gr[self] := "none";
        };
c3:     while (done < n) {
            if (kind[self] = "timeout" /\ dl[self]) {
                res := "tmo";
                goto c8;
            } else {
                \* the -ETIMEDOUT placeholder
                cres[self] := "tmo";
                call invoke(kind[self] = "once");
            };
c4:         with (le = ivr[self], cr = cres[self]) {
                ivr[self] := "none";
                cres[self] := "none";
                if (self \in dead) {
                    goto Done;
                } else if (LastErr(le)) {
                    res := le;
                    goto c8;
                } else if (kind[self] = "timeout" /\ cr = "eintr" /\ dl[self]) {
                    res := "tmo";
                    goto c8;
                } else if (cr = "eagain") {
                    if (kind[self] = "nb") {
                        \* return what came so far
                        res := IF done > 0 THEN "ok" ELSE "eagain";
                        goto c8;
                    } else if (kind[self] = "fullnb") {
                        res := "eagain";
                        goto c8;
                    } else {
                        \* wait without holding the pooled connection
                        ref[held[self]] := NoProc;
                        held[self] := 0;
                        goto c5;
                    };
                } else if (cr # "data") {
                    res := cr;
                    goto c8;
                } else {
                    done := done + 1;
                };
            };
        };
        res := "ok";
        goto c8;
        \* esdm_client_poll_wait()
c5:     skip;
c6:     call getService();
c7:     if (gr[self] # "ok") {
            gr[self] := "none";
            res := "err";
            goto c9;
        } else {
            gr[self] := "none";
            goto c3;
        };
        \* esdm_rpcc_put_unpriv_service()
c8:     ref[held[self]] := NoProc;
        held[self] := 0;
        \* esdm_invoke() repeats on -EINTR
c9:     if (res = "eintr" /\ tries < InvokeRetry) {
            tries := tries + 1;
            done := 0;
            goto c1;
        } else {
            viol := viol
                \cup (IF kind[self] \in {"full", "timeout"} /\ res = "eagain"
                      THEN {"BlockingEagain"} ELSE {})
                \cup (IF sent[self] > 1 THEN {"SentTwice"} ELSE {})
                \cup (IF sg[self] /\ res # "ok" THEN {"GoodFailed"} ELSE {});
            kind[self] := "none";
            sg[self] := FALSE;
            res := "none";
            done := 0;
            tries := 0;
            n := 0;
        };
    };
}

\* the server end of one connection
fair process (sv \in SrvProcs)
{
sv0: while (~AllDone) {
         either {
             \* esdm_rpcs_read() and the handler's answer
             await sopen[ConnOf(self)] /\ toSrv[ConnOf(self)] # <<>>;
             with (q = Head(toSrv[ConnOf(self)]),
                   v \in IF good \/ kind[q[1]] = "once"
                         THEN {"data"} ELSE {"data", "eagain"}) {
                 toCli[ConnOf(self)] := Append(toCli[ConnOf(self)], <<q, v>>);
                 run(q);
             };
             toSrv[ConnOf(self)] := Tail(toSrv[ConnOf(self)]);
         } or {
             \* esdm_rpcs_write_data() timed out: the answer is lost
             await Drops /\ ~good /\ sopen[ConnOf(self)]
                   /\ toSrv[ConnOf(self)] # <<>>;
             run(Head(toSrv[ConnOf(self)]));
             toSrv[ConnOf(self)] := Tail(toSrv[ConnOf(self)]);
         } or {
             \* esdm_rpcs_close_conn(): idle, error or cap; a request not
             \* read yet leaves ECONNRESET
             await Closes /\ ~good /\ sopen[ConnOf(self)];
             with (e \in IF toSrv[ConnOf(self)] # <<>> THEN BOOLEAN
                         ELSE {FALSE})
                 rst[ConnOf(self)] := e;
             sopen[ConnOf(self)] := FALSE;
             toSrv[ConnOf(self)] := <<>>;
         };
     };
}

\* restarts, interrupts, deadlines; the environment may turn good
fair process (en = "env")
{
en0: while (~AllDone) {
         either {
             \* the server restarts: every connection closed
             await restarts < MaxRestarts /\ ~good /\ up;
             restarts := restarts + 1;
             up := FALSE;
             with (e \in [Conns -> BOOLEAN])
                 rst := [c \in Conns |-> rst[c] \/ (toSrv[c] # <<>> /\ e[c])];
             sopen := [c \in Conns |-> FALSE];
             toSrv := [c \in Conns |-> <<>>];
         } or {
             await ~up;
             up := TRUE;
         } or {
             await Interrupts /\ ~good;
             with (t \in {x \in Threads : kind[x] # "none" /\ ~intr[x]})
                 intr[t] := TRUE;
         } or {
             await ~good;
             with (t \in {x \in Threads : kind[x] = "timeout" /\ ~dl[x]})
                 dl[t] := TRUE;
         } or {
             await Heal /\ ~good;
             good := TRUE;
             up := TRUE;
         };
     };
}

\* a caller that checked out the one connection and keeps it past any
\* deadline: a slow request, or a call of many
process (hg \in HogProcs)
{
hg0: await ref[1] \in Free;
     ref[1] := self;
hg1: await FALSE;
}

\* esdm_rpcc_fini_service() and esdm_rpcc_release_conns()
fair process (fi \in FiniProcs)
    variables fc = 1, inUse = FALSE;
{
fi0: wantW := TRUE;
fi1: await wtr = NoProc /\ rdrs = {};
     wtr := self;
     wantW := FALSE;
     \* the pointer swapped to NULL, the last reference dropped
fi2: published := FALSE;
     wtr := NoProc;
fi3: while (fc <= NC) {
         cstate[fc] := "term";
         fc := fc + 1;
     };
fi4: fc := 1;
fi5: while (fc <= NC) {
         either {
             \* mutex_w_timedlock() takes it
             await ref[fc] \in Free;
             ref[fc] := self;
         } or {
             \* ... or times out: a live caller still owns it
             await ref[fc] \notin Free;
             inUse := TRUE;
             fc := fc + 1;
             goto fi5;
         };
fi6:     ref[fc] := NoProc;
         \* wait for the getters blocked on ref_cnt, within the second
fi7:     either {
             await waiters[fc] = 0 /\ lk[fc] \in Free;
             \* esdm_fini_proto_service(), esdm_client_destroy()
             destroyed[fc] := TRUE;
             resetSock(fc);
         } or {
             await waiters[fc] > 0;
             inUse := TRUE;
         };
         fc := fc + 1;
     };
fi8: if (~inUse) freed := TRUE;
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES ref, lk, waiters, cstate, destroyed, published, freed, rdrs, wtr, 
          wantW, cfd, sopen, toSrv, toCli, rst, up, restarts, good, held, 
          kind, intr, dl, gr, ivr, cres, dead, bit, sent, ran, sg, viol, pc, 
          stack

(* define statement *)
Free == {NoProc} \cup dead

Intr(t) == intr[t] \/ (kind[t] = "timeout" /\ dl[t])
AllDone == \A t \in Threads : pc[t] = "Done"

VARIABLES gi, node, once, rounds, resets, sl, wr, r, calls, n, done, tries, 
          res, fc, inUse

vars == << ref, lk, waiters, cstate, destroyed, published, freed, rdrs, wtr, 
           wantW, cfd, sopen, toSrv, toCli, rst, up, restarts, good, held, 
           kind, intr, dl, gr, ivr, cres, dead, bit, sent, ran, sg, viol, pc, 
           stack, gi, node, once, rounds, resets, sl, wr, r, calls, n, done, 
           tries, res, fc, inUse >>

ProcSet == (Threads) \cup (SrvProcs) \cup {"env"} \cup (HogProcs) \cup (FiniProcs)

Init == (* Global variables *)
        /\ ref = [c \in Conns |-> NoProc]
        /\ lk = [c \in Conns |-> NoProc]
        /\ waiters = [c \in Conns |-> 0]
        /\ cstate = [c \in Conns |-> "init"]
        /\ destroyed = [c \in Conns |-> FALSE]
        /\ published = TRUE
        /\ freed = FALSE
        /\ rdrs = {}
        /\ wtr = NoProc
        /\ wantW = FALSE
        /\ cfd = [c \in Conns |-> FALSE]
        /\ sopen = [c \in Conns |-> FALSE]
        /\ toSrv = [c \in Conns |-> <<>>]
        /\ toCli = [c \in Conns |-> <<>>]
        /\ rst = [c \in Conns |-> FALSE]
        /\ up = TRUE
        /\ restarts = 0
        /\ good = FALSE
        /\ held = [t \in Threads |-> 0]
        /\ kind = [t \in Threads |-> "none"]
        /\ intr = [t \in Threads |-> FALSE]
        /\ dl = [t \in Threads |-> FALSE]
        /\ gr = [t \in Threads |-> "none"]
        /\ ivr = [t \in Threads |-> "none"]
        /\ cres = [t \in Threads |-> "none"]
        /\ dead = {}
        /\ bit = [t \in Threads |-> 0]
        /\ sent = [t \in Threads |-> 0]
        /\ ran = [t \in Threads |-> 0]
        /\ sg = [t \in Threads |-> FALSE]
        /\ viol = {}
        (* Procedure getService *)
        /\ gi = [ self \in ProcSet |-> 0]
        /\ node = [ self \in ProcSet |-> 1]
        (* Procedure invoke *)
        /\ once = [ self \in ProcSet |-> defaultInitValue]
        /\ rounds = [ self \in ProcSet |-> 0]
        /\ resets = [ self \in ProcSet |-> 0]
        /\ sl = [ self \in ProcSet |-> 0]
        /\ wr = [ self \in ProcSet |-> 0]
        /\ r = [ self \in ProcSet |-> "none"]
        (* Process cl *)
        /\ calls = [self \in Threads |-> 0]
        /\ n = [self \in Threads |-> 0]
        /\ done = [self \in Threads |-> 0]
        /\ tries = [self \in Threads |-> 0]
        /\ res = [self \in Threads |-> "none"]
        (* Process fi *)
        /\ fc = [self \in FiniProcs |-> 1]
        /\ inUse = [self \in FiniProcs |-> FALSE]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Threads -> "c0"
                                        [] self \in SrvProcs -> "sv0"
                                        [] self = "env" -> "en0"
                                        [] self \in HogProcs -> "hg0"
                                        [] self \in FiniProcs -> "fi0"]

gs0(self) == /\ pc[self] = "gs0"
             /\ wtr = NoProc /\ ~wantW
             /\ IF ~published
                   THEN /\ gr' = [gr EXCEPT ![self] = "efault"]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ gi' = [gi EXCEPT ![self] = Head(stack[self]).gi]
                        /\ node' = [node EXCEPT ![self] = Head(stack[self]).node]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ rdrs' = rdrs
                   ELSE /\ rdrs' = (rdrs \cup {self})
                        /\ \E nd \in Conns:
                             node' = [node EXCEPT ![self] = nd]
                        /\ pc' = [pc EXCEPT ![self] = "gs2"]
                        /\ UNCHANGED << gr, stack, gi >>
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, once, 
                             rounds, resets, sl, wr, r, calls, n, done, tries, 
                             res, fc, inUse >>

gs2(self) == /\ pc[self] = "gs2"
             /\ IF gi[self] < NC
                   THEN /\ IF ref[Slot(node[self], gi[self])] \in Free
                              THEN /\ IF cstate[Slot(node[self], gi[self])] = "init"
                                         THEN /\ ref' = [ref EXCEPT ![Slot(node[self], gi[self])] = self]
                                              /\ held' = [held EXCEPT ![self] = Slot(node[self], gi[self])]
                                              /\ gr' = [gr EXCEPT ![self] = "ok"]
                                         ELSE /\ ref' = [ref EXCEPT ![Slot(node[self], gi[self])] = NoProc]
                                              /\ gr' = [gr EXCEPT ![self] = "eshutdown"]
                                              /\ held' = held
                                   /\ rdrs' = rdrs \ {self}
                                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ gi' = [gi EXCEPT ![self] = Head(stack[self]).gi]
                                   /\ node' = [node EXCEPT ![self] = Head(stack[self]).node]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                              ELSE /\ gi' = [gi EXCEPT ![self] = gi[self] + 1]
                                   /\ pc' = [pc EXCEPT ![self] = "gs2"]
                                   /\ UNCHANGED << ref, rdrs, held, gr, stack, 
                                                   node >>
                   ELSE /\ pc' = [pc EXCEPT ![self] = "gs3"]
                        /\ UNCHANGED << ref, rdrs, held, gr, stack, gi, node >>
             /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                             wtr, wantW, cfd, sopen, toSrv, toCli, rst, up, 
                             restarts, good, kind, intr, dl, ivr, cres, dead, 
                             bit, sent, ran, sg, viol, once, rounds, resets, 
                             sl, wr, r, calls, n, done, tries, res, fc, inUse >>

gs3(self) == /\ pc[self] = "gs3"
             /\ waiters' = [waiters EXCEPT ![node[self]] = waiters[node[self]] + 1]
             /\ rdrs' = rdrs \ {self}
             /\ pc' = [pc EXCEPT ![self] = "gs4"]
             /\ UNCHANGED << ref, lk, cstate, destroyed, published, freed, wtr, 
                             wantW, cfd, sopen, toSrv, toCli, rst, up, 
                             restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

gs4(self) == /\ pc[self] = "gs4"
             /\ \/ /\ ref[node[self]] \in Free
                   /\ ref' = [ref EXCEPT ![node[self]] = self]
                   /\ pc' = [pc EXCEPT ![self] = "gs5"]
                   /\ gr' = gr
                \/ /\ TimedGet /\ kind[self] = "timeout" /\ dl[self]
                   /\ gr' = [gr EXCEPT ![self] = "tmo"]
                   /\ pc' = [pc EXCEPT ![self] = "gs6"]
                   /\ ref' = ref
             /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

gs5(self) == /\ pc[self] = "gs5"
             /\ IF cstate[node[self]] = "init"
                   THEN /\ held' = [held EXCEPT ![self] = node[self]]
                        /\ gr' = [gr EXCEPT ![self] = "ok"]
                        /\ ref' = ref
                   ELSE /\ ref' = [ref EXCEPT ![node[self]] = NoProc]
                        /\ gr' = [gr EXCEPT ![self] = "eshutdown"]
                        /\ held' = held
             /\ pc' = [pc EXCEPT ![self] = "gs6"]
             /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, kind, intr, dl, ivr, cres, 
                             dead, bit, sent, ran, sg, viol, stack, gi, node, 
                             once, rounds, resets, sl, wr, r, calls, n, done, 
                             tries, res, fc, inUse >>

gs6(self) == /\ pc[self] = "gs6"
             /\ waiters' = [waiters EXCEPT ![node[self]] = waiters[node[self]] - 1]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ gi' = [gi EXCEPT ![self] = Head(stack[self]).gi]
             /\ node' = [node EXCEPT ![self] = Head(stack[self]).node]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << ref, lk, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, once, 
                             rounds, resets, sl, wr, r, calls, n, done, tries, 
                             res, fc, inUse >>

getService(self) == gs0(self) \/ gs2(self) \/ gs3(self) \/ gs4(self)
                       \/ gs5(self) \/ gs6(self)

iv0(self) == /\ pc[self] = "iv0"
             /\ lk[held[self]] \in Free
             /\ LET gone == lk[held[self]] \in dead /\ ~NoOwnerDeadReset IN
                  /\ lk' = [lk EXCEPT ![held[self]] = self]
                  /\ IF ~gone /\ cfd[held[self]]
                        THEN /\ pc' = [pc EXCEPT ![self] = "iv2"]
                             /\ UNCHANGED << cfd, sopen, toSrv, toCli, rst, r >>
                        ELSE /\ IF up
                                   THEN /\ \/ /\ cfd' = [cfd EXCEPT ![(held[self])] = TRUE]
                                              /\ sopen' = [sopen EXCEPT ![(held[self])] = TRUE]
                                              /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                              /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                              /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                              /\ pc' = [pc EXCEPT ![self] = "iv2"]
                                              /\ r' = r
                                           \/ /\ Closes /\ ~good
                                              /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                              /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                              /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                              /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                              /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                              /\ r' = [r EXCEPT ![self] = "err"]
                                              /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                                   ELSE /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                        /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                        /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                        /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                        /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                        /\ r' = [r EXCEPT ![self] = "err"]
                                        /\ pc' = [pc EXCEPT ![self] = "ivOut"]
             /\ UNCHANGED << ref, waiters, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, up, restarts, good, held, kind, 
                             intr, dl, gr, ivr, cres, dead, bit, sent, ran, sg, 
                             viol, stack, gi, node, once, rounds, resets, sl, 
                             wr, calls, n, done, tries, res, fc, inUse >>

iv2(self) == /\ pc[self] = "iv2"
             /\ IF Intr(self)
                   THEN /\ IF ~Sticky
                              THEN /\ intr' = [intr EXCEPT ![self] = FALSE]
                              ELSE /\ TRUE
                                   /\ intr' = intr
                        /\ r' = [r EXCEPT ![self] = "intr"]
                        /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                        /\ UNCHANGED << cfd, sopen, toSrv, toCli, rst, bit, 
                                        sent, wr >>
                   ELSE /\ IF ~sopen[held[self]] /\ rst[held[self]]
                              THEN /\ rst' = [rst EXCEPT ![held[self]] = FALSE]
                                   /\ r' = [r EXCEPT ![self] = "err"]
                                   /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                                   /\ UNCHANGED << cfd, sopen, toSrv, toCli, 
                                                   bit, sent, wr >>
                              ELSE /\ IF ~sopen[held[self]]
                                         THEN /\ IF wr[self] > 0 \/ ~up
                                                    THEN /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                                         /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                                         /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                         /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                         /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                                         /\ r' = [r EXCEPT ![self] = "err"]
                                                         /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                                                         /\ wr' = wr
                                                    ELSE /\ cfd' = [cfd EXCEPT ![(held[self])] = TRUE]
                                                         /\ sopen' = [sopen EXCEPT ![(held[self])] = TRUE]
                                                         /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                         /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                         /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                                         /\ wr' = [wr EXCEPT ![self] = wr[self] + 1]
                                                         /\ pc' = [pc EXCEPT ![self] = "iv2"]
                                                         /\ r' = r
                                              /\ UNCHANGED << bit, sent >>
                                         ELSE /\ LET b == 1 - bit[self] IN
                                                   /\ bit' = [bit EXCEPT ![self] = b]
                                                   /\ toSrv' = [toSrv EXCEPT ![held[self]] = Append(toSrv[held[self]], <<self, b>>)]
                                              /\ IF once[self]
                                                    THEN /\ sent' = [sent EXCEPT ![self] = sent[self] + 1]
                                                    ELSE /\ TRUE
                                                         /\ sent' = sent
                                              /\ pc' = [pc EXCEPT ![self] = "rh"]
                                              /\ UNCHANGED << cfd, sopen, 
                                                              toCli, rst, wr, 
                                                              r >>
                        /\ intr' = intr
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, wtr, wantW, up, restarts, good, held, 
                             kind, dl, gr, ivr, cres, dead, ran, sg, viol, 
                             stack, gi, node, once, rounds, resets, sl, calls, 
                             n, done, tries, res, fc, inUse >>

rh(self) == /\ pc[self] = "rh"
            /\ IF Intr(self)
                  THEN /\ IF ~Sticky
                             THEN /\ intr' = [intr EXCEPT ![self] = FALSE]
                             ELSE /\ TRUE
                                  /\ intr' = intr
                       /\ IF ~NoReset
                             THEN /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                  /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                  /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                  /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                  /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                             ELSE /\ TRUE
                                  /\ UNCHANGED << cfd, sopen, toSrv, toCli, 
                                                  rst >>
                       /\ cres' = [cres EXCEPT ![self] = IF once[self] /\ IntrUnknown THEN "tmo" ELSE "eintr"]
                       /\ r' = [r EXCEPT ![self] = "ok"]
                       /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                       /\ UNCHANGED << dead, viol, sl >>
                  ELSE /\ \/ /\ Cardinality(dead) < MaxDeaths
                             /\ dead' = (dead \cup {self})
                             /\ pc' = [pc EXCEPT ![self] = "ivDie"]
                             /\ UNCHANGED <<cfd, sopen, toSrv, toCli, rst, cres, viol, sl, r>>
                          \/ /\ IF toCli[held[self]] # <<>>
                                   THEN /\ IF Head(toCli[held[self]])[1] # <<self, bit[self]>>
                                              THEN /\ viol' = (viol \cup {"Mismatch"})
                                              ELSE /\ TRUE
                                                   /\ viol' = viol
                                        /\ cres' = [cres EXCEPT ![self] = Head(toCli[held[self]])[2]]
                                        /\ toCli' = [toCli EXCEPT ![held[self]] = Tail(toCli[held[self]])]
                                        /\ r' = [r EXCEPT ![self] = "ok"]
                                        /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                                        /\ UNCHANGED << cfd, sopen, toSrv, rst, 
                                                        sl >>
                                   ELSE /\ IF ~sopen[held[self]]
                                              THEN /\ rst' = [rst EXCEPT ![held[self]] = FALSE]
                                                   /\ r' = [r EXCEPT ![self] = "reset"]
                                                   /\ pc' = [pc EXCEPT ![self] = "ivR"]
                                                   /\ UNCHANGED << cfd, sopen, 
                                                                   toSrv, 
                                                                   toCli, cres, 
                                                                   sl >>
                                              ELSE /\ ~good \/ toSrv[held[self]] = <<>>
                                                   /\ \/ /\ sl[self] + 1 < Slices
                                                         /\ sl' = [sl EXCEPT ![self] = sl[self] + 1]
                                                         /\ pc' = [pc EXCEPT ![self] = "rh"]
                                                         /\ UNCHANGED <<cfd, sopen, toSrv, toCli, rst, cres, r>>
                                                      \/ /\ r' = [r EXCEPT ![self] = "eagain"]
                                                         /\ pc' = [pc EXCEPT ![self] = "ivR"]
                                                         /\ UNCHANGED <<cfd, sopen, toSrv, toCli, rst, cres, sl>>
                                                      \/ /\ ReadErr
                                                         /\ IF ResetOnErr
                                                               THEN /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                                                    /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                                                    /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                                    /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                                    /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                                               ELSE /\ TRUE
                                                                    /\ UNCHANGED << cfd, 
                                                                                    sopen, 
                                                                                    toSrv, 
                                                                                    toCli, 
                                                                                    rst >>
                                                         /\ cres' = [cres EXCEPT ![self] = "err"]
                                                         /\ r' = [r EXCEPT ![self] = "err"]
                                                         /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                                                         /\ sl' = sl
                                        /\ viol' = viol
                             /\ dead' = dead
                       /\ intr' = intr
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, up, restarts, good, held, 
                            kind, dl, gr, ivr, bit, sent, ran, sg, stack, gi, 
                            node, once, rounds, resets, wr, calls, n, done, 
                            tries, res, fc, inUse >>

ivR(self) == /\ pc[self] = "ivR"
             /\ IF once[self]
                   THEN /\ IF ~NoReset
                              THEN /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                   /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                   /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                   /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                   /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                              ELSE /\ TRUE
                                   /\ UNCHANGED << cfd, sopen, toSrv, toCli, 
                                                   rst >>
                        /\ r' = [r EXCEPT ![self] = IF r[self] = "eagain" THEN "tmo" ELSE r[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                        /\ UNCHANGED << rounds, resets, sl, wr >>
                   ELSE /\ \/ /\ rounds[self] < MaxRounds /\ ~(r[self] = "reset" /\ resets[self] >= 2)
                              /\ rounds' = [rounds EXCEPT ![self] = rounds[self] + 1]
                              /\ resets' = [resets EXCEPT ![self] = IF r[self] = "reset" THEN resets[self] + 1 ELSE resets[self]]
                              /\ sl' = [sl EXCEPT ![self] = 0]
                              /\ wr' = [wr EXCEPT ![self] = 0]
                              /\ IF NoReset
                                    THEN /\ pc' = [pc EXCEPT ![self] = "iv2"]
                                         /\ UNCHANGED << cfd, sopen, toSrv, 
                                                         toCli, rst, r >>
                                    ELSE /\ IF up
                                               THEN /\ \/ /\ cfd' = [cfd EXCEPT ![(held[self])] = TRUE]
                                                          /\ sopen' = [sopen EXCEPT ![(held[self])] = TRUE]
                                                          /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                          /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                          /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                                          /\ pc' = [pc EXCEPT ![self] = "iv2"]
                                                          /\ r' = r
                                                       \/ /\ Closes /\ ~good
                                                          /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                                          /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                                          /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                          /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                          /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                                          /\ r' = [r EXCEPT ![self] = "err"]
                                                          /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                                               ELSE /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                                    /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                                    /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                    /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                    /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                                    /\ r' = [r EXCEPT ![self] = "err"]
                                                    /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                           \/ /\ IF ~NoReset
                                    THEN /\ cfd' = [cfd EXCEPT ![(held[self])] = FALSE]
                                         /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                         /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                         /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                         /\ rst' = [rst EXCEPT ![(held[self])] = FALSE]
                                    ELSE /\ TRUE
                                         /\ UNCHANGED << cfd, sopen, toSrv, 
                                                         toCli, rst >>
                              /\ r' = [r EXCEPT ![self] = IF r[self] = "eagain" THEN "tmo" ELSE r[self]]
                              /\ pc' = [pc EXCEPT ![self] = "ivOut"]
                              /\ UNCHANGED <<rounds, resets, sl, wr>>
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, wtr, wantW, up, restarts, good, held, 
                             kind, intr, dl, gr, ivr, cres, dead, bit, sent, 
                             ran, sg, viol, stack, gi, node, once, calls, n, 
                             done, tries, res, fc, inUse >>

ivOut(self) == /\ pc[self] = "ivOut"
               /\ ivr' = [ivr EXCEPT ![self] = r[self]]
               /\ lk' = [lk EXCEPT ![held[self]] = NoProc]
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ rounds' = [rounds EXCEPT ![self] = Head(stack[self]).rounds]
               /\ resets' = [resets EXCEPT ![self] = Head(stack[self]).resets]
               /\ sl' = [sl EXCEPT ![self] = Head(stack[self]).sl]
               /\ wr' = [wr EXCEPT ![self] = Head(stack[self]).wr]
               /\ r' = [r EXCEPT ![self] = Head(stack[self]).r]
               /\ once' = [once EXCEPT ![self] = Head(stack[self]).once]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << ref, waiters, cstate, destroyed, published, 
                               freed, rdrs, wtr, wantW, cfd, sopen, toSrv, 
                               toCli, rst, up, restarts, good, held, kind, 
                               intr, dl, gr, cres, dead, bit, sent, ran, sg, 
                               viol, gi, node, calls, n, done, tries, res, fc, 
                               inUse >>

ivDie(self) == /\ pc[self] = "ivDie"
               /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
               /\ rounds' = [rounds EXCEPT ![self] = Head(stack[self]).rounds]
               /\ resets' = [resets EXCEPT ![self] = Head(stack[self]).resets]
               /\ sl' = [sl EXCEPT ![self] = Head(stack[self]).sl]
               /\ wr' = [wr EXCEPT ![self] = Head(stack[self]).wr]
               /\ r' = [r EXCEPT ![self] = Head(stack[self]).r]
               /\ once' = [once EXCEPT ![self] = Head(stack[self]).once]
               /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
               /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                               freed, rdrs, wtr, wantW, cfd, sopen, toSrv, 
                               toCli, rst, up, restarts, good, held, kind, 
                               intr, dl, gr, ivr, cres, dead, bit, sent, ran, 
                               sg, viol, gi, node, calls, n, done, tries, res, 
                               fc, inUse >>

invoke(self) == iv0(self) \/ iv2(self) \/ rh(self) \/ ivR(self)
                   \/ ivOut(self) \/ ivDie(self)

c0(self) == /\ pc[self] = "c0"
            /\ IF calls[self] < MaxCalls
                  THEN /\ \E k \in Kinds:
                            \E s \in Sizes:
                              /\ kind' = [kind EXCEPT ![self] = k]
                              /\ n' = [n EXCEPT ![self] = IF k \in {"fullnb", "once"} THEN 1 ELSE s]
                       /\ calls' = [calls EXCEPT ![self] = calls[self] + 1]
                       /\ intr' = [intr EXCEPT ![self] = FALSE]
                       /\ dl' = [dl EXCEPT ![self] = FALSE]
                       /\ sent' = [sent EXCEPT ![self] = 0]
                       /\ ran' = [ran EXCEPT ![self] = 0]
                       /\ sg' = [sg EXCEPT ![self] = good]
                       /\ pc' = [pc EXCEPT ![self] = "c1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ UNCHANGED << kind, intr, dl, sent, ran, sg, calls, n >>
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, gr, ivr, cres, dead, 
                            bit, viol, stack, gi, node, once, rounds, resets, 
                            sl, wr, r, done, tries, res, fc, inUse >>

c1(self) == /\ pc[self] = "c1"
            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getService",
                                                     pc        |->  "c2",
                                                     gi        |->  gi[self],
                                                     node      |->  node[self] ] >>
                                                 \o stack[self]]
            /\ gi' = [gi EXCEPT ![self] = 0]
            /\ node' = [node EXCEPT ![self] = 1]
            /\ pc' = [pc EXCEPT ![self] = "gs0"]
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, kind, intr, dl, gr, 
                            ivr, cres, dead, bit, sent, ran, sg, viol, once, 
                            rounds, resets, sl, wr, r, calls, n, done, tries, 
                            res, fc, inUse >>

c2(self) == /\ pc[self] = "c2"
            /\ IF gr[self] # "ok"
                  THEN /\ gr' = [gr EXCEPT ![self] = "none"]
                       /\ res' = [res EXCEPT ![self] = "err"]
                       /\ pc' = [pc EXCEPT ![self] = "c9"]
                  ELSE /\ gr' = [gr EXCEPT ![self] = "none"]
                       /\ pc' = [pc EXCEPT ![self] = "c3"]
                       /\ res' = res
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, kind, intr, dl, ivr, 
                            cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                            node, once, rounds, resets, sl, wr, r, calls, n, 
                            done, tries, fc, inUse >>

c3(self) == /\ pc[self] = "c3"
            /\ IF done[self] < n[self]
                  THEN /\ IF kind[self] = "timeout" /\ dl[self]
                             THEN /\ res' = [res EXCEPT ![self] = "tmo"]
                                  /\ pc' = [pc EXCEPT ![self] = "c8"]
                                  /\ UNCHANGED << cres, stack, once, rounds, 
                                                  resets, sl, wr, r >>
                             ELSE /\ cres' = [cres EXCEPT ![self] = "tmo"]
                                  /\ /\ once' = [once EXCEPT ![self] = kind[self] = "once"]
                                     /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "invoke",
                                                                              pc        |->  "c4",
                                                                              rounds    |->  rounds[self],
                                                                              resets    |->  resets[self],
                                                                              sl        |->  sl[self],
                                                                              wr        |->  wr[self],
                                                                              r         |->  r[self],
                                                                              once      |->  once[self] ] >>
                                                                          \o stack[self]]
                                  /\ rounds' = [rounds EXCEPT ![self] = 0]
                                  /\ resets' = [resets EXCEPT ![self] = 0]
                                  /\ sl' = [sl EXCEPT ![self] = 0]
                                  /\ wr' = [wr EXCEPT ![self] = 0]
                                  /\ r' = [r EXCEPT ![self] = "none"]
                                  /\ pc' = [pc EXCEPT ![self] = "iv0"]
                                  /\ res' = res
                  ELSE /\ res' = [res EXCEPT ![self] = "ok"]
                       /\ pc' = [pc EXCEPT ![self] = "c8"]
                       /\ UNCHANGED << cres, stack, once, rounds, resets, sl, 
                                       wr, r >>
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, kind, intr, dl, gr, 
                            ivr, dead, bit, sent, ran, sg, viol, gi, node, 
                            calls, n, done, tries, fc, inUse >>

c4(self) == /\ pc[self] = "c4"
            /\ LET le == ivr[self] IN
                 LET cr == cres[self] IN
                   /\ ivr' = [ivr EXCEPT ![self] = "none"]
                   /\ cres' = [cres EXCEPT ![self] = "none"]
                   /\ IF self \in dead
                         THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                              /\ UNCHANGED << ref, held, done, res >>
                         ELSE /\ IF LastErr(le)
                                    THEN /\ res' = [res EXCEPT ![self] = le]
                                         /\ pc' = [pc EXCEPT ![self] = "c8"]
                                         /\ UNCHANGED << ref, held, done >>
                                    ELSE /\ IF kind[self] = "timeout" /\ cr = "eintr" /\ dl[self]
                                               THEN /\ res' = [res EXCEPT ![self] = "tmo"]
                                                    /\ pc' = [pc EXCEPT ![self] = "c8"]
                                                    /\ UNCHANGED << ref, held, 
                                                                    done >>
                                               ELSE /\ IF cr = "eagain"
                                                          THEN /\ IF kind[self] = "nb"
                                                                     THEN /\ res' = [res EXCEPT ![self] = IF done[self] > 0 THEN "ok" ELSE "eagain"]
                                                                          /\ pc' = [pc EXCEPT ![self] = "c8"]
                                                                          /\ UNCHANGED << ref, 
                                                                                          held >>
                                                                     ELSE /\ IF kind[self] = "fullnb"
                                                                                THEN /\ res' = [res EXCEPT ![self] = "eagain"]
                                                                                     /\ pc' = [pc EXCEPT ![self] = "c8"]
                                                                                     /\ UNCHANGED << ref, 
                                                                                                     held >>
                                                                                ELSE /\ ref' = [ref EXCEPT ![held[self]] = NoProc]
                                                                                     /\ held' = [held EXCEPT ![self] = 0]
                                                                                     /\ pc' = [pc EXCEPT ![self] = "c5"]
                                                                                     /\ res' = res
                                                               /\ done' = done
                                                          ELSE /\ IF cr # "data"
                                                                     THEN /\ res' = [res EXCEPT ![self] = cr]
                                                                          /\ pc' = [pc EXCEPT ![self] = "c8"]
                                                                          /\ done' = done
                                                                     ELSE /\ done' = [done EXCEPT ![self] = done[self] + 1]
                                                                          /\ pc' = [pc EXCEPT ![self] = "c3"]
                                                                          /\ res' = res
                                                               /\ UNCHANGED << ref, 
                                                                               held >>
            /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                            rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                            up, restarts, good, kind, intr, dl, gr, dead, bit, 
                            sent, ran, sg, viol, stack, gi, node, once, rounds, 
                            resets, sl, wr, r, calls, n, tries, fc, inUse >>

c5(self) == /\ pc[self] = "c5"
            /\ TRUE
            /\ pc' = [pc EXCEPT ![self] = "c6"]
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, kind, intr, dl, gr, 
                            ivr, cres, dead, bit, sent, ran, sg, viol, stack, 
                            gi, node, once, rounds, resets, sl, wr, r, calls, 
                            n, done, tries, res, fc, inUse >>

c6(self) == /\ pc[self] = "c6"
            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getService",
                                                     pc        |->  "c7",
                                                     gi        |->  gi[self],
                                                     node      |->  node[self] ] >>
                                                 \o stack[self]]
            /\ gi' = [gi EXCEPT ![self] = 0]
            /\ node' = [node EXCEPT ![self] = 1]
            /\ pc' = [pc EXCEPT ![self] = "gs0"]
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, kind, intr, dl, gr, 
                            ivr, cres, dead, bit, sent, ran, sg, viol, once, 
                            rounds, resets, sl, wr, r, calls, n, done, tries, 
                            res, fc, inUse >>

c7(self) == /\ pc[self] = "c7"
            /\ IF gr[self] # "ok"
                  THEN /\ gr' = [gr EXCEPT ![self] = "none"]
                       /\ res' = [res EXCEPT ![self] = "err"]
                       /\ pc' = [pc EXCEPT ![self] = "c9"]
                  ELSE /\ gr' = [gr EXCEPT ![self] = "none"]
                       /\ pc' = [pc EXCEPT ![self] = "c3"]
                       /\ res' = res
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, kind, intr, dl, ivr, 
                            cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                            node, once, rounds, resets, sl, wr, r, calls, n, 
                            done, tries, fc, inUse >>

c8(self) == /\ pc[self] = "c8"
            /\ ref' = [ref EXCEPT ![held[self]] = NoProc]
            /\ held' = [held EXCEPT ![self] = 0]
            /\ pc' = [pc EXCEPT ![self] = "c9"]
            /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                            rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                            up, restarts, good, kind, intr, dl, gr, ivr, cres, 
                            dead, bit, sent, ran, sg, viol, stack, gi, node, 
                            once, rounds, resets, sl, wr, r, calls, n, done, 
                            tries, res, fc, inUse >>

c9(self) == /\ pc[self] = "c9"
            /\ IF res[self] = "eintr" /\ tries[self] < InvokeRetry
                  THEN /\ tries' = [tries EXCEPT ![self] = tries[self] + 1]
                       /\ done' = [done EXCEPT ![self] = 0]
                       /\ pc' = [pc EXCEPT ![self] = "c1"]
                       /\ UNCHANGED << kind, sg, viol, n, res >>
                  ELSE /\ viol' =     viol
                                  \cup (IF kind[self] \in {"full", "timeout"} /\ res[self] = "eagain"
                                        THEN {"BlockingEagain"} ELSE {})
                                  \cup (IF sent[self] > 1 THEN {"SentTwice"} ELSE {})
                                  \cup (IF sg[self] /\ res[self] # "ok" THEN {"GoodFailed"} ELSE {})
                       /\ kind' = [kind EXCEPT ![self] = "none"]
                       /\ sg' = [sg EXCEPT ![self] = FALSE]
                       /\ res' = [res EXCEPT ![self] = "none"]
                       /\ done' = [done EXCEPT ![self] = 0]
                       /\ tries' = [tries EXCEPT ![self] = 0]
                       /\ n' = [n EXCEPT ![self] = 0]
                       /\ pc' = [pc EXCEPT ![self] = "c0"]
            /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                            freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                            rst, up, restarts, good, held, intr, dl, gr, ivr, 
                            cres, dead, bit, sent, ran, stack, gi, node, once, 
                            rounds, resets, sl, wr, r, calls, fc, inUse >>

cl(self) == c0(self) \/ c1(self) \/ c2(self) \/ c3(self) \/ c4(self)
               \/ c5(self) \/ c6(self) \/ c7(self) \/ c8(self) \/ c9(self)

sv0(self) == /\ pc[self] = "sv0"
             /\ IF ~AllDone
                   THEN /\ \/ /\ sopen[ConnOf(self)] /\ toSrv[ConnOf(self)] # <<>>
                              /\ LET q == Head(toSrv[ConnOf(self)]) IN
                                   \E v \in IF good \/ kind[q[1]] = "once"
                                            THEN {"data"} ELSE {"data", "eagain"}:
                                     /\ toCli' = [toCli EXCEPT ![ConnOf(self)] = Append(toCli[ConnOf(self)], <<q, v>>)]
                                     /\ IF kind[q[1]] = "once"
                                           THEN /\ IF ran[q[1]] > 0
                                                      THEN /\ viol' = (viol \cup {"RanTwice"})
                                                      ELSE /\ TRUE
                                                           /\ viol' = viol
                                                /\ ran' = [ran EXCEPT ![q[1]] = ran[q[1]] + 1]
                                           ELSE /\ TRUE
                                                /\ UNCHANGED << ran, viol >>
                              /\ toSrv' = [toSrv EXCEPT ![ConnOf(self)] = Tail(toSrv[ConnOf(self)])]
                              /\ UNCHANGED <<sopen, rst>>
                           \/ /\ Drops /\ ~good /\ sopen[ConnOf(self)]
                                 /\ toSrv[ConnOf(self)] # <<>>
                              /\ IF kind[(Head(toSrv[ConnOf(self)]))[1]] = "once"
                                    THEN /\ IF ran[(Head(toSrv[ConnOf(self)]))[1]] > 0
                                               THEN /\ viol' = (viol \cup {"RanTwice"})
                                               ELSE /\ TRUE
                                                    /\ viol' = viol
                                         /\ ran' = [ran EXCEPT ![(Head(toSrv[ConnOf(self)]))[1]] = ran[(Head(toSrv[ConnOf(self)]))[1]] + 1]
                                    ELSE /\ TRUE
                                         /\ UNCHANGED << ran, viol >>
                              /\ toSrv' = [toSrv EXCEPT ![ConnOf(self)] = Tail(toSrv[ConnOf(self)])]
                              /\ UNCHANGED <<sopen, toCli, rst>>
                           \/ /\ Closes /\ ~good /\ sopen[ConnOf(self)]
                              /\ \E e \in IF toSrv[ConnOf(self)] # <<>> THEN BOOLEAN
                                          ELSE {FALSE}:
                                   rst' = [rst EXCEPT ![ConnOf(self)] = e]
                              /\ sopen' = [sopen EXCEPT ![ConnOf(self)] = FALSE]
                              /\ toSrv' = [toSrv EXCEPT ![ConnOf(self)] = <<>>]
                              /\ UNCHANGED <<toCli, ran, viol>>
                        /\ pc' = [pc EXCEPT ![self] = "sv0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << sopen, toSrv, toCli, rst, ran, viol >>
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, wtr, wantW, cfd, up, restarts, good, 
                             held, kind, intr, dl, gr, ivr, cres, dead, bit, 
                             sent, sg, stack, gi, node, once, rounds, resets, 
                             sl, wr, r, calls, n, done, tries, res, fc, inUse >>

sv(self) == sv0(self)

en0 == /\ pc["env"] = "en0"
       /\ IF ~AllDone
             THEN /\ \/ /\ restarts < MaxRestarts /\ ~good /\ up
                        /\ restarts' = restarts + 1
                        /\ up' = FALSE
                        /\ \E e \in [Conns -> BOOLEAN]:
                             rst' = [c \in Conns |-> rst[c] \/ (toSrv[c] # <<>> /\ e[c])]
                        /\ sopen' = [c \in Conns |-> FALSE]
                        /\ toSrv' = [c \in Conns |-> <<>>]
                        /\ UNCHANGED <<good, intr, dl>>
                     \/ /\ ~up
                        /\ up' = TRUE
                        /\ UNCHANGED <<sopen, toSrv, rst, restarts, good, intr, dl>>
                     \/ /\ Interrupts /\ ~good
                        /\ \E t \in {x \in Threads : kind[x] # "none" /\ ~intr[x]}:
                             intr' = [intr EXCEPT ![t] = TRUE]
                        /\ UNCHANGED <<sopen, toSrv, rst, up, restarts, good, dl>>
                     \/ /\ ~good
                        /\ \E t \in {x \in Threads : kind[x] = "timeout" /\ ~dl[x]}:
                             dl' = [dl EXCEPT ![t] = TRUE]
                        /\ UNCHANGED <<sopen, toSrv, rst, up, restarts, good, intr>>
                     \/ /\ Heal /\ ~good
                        /\ good' = TRUE
                        /\ up' = TRUE
                        /\ UNCHANGED <<sopen, toSrv, rst, restarts, intr, dl>>
                  /\ pc' = [pc EXCEPT !["env"] = "en0"]
             ELSE /\ pc' = [pc EXCEPT !["env"] = "Done"]
                  /\ UNCHANGED << sopen, toSrv, rst, up, restarts, good, intr, 
                                  dl >>
       /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, freed, 
                       rdrs, wtr, wantW, cfd, toCli, held, kind, gr, ivr, cres, 
                       dead, bit, sent, ran, sg, viol, stack, gi, node, once, 
                       rounds, resets, sl, wr, r, calls, n, done, tries, res, 
                       fc, inUse >>

en == en0

hg0(self) == /\ pc[self] = "hg0"
             /\ ref[1] \in Free
             /\ ref' = [ref EXCEPT ![1] = self]
             /\ pc' = [pc EXCEPT ![self] = "hg1"]
             /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

hg1(self) == /\ pc[self] = "hg1"
             /\ FALSE
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                             rst, up, restarts, good, held, kind, intr, dl, gr, 
                             ivr, cres, dead, bit, sent, ran, sg, viol, stack, 
                             gi, node, once, rounds, resets, sl, wr, r, calls, 
                             n, done, tries, res, fc, inUse >>

hg(self) == hg0(self) \/ hg1(self)

fi0(self) == /\ pc[self] = "fi0"
             /\ wantW' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "fi1"]
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, wtr, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

fi1(self) == /\ pc[self] = "fi1"
             /\ wtr = NoProc /\ rdrs = {}
             /\ wtr' = self
             /\ wantW' = FALSE
             /\ pc' = [pc EXCEPT ![self] = "fi2"]
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, cfd, sopen, toSrv, toCli, rst, up, 
                             restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

fi2(self) == /\ pc[self] = "fi2"
             /\ published' = FALSE
             /\ wtr' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "fi3"]
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, freed, rdrs, 
                             wantW, cfd, sopen, toSrv, toCli, rst, up, 
                             restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

fi3(self) == /\ pc[self] = "fi3"
             /\ IF fc[self] <= NC
                   THEN /\ cstate' = [cstate EXCEPT ![fc[self]] = "term"]
                        /\ fc' = [fc EXCEPT ![self] = fc[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "fi3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "fi4"]
                        /\ UNCHANGED << cstate, fc >>
             /\ UNCHANGED << ref, lk, waiters, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, inUse >>

fi4(self) == /\ pc[self] = "fi4"
             /\ fc' = [fc EXCEPT ![self] = 1]
             /\ pc' = [pc EXCEPT ![self] = "fi5"]
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             freed, rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, 
                             rst, up, restarts, good, held, kind, intr, dl, gr, 
                             ivr, cres, dead, bit, sent, ran, sg, viol, stack, 
                             gi, node, once, rounds, resets, sl, wr, r, calls, 
                             n, done, tries, res, inUse >>

fi5(self) == /\ pc[self] = "fi5"
             /\ IF fc[self] <= NC
                   THEN /\ \/ /\ ref[fc[self]] \in Free
                              /\ ref' = [ref EXCEPT ![fc[self]] = self]
                              /\ pc' = [pc EXCEPT ![self] = "fi6"]
                              /\ UNCHANGED <<fc, inUse>>
                           \/ /\ ref[fc[self]] \notin Free
                              /\ inUse' = [inUse EXCEPT ![self] = TRUE]
                              /\ fc' = [fc EXCEPT ![self] = fc[self] + 1]
                              /\ pc' = [pc EXCEPT ![self] = "fi5"]
                              /\ ref' = ref
                   ELSE /\ pc' = [pc EXCEPT ![self] = "fi8"]
                        /\ UNCHANGED << ref, fc, inUse >>
             /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res >>

fi6(self) == /\ pc[self] = "fi6"
             /\ ref' = [ref EXCEPT ![fc[self]] = NoProc]
             /\ pc' = [pc EXCEPT ![self] = "fi7"]
             /\ UNCHANGED << lk, waiters, cstate, destroyed, published, freed, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

fi7(self) == /\ pc[self] = "fi7"
             /\ \/ /\ waiters[fc[self]] = 0 /\ lk[fc[self]] \in Free
                   /\ destroyed' = [destroyed EXCEPT ![fc[self]] = TRUE]
                   /\ cfd' = [cfd EXCEPT ![fc[self]] = FALSE]
                   /\ sopen' = [sopen EXCEPT ![fc[self]] = FALSE]
                   /\ toSrv' = [toSrv EXCEPT ![fc[self]] = <<>>]
                   /\ toCli' = [toCli EXCEPT ![fc[self]] = <<>>]
                   /\ rst' = [rst EXCEPT ![fc[self]] = FALSE]
                   /\ inUse' = inUse
                \/ /\ waiters[fc[self]] > 0
                   /\ inUse' = [inUse EXCEPT ![self] = TRUE]
                   /\ UNCHANGED <<destroyed, cfd, sopen, toSrv, toCli, rst>>
             /\ fc' = [fc EXCEPT ![self] = fc[self] + 1]
             /\ pc' = [pc EXCEPT ![self] = "fi5"]
             /\ UNCHANGED << ref, lk, waiters, cstate, published, freed, rdrs, 
                             wtr, wantW, up, restarts, good, held, kind, intr, 
                             dl, gr, ivr, cres, dead, bit, sent, ran, sg, viol, 
                             stack, gi, node, once, rounds, resets, sl, wr, r, 
                             calls, n, done, tries, res >>

fi8(self) == /\ pc[self] = "fi8"
             /\ IF ~inUse[self]
                   THEN /\ freed' = TRUE
                   ELSE /\ TRUE
                        /\ freed' = freed
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << ref, lk, waiters, cstate, destroyed, published, 
                             rdrs, wtr, wantW, cfd, sopen, toSrv, toCli, rst, 
                             up, restarts, good, held, kind, intr, dl, gr, ivr, 
                             cres, dead, bit, sent, ran, sg, viol, stack, gi, 
                             node, once, rounds, resets, sl, wr, r, calls, n, 
                             done, tries, res, fc, inUse >>

fi(self) == fi0(self) \/ fi1(self) \/ fi2(self) \/ fi3(self) \/ fi4(self)
               \/ fi5(self) \/ fi6(self) \/ fi7(self) \/ fi8(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == en
           \/ (\E self \in ProcSet: getService(self) \/ invoke(self))
           \/ (\E self \in Threads: cl(self))
           \/ (\E self \in SrvProcs: sv(self))
           \/ (\E self \in HogProcs: hg(self))
           \/ (\E self \in FiniProcs: fi(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Threads : SF_vars(cl(self)) /\ SF_vars(getService(self)) /\ SF_vars(invoke(self))
        /\ \A self \in SrvProcs : WF_vars(sv(self))
        /\ WF_vars(en)
        /\ \A self \in FiniProcs : WF_vars(fi(self))

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

InvokeLabels == {"iv2", "rh", "ivR", "ivOut"}
Live == Threads \ dead

TypeOK ==
    /\ ref \in [Conns -> Threads \cup FiniProcs \cup HogProcs \cup {NoProc}]
    /\ lk \in [Conns -> Threads \cup {NoProc}]
    /\ held \in [Threads -> 0..NC]
    /\ waiters \in [Conns -> 0..Cardinality(Threads)]
    /\ \A c \in Conns : Len(toSrv[c]) + Len(toCli[c]) <= 2

\* A call takes the response to its own request or none: never another
\* thread's, never a late one of a request given up on.
ResponseMatch == "Mismatch" \notin viol

\* A socket is used by one thread at a time: the one that checked the
\* connection out and holds its lock.
ExclusiveUse ==
    /\ \A t \in Live :
           pc[t] \in InvokeLabels =>
               held[t] # 0 /\ ref[held[t]] = t /\ lk[held[t]] = t
    /\ \A t1, t2 \in Live : t1 # t2 /\ held[t1] # 0 => held[t1] # held[t2]

\* write() and read() only on an open fd
NoUseAfterClose ==
    \A t \in Live : pc[t] \in {"iv2", "rh"} => cfd[held[t]]

\* Between calls a thread holds no connection and no lock.
NoLockLeak ==
    \A t \in Live :
        pc[t] \in {"c0", "Done"} =>
            /\ held[t] = 0
            /\ \A c \in Conns : ref[c] # t /\ lk[c] # t
            /\ t \notin rdrs

\* No connection is used, nor waited for, once it is torn down, and no
\* getter reads the array once it is freed.
NoUseAfterFini ==
    \A t \in Live :
        /\ held[t] # 0 => ~destroyed[held[t]]
        /\ pc[t] \in {"gs4", "gs5", "gs6"} => ~destroyed[node[t]]
        /\ pc[t] = "gs2" => ~freed

\* A call that blocks for seeding never returns -EAGAIN, and only a call
\* that blocks waits between requests.
BlockingNoEagain == "BlockingEagain" \notin viol
NoblockNoWait ==
    \A t \in Threads : pc[t] = "c5" => kind[t] \in {"full", "timeout"}

\* A request whose effect adds up is written once per call, esdm_invoke()
\* included, and the server runs it once at most.
SentOnce == "SentTwice" \notin viol
RanOnce == "RanTwice" \notin viol

\* A _full_timeout call past its deadline is never left waiting for a
\* connection that another caller keeps.
DeadlineNoWait ==
    \A t \in Threads :
        pc[t] = "gs4" /\ kind[t] = "timeout" /\ dl[t] => ENABLED gs4(t)

\* A call made once the environment is good succeeds, whatever sockets
\* and locks the bad time left behind: a restart or a dropped connection
\* is recovered.
GoodCallsSucceed == "GoodFailed" \notin viol

-----------------------------------------------------------------------------
(* Liveness *)

Idle(t) == pc[t] \in {"c0", "Done"}

\* Every call returns, once the server answers with data for good.
CallsReturn == <>[]good => \A t \in Threads : [](~Idle(t) => <>Idle(t))

\* A _full_timeout call returns once its deadline passed, whatever the
\* server does and however long other callers hold the connections.
DeadlineReturns ==
    \A t \in Threads :
        [](kind[t] = "timeout" /\ dl[t] => <>(kind[t] # "timeout"))
=============================================================================
