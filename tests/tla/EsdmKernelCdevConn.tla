------------------------- MODULE EsdmKernelCdevConn -------------------------
(***************************************************************************)
(* The connections of the kernel module esdm_cdev to the ESDM:             *)
(* esdm_cdev_invoke() of kernel/esdm_cdev/esdm_cdev_egd.c with the pool of *)
(* ESDM_CDEV_CONNS connections (esdm_cdev_conn_get/put, the exclusive wait *)
(* queue), the connect on the workqueue with its completion and reference  *)
(* count, the back-off, and the ESDM restarting. One step is one lock or   *)
(* wait queue operation, one socket call or one atomic access; the labels  *)
(* name the C functions they come from.                                    *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - A socket is the state of one connection: the module's end, the        *)
(*   ESDM's end, the requests the ESDM has not read and the answers the    *)
(*   module has not read. sock_release() discards all of it, so a late     *)
(*   answer never reaches the next socket. A request is the tag            *)
(*   <<client, bit>>, the bit flipped per request, which the ESDM echoes:  *)
(*   EGD has no tags, answers are matched by order, which the tags check.  *)
(* - The ESDM reads a request and answers it in one step. Until the        *)
(*   environment turns good it restarts (closing every connection and      *)
(*   refusing connects while down), closes single connections, possibly    *)
(*   after carrying out the request it read, and any wait may time out;    *)
(*   once good it answers every request and closes nothing. Signals come   *)
(*   only before that, and a request of a privileged command ("priv")      *)
(*   waits for its answer despite them (esdm_cdev_recv_committed()). The   *)
(*   stops, closes and timeouts are MaxFaults in all.                      *)
(* - Time: the back-off is a flag the passing of time clears; the timeouts *)
(*   of a transfer, a connect and the wait for a connection fire only      *)
(*   before the environment is good.                                       *)
(* - A connect work is one of MaxWorks slots, run by a worker of its own;  *)
(*   the connect and complete() are one step. With InitConn the            *)
(*   connections start out connected, for the configurations about the    *)
(*   pool alone.                                                           *)
(* - Each client makes MaxCalls calls of one kind, "read" (the bulk read,  *)
(*   the state, the status) or "priv", and repeats a call that failed, as  *)
(*   a blocking read does, but not one a signal ended, which returns to    *)
(*   user space; a request goes out in one send.                           *)
(*   Not modelled: answers that do not fit (-EPROTO, a closed connection   *)
(*   as well), partial sends, fatal signals, module unload.                *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Clients,     \* tasks calling esdm_cdev_invoke()
    PrivClients, \* ... those sending a privileged command
    NC,          \* connections, ESDM_CDEV_CONNS
    MaxWorks,    \* connect works allocated at a time
    MaxCalls,    \* calls per client
    MaxSig,      \* signals in all
    MaxFaults,   \* stops, closes and timeouts in all
    Liveness,    \* the environment eventually turns good
    InitConn,    \* the connections start out connected
    PassOn       \* a wakeup taken by a waiter that leaves is passed on
                 \* (the code)

Conns == 1..NC
Works == {<<"w1", "w2", "w3", "w4">>[i] : i \in 1..MaxWorks}
NoProc == "none"
Kind(t) == IF t \in PrivClients THEN "priv" ELSE "read"
\* the first free connection from the one at s on, as esdm_cdev_conn_try()
Order(s) == [i \in 1..NC |-> ((s + i - 2) % NC) + 1]
RemoveAt(q, i) == SubSeq(q, 1, i - 1) \o SubSeq(q, i + 1, Len(q))
InQ(q, t) == \E i \in 1..Len(q) : q[i] = t

(* --algorithm EsdmKernelCdevConn {
variables
    \* the pool
    lk = [c \in Conns |-> NoProc],        \* conn->lock
    held = [t \in Clients |-> 0],         \* the connection a client got
    cq = <<>>,                            \* esdm_cdev_conn_wait, exclusive
    cst = [t \in Clients |-> "run"],      \* TASK_RUNNING or INTERRUPTIBLE
    \* the socket of each connection
    sk = [c \in Conns |-> InitConn],      \* conn->sock != NULL
    sopen = [c \in Conns |-> InitConn],   \* the ESDM's end is open
    toSrv = [c \in Conns |-> <<>>],
    toCli = [c \in Conns |-> <<>>],
    \* the connect works
    wSt = [w \in Works |-> "free"],       \* "free", "queued", "done"
    wRef = [w \in Works |-> 0],           \* c->ref
    wSock = [w \in Works |-> FALSE],      \* c->sock
    wOpen = [w \in Works |-> FALSE],      \* ... the ESDM's end open
    wOk = [w \in Works |-> FALSE],        \* c->ret == 0
    \* the back-off: esdm_cdev_backoff_ms set, esdm_cdev_retry_at ahead
    boff = FALSE,
    boffT = FALSE,
    \* the ESDM and the environment
    up = TRUE,
    good = FALSE,
    sig = [t \in Clients |-> FALSE],
    nsig = 0,
    faults = 0,
    \* the error of esdm_cdev_conn_get()
    gerr = [t \in Clients |-> "none"],
    \* ghosts: request bit, executions of the current privileged request,
    \* violations
    bit = [t \in Clients |-> 0],
    exec = [t \in Clients |-> 0],
    viol = {};

define {
    FreeConn(s) == {i \in 1..NC : lk[Order(s)[i]] = NoProc}
    FirstFree(s) == Order(s)[CHOOSE i \in FreeConn(s) :
                                 \A j \in FreeConn(s) : i <= j]
    \* the first queued waiter a wakeup finds sleeping
    Sleepers == {i \in 1..Len(cq) : cst[cq[i]] = "intr"}
}

\* wake_up(&esdm_cdev_conn_wait): one exclusive waiter, autoremoved;
\* try_to_wake_up() skips one that runs
macro wakeOne() {
    if (Sleepers # {}) {
        with (i = CHOOSE i \in Sleepers : \A j \in Sleepers : i <= j) {
            cst[cq[i]] := "run";
            cq := RemoveAt(cq, i);
        };
    };
}

\* sock_release() of conn->sock, esdm_cdev_conn_drop()
macro dropSock(c) {
    sk[c] := FALSE;
    sopen[c] := FALSE;
    toSrv[c] := <<>>;
    toCli[c] := <<>>;
}

\* esdm_cdev_conn_get(); held[self] the connection, or 0 and gerr
procedure connGet()
    variables st = 1, tmo = FALSE;
{
g0: with (s \in Conns) {
        if (FreeConn(s) # {}) {
            lk[FirstFree(s)] := self;
            held[self] := FirstFree(s);
            return;
        } else {
            st := s;
        };
    };
    \* prepare_to_wait_exclusive()
g1: if (~InQ(cq, self)) cq := Append(cq, self);
    cst[self] := "intr";
    \* esdm_cdev_conn_try(), the time left, the signal
g2: if (FreeConn(st) # {}) {
        lk[FirstFree(st)] := self;
        held[self] := FirstFree(st);
        goto g4;
    } else if (tmo) {
        gerr[self] := "etimedout";
        goto g4;
    } else if (sig[self]) {
        gerr[self] := "erestartsys";
        goto g4;
    };
    \* schedule_timeout(): woken, signalled, or the time is up
g3: either {
        await cst[self] = "run";
    } or {
        \* process_timeout() wakes the task, the entry stays queued
        await ~good /\ faults < MaxFaults;
        faults := faults + 1;
        cst[self] := "run";
        tmo := TRUE;
    };
    goto g1;
    \* TASK_RUNNING; a wakeup taken is passed on, else the entry removed
g4: cst[self] := "run";
g6: if (~InQ(cq, self)) {
        if (PassOn) wakeOne();
    } else {
        with (i = CHOOSE i \in 1..Len(cq) : cq[i] = self)
            cq := RemoveAt(cq, i);
    };
    return;
}

\* a task in esdm_cdev_invoke(), one per call
fair process (cl \in Clients)
    variables nc = 0, att = 0, myw = "none", r = "none", ret = "none",
              sent = FALSE;
{
c0: while (nc < MaxCalls) {
        exec[self] := 0;
        call connGet();
c1:     if (held[self] = 0) {
            ret := gerr[self];
            goto cR;
        };
        \* esdm_cdev_conn_connect(): the socket, or the back-off, or a
        \* connect queued on the workqueue
c2:     if (sk[held[self]]) {
            goto c5;
        } else if (boff /\ boffT) {
            ret := "enotconn";
            goto c9;
        } else {
            with (w \in {x \in Works : wSt[x] = "free"}) {
                wSt[w] := "queued";
                wRef[w] := 2;
                wSock[w] := FALSE;
                wOpen[w] := FALSE;
                wOk[w] := FALSE;
                myw := w;
            };
        };
        \* wait_for_completion_interruptible_timeout()
c3:     either {
            await wSt[myw] = "done";
            if (wOk[myw]) {
                sk[held[self]] := TRUE;
                sopen[held[self]] := wOpen[myw];
                toSrv[held[self]] := <<>>;
                toCli[held[self]] := <<>>;
                wSock[myw] := FALSE;
                r := "ok";
            } else {
                r := "err";
            };
        } or {
            await ~good /\ faults < MaxFaults;
            faults := faults + 1;
            r := "etimedout";
        } or {
            await sig[self];
            r := "erestartsys";
        };
        \* esdm_cdev_connect_put()
c4:     with (o = wRef[myw]) {
            wRef[myw] := o - 1;
            if (o = 1) {
                wSt[myw] := "free";
                wSock[myw] := FALSE;
            };
        };
        myw := "none";
        if (r = "erestartsys") {
            ret := r;
            goto c9;
        } else if (r # "ok") {
            \* esdm_cdev_backoff(true)
            boff := TRUE;
            boffT := TRUE;
            ret := "enotconn";
            goto c9;
        };
        \* the request goes out: a closed end is -EPIPE, nothing sent
c5:     if (~sopen[held[self]]) {
            r := "epipe";
            goto c7;
        } else {
            with (b = 1 - bit[self]) {
                bit[self] := b;
                toSrv[held[self]] := Append(toSrv[held[self]],
                                            <<self, b, Kind(self)>>);
            };
            sent := TRUE;
        };
        \* the answer: data, EOF, the timeout, a signal unless committed
c6:     either {
            await toCli[held[self]] # <<>>;
            if (Head(toCli[held[self]]) # <<self, bit[self]>>)
                viol := viol \cup {"Mismatch"};
            toCli[held[self]] := Tail(toCli[held[self]]);
            r := "ok";
        } or {
            await toCli[held[self]] = <<>> /\ ~sopen[held[self]];
            r := "econnreset";
        } or {
            await toCli[held[self]] = <<>> /\ ~good /\ faults < MaxFaults;
            faults := faults + 1;
            r := "etimedout";
        } or {
            await toCli[held[self]] = <<>> /\ sig[self]
                  /\ Kind(self) = "read";
            r := "erestartsys";
        };
        \* esdm_cdev_invoke(): done, or the stream is lost
c7:     if (r = "ok") {
            boff := FALSE;
            ret := "ok";
            goto c9;
        } else if (Kind(self) = "priv" /\ sent) {
            \* gone out: never again
            dropSock(held[self]);
            boff := TRUE;
            boffT := TRUE;
            ret := r;
            goto c9;
        } else {
            with (intr = r = "erestartsys" \/ sig[self],
                  again = att = 0 /\ ~intr /\ r \in {"econnreset", "epipe"}) {
                dropSock(held[self]);
                if (~intr /\ ~again) {
                    boff := TRUE;
                    boffT := TRUE;
                };
                if (intr) {
                    ret := "erestartsys";
                    goto c9;
                } else if (~again) {
                    ret := r;
                    goto c9;
                } else {
                    att := 1;
                    sent := FALSE;
                    goto c2;
                };
            };
        };
        \* esdm_cdev_conn_put(): unlock, then wake one
c9:     lk[held[self]] := NoProc;
        held[self] := 0;
c10:    wakeOne();
        \* the call returns, and is repeated unless it succeeded
cR:     if (exec[self] > 1) viol := viol \cup {"Twice"};
        if (ret \in {"ok", "erestartsys"}) nc := nc + 1;
        sig[self] := FALSE;
        gerr[self] := "none";
        att := 0;
        r := "none";
        ret := "none";
        sent := FALSE;
    };
}

\* esdm_cdev_connect_work() on the workqueue
fair process (wk \in Works)
{
k0: while (TRUE) {
        \* esdm_cdev_connect_init(), complete()
        await wSt[self] = "queued";
        if (up) {
            wSock[self] := TRUE;
            wOpen[self] := TRUE;
            wOk[self] := TRUE;
        };
        wSt[self] := "done";
        \* esdm_cdev_connect_put()
k1:     with (o = wRef[self]) {
            wRef[self] := o - 1;
            if (o = 1) {
                wSt[self] := "free";
                wSock[self] := FALSE;
            };
        };
    };
}

\* the ESDM's EGD interface
fair process (sv \in {"esdm"})
{
s0: while (TRUE) {
        either {
            \* reads a request, carries it out, answers
            with (c \in {x \in Conns : up /\ sopen[x] /\ toSrv[x] # <<>>},
                  q = Head(toSrv[c])) {
                toCli[c] := Append(toCli[c], <<q[1], q[2]>>);
                toSrv[c] := Tail(toSrv[c]);
                if (q[3] = "priv") exec[q[1]] := exec[q[1]] + 1;
            };
        } or {
            \* stops: every connection closed, connects refused
            await ~good /\ up /\ faults < MaxFaults;
            faults := faults + 1;
            up := FALSE;
            sopen := [c \in Conns |-> FALSE];
            toSrv := [c \in Conns |-> <<>>];
            wOpen := [w \in Works |-> FALSE];
        } or {
            await ~good /\ ~up;
            up := TRUE;
        } or {
            \* closes a connection, after carrying out what it read or not
            await ~good /\ faults < MaxFaults;
            faults := faults + 1;
            with (c \in {x \in Conns : sopen[x]},
                  ex \in IF toSrv[c] # <<>> /\ Head(toSrv[c])[3] = "priv"
                         THEN BOOLEAN ELSE {FALSE}) {
                if (ex)
                    exec[Head(toSrv[c])[1]] := exec[Head(toSrv[c])[1]] + 1;
                sopen[c] := FALSE;
                toSrv[c] := <<>>;
            };
        };
    };
}

\* time and signals
fair process (en \in {"env"})
{
e0: while (TRUE) {
        either {
            \* esdm_cdev_retry_at passes
            await boffT;
            boffT := FALSE;
        } or {
            \* a signal, waking an interruptible sleeper
            await ~good /\ nsig < MaxSig;
            with (t \in {x \in Clients : pc[x] # "c0" /\ pc[x] # "Done"
                                         /\ ~sig[x]}) {
                sig[t] := TRUE;
                if (cst[t] = "intr") cst[t] := "run";
            };
            nsig := nsig + 1;
        } or {
            await Liveness /\ ~good;
            good := TRUE;
            up := TRUE;
        };
    };
}

} *)
\* BEGIN TRANSLATION
VARIABLES lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, wOpen, 
          wOk, boff, boffT, up, good, sig, nsig, faults, gerr, bit, exec, 
          viol, pc, stack

(* define statement *)
FreeConn(s) == {i \in 1..NC : lk[Order(s)[i]] = NoProc}
FirstFree(s) == Order(s)[CHOOSE i \in FreeConn(s) :
                             \A j \in FreeConn(s) : i <= j]

Sleepers == {i \in 1..Len(cq) : cst[cq[i]] = "intr"}

VARIABLES st, tmo, nc, att, myw, r, ret, sent

vars == << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
           wOpen, wOk, boff, boffT, up, good, sig, nsig, faults, gerr, bit, 
           exec, viol, pc, stack, st, tmo, nc, att, myw, r, ret, sent >>

ProcSet == (Clients) \cup (Works) \cup ({"esdm"}) \cup ({"env"})

Init == (* Global variables *)
        /\ lk = [c \in Conns |-> NoProc]
        /\ held = [t \in Clients |-> 0]
        /\ cq = <<>>
        /\ cst = [t \in Clients |-> "run"]
        /\ sk = [c \in Conns |-> InitConn]
        /\ sopen = [c \in Conns |-> InitConn]
        /\ toSrv = [c \in Conns |-> <<>>]
        /\ toCli = [c \in Conns |-> <<>>]
        /\ wSt = [w \in Works |-> "free"]
        /\ wRef = [w \in Works |-> 0]
        /\ wSock = [w \in Works |-> FALSE]
        /\ wOpen = [w \in Works |-> FALSE]
        /\ wOk = [w \in Works |-> FALSE]
        /\ boff = FALSE
        /\ boffT = FALSE
        /\ up = TRUE
        /\ good = FALSE
        /\ sig = [t \in Clients |-> FALSE]
        /\ nsig = 0
        /\ faults = 0
        /\ gerr = [t \in Clients |-> "none"]
        /\ bit = [t \in Clients |-> 0]
        /\ exec = [t \in Clients |-> 0]
        /\ viol = {}
        (* Procedure connGet *)
        /\ st = [ self \in ProcSet |-> 1]
        /\ tmo = [ self \in ProcSet |-> FALSE]
        (* Process cl *)
        /\ nc = [self \in Clients |-> 0]
        /\ att = [self \in Clients |-> 0]
        /\ myw = [self \in Clients |-> "none"]
        /\ r = [self \in Clients |-> "none"]
        /\ ret = [self \in Clients |-> "none"]
        /\ sent = [self \in Clients |-> FALSE]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Clients -> "c0"
                                        [] self \in Works -> "k0"
                                        [] self \in {"esdm"} -> "s0"
                                        [] self \in {"env"} -> "e0"]

g0(self) == /\ pc[self] = "g0"
            /\ \E s \in Conns:
                 IF FreeConn(s) # {}
                    THEN /\ lk' = [lk EXCEPT ![FirstFree(s)] = self]
                         /\ held' = [held EXCEPT ![self] = FirstFree(s)]
                         /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                         /\ st' = [st EXCEPT ![self] = Head(stack[self]).st]
                         /\ tmo' = [tmo EXCEPT ![self] = Head(stack[self]).tmo]
                         /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                    ELSE /\ st' = [st EXCEPT ![self] = s]
                         /\ pc' = [pc EXCEPT ![self] = "g1"]
                         /\ UNCHANGED << lk, held, stack, tmo >>
            /\ UNCHANGED << cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
                            wOpen, wOk, boff, boffT, up, good, sig, nsig, 
                            faults, gerr, bit, exec, viol, nc, att, myw, r, 
                            ret, sent >>

g1(self) == /\ pc[self] = "g1"
            /\ IF ~InQ(cq, self)
                  THEN /\ cq' = Append(cq, self)
                  ELSE /\ TRUE
                       /\ cq' = cq
            /\ cst' = [cst EXCEPT ![self] = "intr"]
            /\ pc' = [pc EXCEPT ![self] = "g2"]
            /\ UNCHANGED << lk, held, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, gerr, bit, exec, viol, stack, st, 
                            tmo, nc, att, myw, r, ret, sent >>

g2(self) == /\ pc[self] = "g2"
            /\ IF FreeConn(st[self]) # {}
                  THEN /\ lk' = [lk EXCEPT ![FirstFree(st[self])] = self]
                       /\ held' = [held EXCEPT ![self] = FirstFree(st[self])]
                       /\ pc' = [pc EXCEPT ![self] = "g4"]
                       /\ gerr' = gerr
                  ELSE /\ IF tmo[self]
                             THEN /\ gerr' = [gerr EXCEPT ![self] = "etimedout"]
                                  /\ pc' = [pc EXCEPT ![self] = "g4"]
                             ELSE /\ IF sig[self]
                                        THEN /\ gerr' = [gerr EXCEPT ![self] = "erestartsys"]
                                             /\ pc' = [pc EXCEPT ![self] = "g4"]
                                        ELSE /\ pc' = [pc EXCEPT ![self] = "g3"]
                                             /\ gerr' = gerr
                       /\ UNCHANGED << lk, held >>
            /\ UNCHANGED << cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
                            wOpen, wOk, boff, boffT, up, good, sig, nsig, 
                            faults, bit, exec, viol, stack, st, tmo, nc, att, 
                            myw, r, ret, sent >>

g3(self) == /\ pc[self] = "g3"
            /\ \/ /\ cst[self] = "run"
                  /\ UNCHANGED <<cst, faults, tmo>>
               \/ /\ ~good /\ faults < MaxFaults
                  /\ faults' = faults + 1
                  /\ cst' = [cst EXCEPT ![self] = "run"]
                  /\ tmo' = [tmo EXCEPT ![self] = TRUE]
            /\ pc' = [pc EXCEPT ![self] = "g1"]
            /\ UNCHANGED << lk, held, cq, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, gerr, bit, exec, viol, stack, st, nc, att, 
                            myw, r, ret, sent >>

g4(self) == /\ pc[self] = "g4"
            /\ cst' = [cst EXCEPT ![self] = "run"]
            /\ pc' = [pc EXCEPT ![self] = "g6"]
            /\ UNCHANGED << lk, held, cq, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, gerr, bit, exec, viol, stack, st, 
                            tmo, nc, att, myw, r, ret, sent >>

g6(self) == /\ pc[self] = "g6"
            /\ IF ~InQ(cq, self)
                  THEN /\ IF PassOn
                             THEN /\ IF Sleepers # {}
                                        THEN /\ LET i == CHOOSE i \in Sleepers : \A j \in Sleepers : i <= j IN
                                                  /\ cst' = [cst EXCEPT ![cq[i]] = "run"]
                                                  /\ cq' = RemoveAt(cq, i)
                                        ELSE /\ TRUE
                                             /\ UNCHANGED << cq, cst >>
                             ELSE /\ TRUE
                                  /\ UNCHANGED << cq, cst >>
                  ELSE /\ LET i == CHOOSE i \in 1..Len(cq) : cq[i] = self IN
                            cq' = RemoveAt(cq, i)
                       /\ cst' = cst
            /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
            /\ st' = [st EXCEPT ![self] = Head(stack[self]).st]
            /\ tmo' = [tmo EXCEPT ![self] = Head(stack[self]).tmo]
            /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << lk, held, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, gerr, bit, exec, viol, nc, att, myw, 
                            r, ret, sent >>

connGet(self) == g0(self) \/ g1(self) \/ g2(self) \/ g3(self) \/ g4(self)
                    \/ g6(self)

c0(self) == /\ pc[self] = "c0"
            /\ IF nc[self] < MaxCalls
                  THEN /\ exec' = [exec EXCEPT ![self] = 0]
                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "connGet",
                                                                pc        |->  "c1",
                                                                st        |->  st[self],
                                                                tmo       |->  tmo[self] ] >>
                                                            \o stack[self]]
                       /\ st' = [st EXCEPT ![self] = 1]
                       /\ tmo' = [tmo EXCEPT ![self] = FALSE]
                       /\ pc' = [pc EXCEPT ![self] = "g0"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ UNCHANGED << exec, stack, st, tmo >>
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            sig, nsig, faults, gerr, bit, viol, nc, att, myw, 
                            r, ret, sent >>

c1(self) == /\ pc[self] = "c1"
            /\ IF held[self] = 0
                  THEN /\ ret' = [ret EXCEPT ![self] = gerr[self]]
                       /\ pc' = [pc EXCEPT ![self] = "cR"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "c2"]
                       /\ ret' = ret
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            sig, nsig, faults, gerr, bit, exec, viol, stack, 
                            st, tmo, nc, att, myw, r, sent >>

c2(self) == /\ pc[self] = "c2"
            /\ IF sk[held[self]]
                  THEN /\ pc' = [pc EXCEPT ![self] = "c5"]
                       /\ UNCHANGED << wSt, wRef, wSock, wOpen, wOk, myw, ret >>
                  ELSE /\ IF boff /\ boffT
                             THEN /\ ret' = [ret EXCEPT ![self] = "enotconn"]
                                  /\ pc' = [pc EXCEPT ![self] = "c9"]
                                  /\ UNCHANGED << wSt, wRef, wSock, wOpen, wOk, 
                                                  myw >>
                             ELSE /\ \E w \in {x \in Works : wSt[x] = "free"}:
                                       /\ wSt' = [wSt EXCEPT ![w] = "queued"]
                                       /\ wRef' = [wRef EXCEPT ![w] = 2]
                                       /\ wSock' = [wSock EXCEPT ![w] = FALSE]
                                       /\ wOpen' = [wOpen EXCEPT ![w] = FALSE]
                                       /\ wOk' = [wOk EXCEPT ![w] = FALSE]
                                       /\ myw' = [myw EXCEPT ![self] = w]
                                  /\ pc' = [pc EXCEPT ![self] = "c3"]
                                  /\ ret' = ret
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, boff, 
                            boffT, up, good, sig, nsig, faults, gerr, bit, 
                            exec, viol, stack, st, tmo, nc, att, r, sent >>

c3(self) == /\ pc[self] = "c3"
            /\ \/ /\ wSt[myw[self]] = "done"
                  /\ IF wOk[myw[self]]
                        THEN /\ sk' = [sk EXCEPT ![held[self]] = TRUE]
                             /\ sopen' = [sopen EXCEPT ![held[self]] = wOpen[myw[self]]]
                             /\ toSrv' = [toSrv EXCEPT ![held[self]] = <<>>]
                             /\ toCli' = [toCli EXCEPT ![held[self]] = <<>>]
                             /\ wSock' = [wSock EXCEPT ![myw[self]] = FALSE]
                             /\ r' = [r EXCEPT ![self] = "ok"]
                        ELSE /\ r' = [r EXCEPT ![self] = "err"]
                             /\ UNCHANGED << sk, sopen, toSrv, toCli, wSock >>
                  /\ UNCHANGED faults
               \/ /\ ~good /\ faults < MaxFaults
                  /\ faults' = faults + 1
                  /\ r' = [r EXCEPT ![self] = "etimedout"]
                  /\ UNCHANGED <<sk, sopen, toSrv, toCli, wSock>>
               \/ /\ sig[self]
                  /\ r' = [r EXCEPT ![self] = "erestartsys"]
                  /\ UNCHANGED <<sk, sopen, toSrv, toCli, wSock, faults>>
            /\ pc' = [pc EXCEPT ![self] = "c4"]
            /\ UNCHANGED << lk, held, cq, cst, wSt, wRef, wOpen, wOk, boff, 
                            boffT, up, good, sig, nsig, gerr, bit, exec, viol, 
                            stack, st, tmo, nc, att, myw, ret, sent >>

c4(self) == /\ pc[self] = "c4"
            /\ LET o == wRef[myw[self]] IN
                 /\ wRef' = [wRef EXCEPT ![myw[self]] = o - 1]
                 /\ IF o = 1
                       THEN /\ wSt' = [wSt EXCEPT ![myw[self]] = "free"]
                            /\ wSock' = [wSock EXCEPT ![myw[self]] = FALSE]
                       ELSE /\ TRUE
                            /\ UNCHANGED << wSt, wSock >>
            /\ myw' = [myw EXCEPT ![self] = "none"]
            /\ IF r[self] = "erestartsys"
                  THEN /\ ret' = [ret EXCEPT ![self] = r[self]]
                       /\ pc' = [pc EXCEPT ![self] = "c9"]
                       /\ UNCHANGED << boff, boffT >>
                  ELSE /\ IF r[self] # "ok"
                             THEN /\ boff' = TRUE
                                  /\ boffT' = TRUE
                                  /\ ret' = [ret EXCEPT ![self] = "enotconn"]
                                  /\ pc' = [pc EXCEPT ![self] = "c9"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "c5"]
                                  /\ UNCHANGED << boff, boffT, ret >>
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wOpen, 
                            wOk, up, good, sig, nsig, faults, gerr, bit, exec, 
                            viol, stack, st, tmo, nc, att, r, sent >>

c5(self) == /\ pc[self] = "c5"
            /\ IF ~sopen[held[self]]
                  THEN /\ r' = [r EXCEPT ![self] = "epipe"]
                       /\ pc' = [pc EXCEPT ![self] = "c7"]
                       /\ UNCHANGED << toSrv, bit, sent >>
                  ELSE /\ LET b == 1 - bit[self] IN
                            /\ bit' = [bit EXCEPT ![self] = b]
                            /\ toSrv' = [toSrv EXCEPT ![held[self]] = Append(toSrv[held[self]],
                                                                             <<self, b, Kind(self)>>)]
                       /\ sent' = [sent EXCEPT ![self] = TRUE]
                       /\ pc' = [pc EXCEPT ![self] = "c6"]
                       /\ r' = r
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, gerr, exec, viol, stack, st, tmo, nc, 
                            att, myw, ret >>

c6(self) == /\ pc[self] = "c6"
            /\ \/ /\ toCli[held[self]] # <<>>
                  /\ IF Head(toCli[held[self]]) # <<self, bit[self]>>
                        THEN /\ viol' = (viol \cup {"Mismatch"})
                        ELSE /\ TRUE
                             /\ viol' = viol
                  /\ toCli' = [toCli EXCEPT ![held[self]] = Tail(toCli[held[self]])]
                  /\ r' = [r EXCEPT ![self] = "ok"]
                  /\ UNCHANGED faults
               \/ /\ toCli[held[self]] = <<>> /\ ~sopen[held[self]]
                  /\ r' = [r EXCEPT ![self] = "econnreset"]
                  /\ UNCHANGED <<toCli, faults, viol>>
               \/ /\ toCli[held[self]] = <<>> /\ ~good /\ faults < MaxFaults
                  /\ faults' = faults + 1
                  /\ r' = [r EXCEPT ![self] = "etimedout"]
                  /\ UNCHANGED <<toCli, viol>>
               \/ /\ toCli[held[self]] = <<>> /\ sig[self]
                     /\ Kind(self) = "read"
                  /\ r' = [r EXCEPT ![self] = "erestartsys"]
                  /\ UNCHANGED <<toCli, faults, viol>>
            /\ pc' = [pc EXCEPT ![self] = "c7"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, gerr, bit, exec, stack, st, tmo, nc, att, 
                            myw, ret, sent >>

c7(self) == /\ pc[self] = "c7"
            /\ IF r[self] = "ok"
                  THEN /\ boff' = FALSE
                       /\ ret' = [ret EXCEPT ![self] = "ok"]
                       /\ pc' = [pc EXCEPT ![self] = "c9"]
                       /\ UNCHANGED << sk, sopen, toSrv, toCli, boffT, att, 
                                       sent >>
                  ELSE /\ IF Kind(self) = "priv" /\ sent[self]
                             THEN /\ sk' = [sk EXCEPT ![(held[self])] = FALSE]
                                  /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                  /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                  /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                  /\ boff' = TRUE
                                  /\ boffT' = TRUE
                                  /\ ret' = [ret EXCEPT ![self] = r[self]]
                                  /\ pc' = [pc EXCEPT ![self] = "c9"]
                                  /\ UNCHANGED << att, sent >>
                             ELSE /\ LET intr == r[self] = "erestartsys" \/ sig[self] IN
                                       LET again == att[self] = 0 /\ ~intr /\ r[self] \in {"econnreset", "epipe"} IN
                                         /\ sk' = [sk EXCEPT ![(held[self])] = FALSE]
                                         /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                         /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                         /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                         /\ IF ~intr /\ ~again
                                               THEN /\ boff' = TRUE
                                                    /\ boffT' = TRUE
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED << boff, 
                                                                    boffT >>
                                         /\ IF intr
                                               THEN /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                                                    /\ pc' = [pc EXCEPT ![self] = "c9"]
                                                    /\ UNCHANGED << att, sent >>
                                               ELSE /\ IF ~again
                                                          THEN /\ ret' = [ret EXCEPT ![self] = r[self]]
                                                               /\ pc' = [pc EXCEPT ![self] = "c9"]
                                                               /\ UNCHANGED << att, 
                                                                               sent >>
                                                          ELSE /\ att' = [att EXCEPT ![self] = 1]
                                                               /\ sent' = [sent EXCEPT ![self] = FALSE]
                                                               /\ pc' = [pc EXCEPT ![self] = "c2"]
                                                               /\ ret' = ret
            /\ UNCHANGED << lk, held, cq, cst, wSt, wRef, wSock, wOpen, wOk, 
                            up, good, sig, nsig, faults, gerr, bit, exec, viol, 
                            stack, st, tmo, nc, myw, r >>

c9(self) == /\ pc[self] = "c9"
            /\ lk' = [lk EXCEPT ![held[self]] = NoProc]
            /\ held' = [held EXCEPT ![self] = 0]
            /\ pc' = [pc EXCEPT ![self] = "c10"]
            /\ UNCHANGED << cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
                            wOpen, wOk, boff, boffT, up, good, sig, nsig, 
                            faults, gerr, bit, exec, viol, stack, st, tmo, nc, 
                            att, myw, r, ret, sent >>

c10(self) == /\ pc[self] = "c10"
             /\ IF Sleepers # {}
                   THEN /\ LET i == CHOOSE i \in Sleepers : \A j \in Sleepers : i <= j IN
                             /\ cst' = [cst EXCEPT ![cq[i]] = "run"]
                             /\ cq' = RemoveAt(cq, i)
                   ELSE /\ TRUE
                        /\ UNCHANGED << cq, cst >>
             /\ pc' = [pc EXCEPT ![self] = "cR"]
             /\ UNCHANGED << lk, held, sk, sopen, toSrv, toCli, wSt, wRef, 
                             wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                             nsig, faults, gerr, bit, exec, viol, stack, st, 
                             tmo, nc, att, myw, r, ret, sent >>

cR(self) == /\ pc[self] = "cR"
            /\ IF exec[self] > 1
                  THEN /\ viol' = (viol \cup {"Twice"})
                  ELSE /\ TRUE
                       /\ viol' = viol
            /\ IF ret[self] \in {"ok", "erestartsys"}
                  THEN /\ nc' = [nc EXCEPT ![self] = nc[self] + 1]
                  ELSE /\ TRUE
                       /\ nc' = nc
            /\ sig' = [sig EXCEPT ![self] = FALSE]
            /\ gerr' = [gerr EXCEPT ![self] = "none"]
            /\ att' = [att EXCEPT ![self] = 0]
            /\ r' = [r EXCEPT ![self] = "none"]
            /\ ret' = [ret EXCEPT ![self] = "none"]
            /\ sent' = [sent EXCEPT ![self] = FALSE]
            /\ pc' = [pc EXCEPT ![self] = "c0"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            nsig, faults, bit, exec, stack, st, tmo, myw >>

cl(self) == c0(self) \/ c1(self) \/ c2(self) \/ c3(self) \/ c4(self)
               \/ c5(self) \/ c6(self) \/ c7(self) \/ c9(self) \/ c10(self)
               \/ cR(self)

k0(self) == /\ pc[self] = "k0"
            /\ wSt[self] = "queued"
            /\ IF up
                  THEN /\ wSock' = [wSock EXCEPT ![self] = TRUE]
                       /\ wOpen' = [wOpen EXCEPT ![self] = TRUE]
                       /\ wOk' = [wOk EXCEPT ![self] = TRUE]
                  ELSE /\ TRUE
                       /\ UNCHANGED << wSock, wOpen, wOk >>
            /\ wSt' = [wSt EXCEPT ![self] = "done"]
            /\ pc' = [pc EXCEPT ![self] = "k1"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wRef, 
                            boff, boffT, up, good, sig, nsig, faults, gerr, 
                            bit, exec, viol, stack, st, tmo, nc, att, myw, r, 
                            ret, sent >>

k1(self) == /\ pc[self] = "k1"
            /\ LET o == wRef[self] IN
                 /\ wRef' = [wRef EXCEPT ![self] = o - 1]
                 /\ IF o = 1
                       THEN /\ wSt' = [wSt EXCEPT ![self] = "free"]
                            /\ wSock' = [wSock EXCEPT ![self] = FALSE]
                       ELSE /\ TRUE
                            /\ UNCHANGED << wSt, wSock >>
            /\ pc' = [pc EXCEPT ![self] = "k0"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wOpen, 
                            wOk, boff, boffT, up, good, sig, nsig, faults, 
                            gerr, bit, exec, viol, stack, st, tmo, nc, att, 
                            myw, r, ret, sent >>

wk(self) == k0(self) \/ k1(self)

s0(self) == /\ pc[self] = "s0"
            /\ \/ /\ \E c \in {x \in Conns : up /\ sopen[x] /\ toSrv[x] # <<>>}:
                       LET q == Head(toSrv[c]) IN
                         /\ toCli' = [toCli EXCEPT ![c] = Append(toCli[c], <<q[1], q[2]>>)]
                         /\ toSrv' = [toSrv EXCEPT ![c] = Tail(toSrv[c])]
                         /\ IF q[3] = "priv"
                               THEN /\ exec' = [exec EXCEPT ![q[1]] = exec[q[1]] + 1]
                               ELSE /\ TRUE
                                    /\ exec' = exec
                  /\ UNCHANGED <<sopen, wOpen, up, faults>>
               \/ /\ ~good /\ up /\ faults < MaxFaults
                  /\ faults' = faults + 1
                  /\ up' = FALSE
                  /\ sopen' = [c \in Conns |-> FALSE]
                  /\ toSrv' = [c \in Conns |-> <<>>]
                  /\ wOpen' = [w \in Works |-> FALSE]
                  /\ UNCHANGED <<toCli, exec>>
               \/ /\ ~good /\ ~up
                  /\ up' = TRUE
                  /\ UNCHANGED <<sopen, toSrv, toCli, wOpen, faults, exec>>
               \/ /\ ~good /\ faults < MaxFaults
                  /\ faults' = faults + 1
                  /\ \E c \in {x \in Conns : sopen[x]}:
                       \E ex \in IF toSrv[c] # <<>> /\ Head(toSrv[c])[3] = "priv"
                                 THEN BOOLEAN ELSE {FALSE}:
                         /\ IF ex
                               THEN /\ exec' = [exec EXCEPT ![Head(toSrv[c])[1]] = exec[Head(toSrv[c])[1]] + 1]
                               ELSE /\ TRUE
                                    /\ exec' = exec
                         /\ sopen' = [sopen EXCEPT ![c] = FALSE]
                         /\ toSrv' = [toSrv EXCEPT ![c] = <<>>]
                  /\ UNCHANGED <<toCli, wOpen, up>>
            /\ pc' = [pc EXCEPT ![self] = "s0"]
            /\ UNCHANGED << lk, held, cq, cst, sk, wSt, wRef, wSock, wOk, boff, 
                            boffT, good, sig, nsig, gerr, bit, viol, stack, st, 
                            tmo, nc, att, myw, r, ret, sent >>

sv(self) == s0(self)

e0(self) == /\ pc[self] = "e0"
            /\ \/ /\ boffT
                  /\ boffT' = FALSE
                  /\ UNCHANGED <<cst, up, good, sig, nsig>>
               \/ /\ ~good /\ nsig < MaxSig
                  /\ \E t \in {x \in Clients : pc[x] # "c0" /\ pc[x] # "Done"
                                               /\ ~sig[x]}:
                       /\ sig' = [sig EXCEPT ![t] = TRUE]
                       /\ IF cst[t] = "intr"
                             THEN /\ cst' = [cst EXCEPT ![t] = "run"]
                             ELSE /\ TRUE
                                  /\ cst' = cst
                  /\ nsig' = nsig + 1
                  /\ UNCHANGED <<boffT, up, good>>
               \/ /\ Liveness /\ ~good
                  /\ good' = TRUE
                  /\ up' = TRUE
                  /\ UNCHANGED <<cst, boffT, sig, nsig>>
            /\ pc' = [pc EXCEPT ![self] = "e0"]
            /\ UNCHANGED << lk, held, cq, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, faults, gerr, bit, exec, 
                            viol, stack, st, tmo, nc, att, myw, r, ret, sent >>

en(self) == e0(self)

Next == (\E self \in ProcSet: connGet(self))
           \/ (\E self \in Clients: cl(self))
           \/ (\E self \in Works: wk(self))
           \/ (\E self \in {"esdm"}: sv(self))
           \/ (\E self \in {"env"}: en(self))

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Clients : WF_vars(cl(self)) /\ WF_vars(connGet(self))
        /\ \A self \in Works : WF_vars(wk(self))
        /\ \A self \in {"esdm"} : WF_vars(sv(self))
        /\ \A self \in {"env"} : WF_vars(en(self))

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ lk \in [Conns -> Clients \cup {NoProc}]
    /\ wRef \in [Works -> 0..2]
    /\ Len(cq) <= Cardinality(Clients)

\* Every answer a request reads is the answer to that request: a reader
\* never gets the data of another one, whatever was interrupted, timed out
\* or restarted before.
ResponseMatch == "Mismatch" \notin viol

\* A privileged command is carried out at most once per call: one that went
\* out is never sent again.
SentOnce == "Twice" \notin viol

\* A connection serves one request at a time, the one of its holder.
ExclusiveUse == \A t \in Clients : held[t] # 0 => lk[held[t]] = t

\* The socket of a connect is taken by its waiter or released by the last
\* reference: none is left behind.
NoSockLeak == \A w \in Works : wRef[w] = 0 => ~wSock[w] /\ wSt[w] = "free"

\* Once the ESDM is good, no task sleeps for a connection while nothing but
\* time can happen.
NoStrandedWaiter ==
    good /\ (\E t \in Clients : pc[t] = "g3" /\ cst[t] = "intr")
        => \/ \E t \in Clients : ENABLED (cl(t) \/ connGet(t))
           \/ \E w \in Works : ENABLED wk(w)
           \/ ENABLED sv("esdm")

\* No free connection is left with sleepers (esdm_cdev_conn_get()): a task
\* sleeps for a connection while one is free only while a wakeup is on its
\* way or a task is about to take that connection.
NoSleeperByFreeConn ==
    (\E c \in Conns : lk[c] = NoProc)
    /\ (\E t \in Clients : pc[t] = "g3" /\ cst[t] = "intr")
        => \E q \in Clients : \/ pc[q] \in {"c10", "g0", "g1", "g2", "g4", "g6"}
                              \/ pc[q] = "g3" /\ cst[q] = "run"

-----------------------------------------------------------------------------
(* Liveness, once the environment stays good *)

\* Every call returns.
CallsReturn ==
    <>[]good => \A t \in Clients :
                    [](pc[t] \notin {"c0", "Done"}
                       => <>(pc[t] \in {"c0", "Done"}))

\* Every client gets its answers in the end, but for calls a signal ended:
\* connections closed by a restart of the ESDM are made anew, and the
\* back-off ends.
CallsSucceed == <>[]good => <>(\A t \in Clients : pc[t] = "Done")
=============================================================================
