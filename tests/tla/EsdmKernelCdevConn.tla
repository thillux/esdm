------------------------- MODULE EsdmKernelCdevConn -------------------------
(***************************************************************************)
(* The connections of the kernel module esdm_cdev to the ESDM:             *)
(* esdm_cdev_invoke() of kernel/esdm_cdev/esdm_cdev_egd.c with the pool of *)
(* ESDM_CDEV_CONNS connections (esdm_cdev_conn_get/put, the exclusive wait *)
(* queue), the connect on the workqueue with its completion and reference  *)
(* count, the back-off, and the ESDM restarting. One step is one lock or   *)
(* wait queue operation, one socket call or one atomic access; the labels  *)
(* name the C functions they come from. esdm_cdev_conn_try() is one        *)
(* mutex_trylock() per step, so that with several connections one may be   *)
(* freed behind the scan.                                                  *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - A socket is the state of one connection: the module's end, the        *)
(*   ESDM's end, the requests the ESDM has not read and the answers the    *)
(*   module has not read. sock_release() discards the answers, so a late   *)
(*   answer never reaches the next socket. A request the ESDM has not read *)
(*   by then is discarded as well when it is a read; a privileged command  *)
(*   stays with the ESDM (orph), which may still carry it out: the data    *)
(*   of a closed stream socket stays readable. A request is the tag        *)
(*   <<client, bit, kind>>, the bit flipped per request, of which the ESDM *)
(*   echoes client and bit: EGD has no tags, answers are matched by order, *)
(*   which the tags check.                                                 *)
(* - Sockets are counted (live): one more with each connect that succeeds, *)
(*   one less with each sock_release(). conn->sock and c->sock are flags,  *)
(*   and NoSockLeak compares their number with the count.                  *)
(* - The ESDM reads a request and answers it in one step. Until the        *)
(*   environment turns good it restarts (closing every connection,         *)
(*   forgetting what it has not read and refusing connects while down),    *)
(*   closes single connections, possibly after carrying out the request it *)
(*   read, and any wait may time out; once good it answers every request   *)
(*   and closes nothing. Signals come only before that, and a request of a *)
(*   privileged command ("priv") waits for its answer despite them         *)
(*   (esdm_cdev_recv_committed()). The stops, closes and timeouts are      *)
(*   MaxFaults in all.                                                     *)
(* - Time: the back-off is a flag the passing of time clears; the timeouts *)
(*   of a transfer, a connect and the wait for a connection fire only      *)
(*   before the environment is good.                                       *)
(* - A connect work is one of MaxWorks slots, run by a worker of its own;  *)
(*   the connect and complete() are one step. With no slot free the        *)
(*   allocation fails (-ENOMEM, no back-off), the only way an allocation   *)
(*   failure is modelled. With InitConn the connections start out          *)
(*   connected, for the configurations about the pool alone.               *)
(* - esdm_cdev_conn_next is not modelled: a scan starts at any connection. *)
(* - Each client makes MaxCalls calls of one kind, "read" (the bulk read,  *)
(*   the state, the status) or "priv", and repeats a call that failed, as  *)
(*   a blocking read does. A call a signal ended (-ERESTARTSYS) returns to *)
(*   user space; that of a privileged command may instead be restarted by  *)
(*   the kernel, and is then the same command to the ESDM. A request goes  *)
(*   out in one send.                                                      *)
(* - The model ends when every client made its calls: the environment      *)
(*   then idles (the last alternative of the process en), the only state   *)
(*   from which nothing else can happen. Any other state without a         *)
(*   successor is a deadlock, which every configuration checks for: the    *)
(*   faults, the signals, the restarts and the passing of the back-off are *)
(*   bounded, so no step of the environment hides a task that hangs.       *)
(*   Not modelled: answers that do not fit (-EPROTO, a closed connection   *)
(*   as well), partial sends, fatal signals (-EINTR of a privileged        *)
(*   command), module unload.                                              *)
(*                                                                         *)
(* The constants PassOn, Locked, Drop, Commit, Await, Finish and Release   *)
(* are TRUE for the code; each switches one of its measures off for a      *)
(* configuration that demonstrates a property failing. WakeNext is FALSE   *)
(* for the code: it switches on a measure the code does not have, see      *)
(* NoSleeperByFreeConn.                                                    *)
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
    PassOn,      \* a wakeup taken by a waiter that leaves is passed on
    Locked,      \* a connection is taken with mutex_trylock()
    Drop,        \* the connection of a request that failed is closed
    Commit,      \* a privileged command that went out is not made again
                 \* ("changes" of esdm_cdev_invoke())
    Await,       \* the answer to a privileged command is waited for
                 \* despite signals (esdm_cdev_recv_committed())
    Finish,      \* a waiter that leaves removes its wait queue entry
    Release,     \* the last reference to a connect releases the socket
                 \* nobody took
    WakeNext     \* not the code: a waiter that leaves with a connection
                 \* wakes the next waiter

Conns == 1..NC
WorkSeq == SubSeq(<<"w1", "w2", "w3", "w4">>, 1, MaxWorks)
Works == {WorkSeq[i] : i \in 1..MaxWorks}
NoProc == "none"
Kind(t) == IF t \in PrivClients THEN "priv" ELSE "read"
\* the request of t changes something in the ESDM, "changes" of
\* esdm_cdev_invoke()
Chg(t) == Commit /\ Kind(t) = "priv"
\* the connections in the order of esdm_cdev_conn_try(start)
Order(s) == [i \in 1..NC |-> ((s + i - 2) % NC) + 1]
RemoveAt(q, i) == SubSeq(q, 1, i - 1) \o SubSeq(q, i + 1, Len(q))
InQ(q, t) == \E i \in 1..Len(q) : q[i] = t
Count(S) == Cardinality(S)
\* The readers are interchangeable: the safety configurations with many of
\* them make the clients model values and name this as their SYMMETRY.
Sym == Permutations(Clients \ PrivClients)

(* --algorithm EsdmKernelCdevConn {
variables
    \* the pool
    lk = [c \in Conns |-> NoProc],        \* conn->lock
    held = [t \in Clients |-> 0],         \* conn of esdm_cdev_invoke()
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
    \* privileged commands of sockets the module closed, unread by the ESDM
    orph = [t \in Clients |-> 0],
    \* the error of esdm_cdev_conn_get()
    gerr = [t \in Clients |-> "none"],
    \* ghosts: request bit, executions of the current privileged command,
    \* sockets that exist, violations
    bit = [t \in Clients |-> 0],
    exec = [t \in Clients |-> 0],
    live = IF InitConn THEN NC ELSE 0,
    viol = {};

define {
    \* the first queued waiter a wakeup finds sleeping
    Sleepers == {i \in 1..Len(cq) : cst[cq[i]] = "intr"}
    FreeWorks == {i \in 1..MaxWorks : wSt[WorkSeq[i]] = "free"}
    AllDone == \A t \in Clients : pc[t] = "Done"
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
    if (toSrv[c] # <<>> /\ Head(toSrv[c])[3] = "priv")
        orph[Head(toSrv[c])[1]] := orph[Head(toSrv[c])[1]] + 1;
    sk[c] := FALSE;
    sopen[c] := FALSE;
    toSrv[c] := <<>>;
    toCli[c] := <<>>;
    live := live - 1;
}

\* esdm_cdev_connect_put()
macro connectPut(w) {
    with (o = wRef[w]) {
        wRef[w] := o - 1;
        if (o = 1) {
            \* made for a waiter that gave up: sock_release(), kfree()
            if (wSock[w] /\ Release) live := live - 1;
            wSock[w] := FALSE;
            wSt[w] := "free";
        };
    };
}

\* esdm_cdev_conn_get(); held[self] the connection, or 0 and gerr
procedure connGet()
    variables st = 1, ix = 1, tmo = FALSE;
{
    \* atomic_inc_return(&esdm_cdev_conn_next)
g0: with (s \in Conns) st := s;
    \* esdm_cdev_conn_try(): mutex_trylock() of one connection after the
    \* other
gA: if (lk[Order(st)[ix]] = NoProc \/ ~Locked) {
        lk[Order(st)[ix]] := self;
        held[self] := Order(st)[ix];
        return;
    } else if (ix < NC) {
        ix := ix + 1;
        goto gA;
    } else {
        ix := 1;
    };
    \* prepare_to_wait_exclusive()
g1: if (~InQ(cq, self)) cq := Append(cq, self);
    cst[self] := "intr";
    \* esdm_cdev_conn_try()
gB: if (lk[Order(st)[ix]] = NoProc) {
        lk[Order(st)[ix]] := self;
        held[self] := Order(st)[ix];
        ix := 1;
        goto g4;
    } else if (ix < NC) {
        ix := ix + 1;
        goto gB;
    } else {
        ix := 1;
    };
    \* the time left, the signal
g2: if (tmo) {
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
    \* TASK_RUNNING; a wakeup taken is passed on, else the entry removed,
    \* under the lock of the wait queue. With WakeNext a waiter that leaves
    \* with a connection wakes the next one as well.
g4: cst[self] := "run";
g6: with (q = IF InQ(cq, self) /\ Finish
                 THEN RemoveAt(cq, CHOOSE j \in 1..Len(cq) : cq[j] = self)
                 ELSE cq,
              pass = (PassOn /\ ~InQ(cq, self))
                     \/ (WakeNext /\ held[self] # 0),
              S = {k \in 1..Len(q) : cst[q[k]] = "intr"}) {
        if (pass /\ S # {}) {
            with (k = CHOOSE k \in S : \A l \in S : k <= l) {
                cst[q[k]] := "run";
                cq := RemoveAt(q, k);
            };
        } else {
            cq := q;
        };
    };
    return;
}

\* a task in esdm_cdev_invoke(), one per call
fair process (cl \in Clients)
    variables nc = 0, att = 0, myw = "none", r = "none", ret = "none",
              sent = FALSE;
{
c0: while (nc < MaxCalls) {
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
        } else if (FreeWorks = {}) {
            \* kzalloc() failed
            ret := "enomem";
            goto c9;
        } else {
            with (w = WorkSeq[CHOOSE k \in FreeWorks :
                                  \A l \in FreeWorks : k <= l]) {
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
                \* conn->sock = c->sock; c->sock = NULL
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
c4:     connectPut(myw);
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
                  /\ ~(Await /\ Kind(self) = "priv");
            r := "erestartsys";
        };
        \* esdm_cdev_invoke(): done, or the stream is lost
c7:     if (r = "ok") {
            boff := FALSE;
            ret := "ok";
            goto c9;
        } else if (Chg(self) /\ sent) {
            \* gone out: never again, -EINTR instead of a restart
            dropSock(held[self]);
            if (r = "erestartsys") {
                ret := "eintr";
            } else {
                boff := TRUE;
                boffT := TRUE;
                ret := r;
            };
            goto c9;
        } else {
            with (intr = r = "erestartsys" \/ sig[self],
                  again = att = 0 /\ ~intr /\ r \in {"econnreset", "epipe"}) {
                if (Drop) {
                    dropSock(held[self]);
                };
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
        \* the call returns: repeated by the task unless it succeeded or a
        \* signal ended it; a privileged command a signal ended may be
        \* restarted by the kernel instead, the same command once more
cR:     either {
            if (ret \in {"ok", "erestartsys", "eintr"}) nc := nc + 1;
            exec[self] := 0;
            orph[self] := 0;
        } or {
            await ret = "erestartsys" /\ Kind(self) = "priv";
        };
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
            live := live + 1;
        };
        wSt[self] := "done";
k1:     connectPut(self);
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
            \* reads a privileged command of a connection the module
            \* closed and carries it out, the answer goes nowhere
            with (t \in {x \in Clients : up /\ orph[x] > 0}) {
                orph[t] := orph[t] - 1;
                exec[t] := exec[t] + 1;
            };
        } or {
            \* stops: every connection closed, connects refused
            await ~good /\ up /\ faults < MaxFaults;
            faults := faults + 1;
            up := FALSE;
            sopen := [c \in Conns |-> FALSE];
            toSrv := [c \in Conns |-> <<>>];
            wOpen := [w \in Works |-> FALSE];
            orph := [t \in Clients |-> 0];
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
        } or {
            \* every call is made: the model ends here
            await AllDone;
        };
    };
}

} *)
\* BEGIN TRANSLATION
VARIABLES lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, wOpen, 
          wOk, boff, boffT, up, good, sig, nsig, faults, orph, gerr, bit, 
          exec, live, viol, pc, stack

(* define statement *)
Sleepers == {i \in 1..Len(cq) : cst[cq[i]] = "intr"}
FreeWorks == {i \in 1..MaxWorks : wSt[WorkSeq[i]] = "free"}
AllDone == \A t \in Clients : pc[t] = "Done"

VARIABLES st, ix, tmo, nc, att, myw, r, ret, sent

vars == << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
           wOpen, wOk, boff, boffT, up, good, sig, nsig, faults, orph, gerr, 
           bit, exec, live, viol, pc, stack, st, ix, tmo, nc, att, myw, r, 
           ret, sent >>

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
        /\ orph = [t \in Clients |-> 0]
        /\ gerr = [t \in Clients |-> "none"]
        /\ bit = [t \in Clients |-> 0]
        /\ exec = [t \in Clients |-> 0]
        /\ live = IF InitConn THEN NC ELSE 0
        /\ viol = {}
        (* Procedure connGet *)
        /\ st = [ self \in ProcSet |-> 1]
        /\ ix = [ self \in ProcSet |-> 1]
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
                 st' = [st EXCEPT ![self] = s]
            /\ pc' = [pc EXCEPT ![self] = "gA"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            sig, nsig, faults, orph, gerr, bit, exec, live, 
                            viol, stack, ix, tmo, nc, att, myw, r, ret, sent >>

gA(self) == /\ pc[self] = "gA"
            /\ IF lk[Order(st[self])[ix[self]]] = NoProc \/ ~Locked
                  THEN /\ lk' = [lk EXCEPT ![Order(st[self])[ix[self]]] = self]
                       /\ held' = [held EXCEPT ![self] = Order(st[self])[ix[self]]]
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ st' = [st EXCEPT ![self] = Head(stack[self]).st]
                       /\ ix' = [ix EXCEPT ![self] = Head(stack[self]).ix]
                       /\ tmo' = [tmo EXCEPT ![self] = Head(stack[self]).tmo]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  ELSE /\ IF ix[self] < NC
                             THEN /\ ix' = [ix EXCEPT ![self] = ix[self] + 1]
                                  /\ pc' = [pc EXCEPT ![self] = "gA"]
                             ELSE /\ ix' = [ix EXCEPT ![self] = 1]
                                  /\ pc' = [pc EXCEPT ![self] = "g1"]
                       /\ UNCHANGED << lk, held, stack, st, tmo >>
            /\ UNCHANGED << cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
                            wOpen, wOk, boff, boffT, up, good, sig, nsig, 
                            faults, orph, gerr, bit, exec, live, viol, nc, att, 
                            myw, r, ret, sent >>

g1(self) == /\ pc[self] = "g1"
            /\ IF ~InQ(cq, self)
                  THEN /\ cq' = Append(cq, self)
                  ELSE /\ TRUE
                       /\ cq' = cq
            /\ cst' = [cst EXCEPT ![self] = "intr"]
            /\ pc' = [pc EXCEPT ![self] = "gB"]
            /\ UNCHANGED << lk, held, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, orph, gerr, bit, exec, live, viol, 
                            stack, st, ix, tmo, nc, att, myw, r, ret, sent >>

gB(self) == /\ pc[self] = "gB"
            /\ IF lk[Order(st[self])[ix[self]]] = NoProc
                  THEN /\ lk' = [lk EXCEPT ![Order(st[self])[ix[self]]] = self]
                       /\ held' = [held EXCEPT ![self] = Order(st[self])[ix[self]]]
                       /\ ix' = [ix EXCEPT ![self] = 1]
                       /\ pc' = [pc EXCEPT ![self] = "g4"]
                  ELSE /\ IF ix[self] < NC
                             THEN /\ ix' = [ix EXCEPT ![self] = ix[self] + 1]
                                  /\ pc' = [pc EXCEPT ![self] = "gB"]
                             ELSE /\ ix' = [ix EXCEPT ![self] = 1]
                                  /\ pc' = [pc EXCEPT ![self] = "g2"]
                       /\ UNCHANGED << lk, held >>
            /\ UNCHANGED << cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
                            wOpen, wOk, boff, boffT, up, good, sig, nsig, 
                            faults, orph, gerr, bit, exec, live, viol, stack, 
                            st, tmo, nc, att, myw, r, ret, sent >>

g2(self) == /\ pc[self] = "g2"
            /\ IF tmo[self]
                  THEN /\ gerr' = [gerr EXCEPT ![self] = "etimedout"]
                       /\ pc' = [pc EXCEPT ![self] = "g4"]
                  ELSE /\ IF sig[self]
                             THEN /\ gerr' = [gerr EXCEPT ![self] = "erestartsys"]
                                  /\ pc' = [pc EXCEPT ![self] = "g4"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "g3"]
                                  /\ gerr' = gerr
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            sig, nsig, faults, orph, bit, exec, live, viol, 
                            stack, st, ix, tmo, nc, att, myw, r, ret, sent >>

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
                            nsig, orph, gerr, bit, exec, live, viol, stack, st, 
                            ix, nc, att, myw, r, ret, sent >>

g4(self) == /\ pc[self] = "g4"
            /\ cst' = [cst EXCEPT ![self] = "run"]
            /\ pc' = [pc EXCEPT ![self] = "g6"]
            /\ UNCHANGED << lk, held, cq, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, orph, gerr, bit, exec, live, viol, 
                            stack, st, ix, tmo, nc, att, myw, r, ret, sent >>

g6(self) == /\ pc[self] = "g6"
            /\ LET q == IF InQ(cq, self) /\ Finish
                           THEN RemoveAt(cq, CHOOSE j \in 1..Len(cq) : cq[j] = self)
                           ELSE cq IN
                 LET pass == (PassOn /\ ~InQ(cq, self))
                             \/ (WakeNext /\ held[self] # 0) IN
                   LET S == {k \in 1..Len(q) : cst[q[k]] = "intr"} IN
                     IF pass /\ S # {}
                        THEN /\ LET k == CHOOSE k \in S : \A l \in S : k <= l IN
                                  /\ cst' = [cst EXCEPT ![q[k]] = "run"]
                                  /\ cq' = RemoveAt(q, k)
                        ELSE /\ cq' = q
                             /\ cst' = cst
            /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
            /\ st' = [st EXCEPT ![self] = Head(stack[self]).st]
            /\ ix' = [ix EXCEPT ![self] = Head(stack[self]).ix]
            /\ tmo' = [tmo EXCEPT ![self] = Head(stack[self]).tmo]
            /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
            /\ UNCHANGED << lk, held, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, faults, orph, gerr, bit, exec, live, viol, 
                            nc, att, myw, r, ret, sent >>

connGet(self) == g0(self) \/ gA(self) \/ g1(self) \/ gB(self) \/ g2(self)
                    \/ g3(self) \/ g4(self) \/ g6(self)

c0(self) == /\ pc[self] = "c0"
            /\ IF nc[self] < MaxCalls
                  THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "connGet",
                                                                pc        |->  "c1",
                                                                st        |->  st[self],
                                                                ix        |->  ix[self],
                                                                tmo       |->  tmo[self] ] >>
                                                            \o stack[self]]
                       /\ st' = [st EXCEPT ![self] = 1]
                       /\ ix' = [ix EXCEPT ![self] = 1]
                       /\ tmo' = [tmo EXCEPT ![self] = FALSE]
                       /\ pc' = [pc EXCEPT ![self] = "g0"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ UNCHANGED << stack, st, ix, tmo >>
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            sig, nsig, faults, orph, gerr, bit, exec, live, 
                            viol, nc, att, myw, r, ret, sent >>

c1(self) == /\ pc[self] = "c1"
            /\ IF held[self] = 0
                  THEN /\ ret' = [ret EXCEPT ![self] = gerr[self]]
                       /\ pc' = [pc EXCEPT ![self] = "cR"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "c2"]
                       /\ ret' = ret
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            sig, nsig, faults, orph, gerr, bit, exec, live, 
                            viol, stack, st, ix, tmo, nc, att, myw, r, sent >>

c2(self) == /\ pc[self] = "c2"
            /\ IF sk[held[self]]
                  THEN /\ pc' = [pc EXCEPT ![self] = "c5"]
                       /\ UNCHANGED << wSt, wRef, wSock, wOpen, wOk, myw, ret >>
                  ELSE /\ IF boff /\ boffT
                             THEN /\ ret' = [ret EXCEPT ![self] = "enotconn"]
                                  /\ pc' = [pc EXCEPT ![self] = "c9"]
                                  /\ UNCHANGED << wSt, wRef, wSock, wOpen, wOk, 
                                                  myw >>
                             ELSE /\ IF FreeWorks = {}
                                        THEN /\ ret' = [ret EXCEPT ![self] = "enomem"]
                                             /\ pc' = [pc EXCEPT ![self] = "c9"]
                                             /\ UNCHANGED << wSt, wRef, wSock, 
                                                             wOpen, wOk, myw >>
                                        ELSE /\ LET w == WorkSeq[CHOOSE k \in FreeWorks :
                                                                     \A l \in FreeWorks : k <= l] IN
                                                  /\ wSt' = [wSt EXCEPT ![w] = "queued"]
                                                  /\ wRef' = [wRef EXCEPT ![w] = 2]
                                                  /\ wSock' = [wSock EXCEPT ![w] = FALSE]
                                                  /\ wOpen' = [wOpen EXCEPT ![w] = FALSE]
                                                  /\ wOk' = [wOk EXCEPT ![w] = FALSE]
                                                  /\ myw' = [myw EXCEPT ![self] = w]
                                             /\ pc' = [pc EXCEPT ![self] = "c3"]
                                             /\ ret' = ret
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, boff, 
                            boffT, up, good, sig, nsig, faults, orph, gerr, 
                            bit, exec, live, viol, stack, st, ix, tmo, nc, att, 
                            r, sent >>

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
                            boffT, up, good, sig, nsig, orph, gerr, bit, exec, 
                            live, viol, stack, st, ix, tmo, nc, att, myw, ret, 
                            sent >>

c4(self) == /\ pc[self] = "c4"
            /\ LET o == wRef[myw[self]] IN
                 /\ wRef' = [wRef EXCEPT ![myw[self]] = o - 1]
                 /\ IF o = 1
                       THEN /\ IF wSock[myw[self]] /\ Release
                                  THEN /\ live' = live - 1
                                  ELSE /\ TRUE
                                       /\ live' = live
                            /\ wSock' = [wSock EXCEPT ![myw[self]] = FALSE]
                            /\ wSt' = [wSt EXCEPT ![myw[self]] = "free"]
                       ELSE /\ TRUE
                            /\ UNCHANGED << wSt, wSock, live >>
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
                            wOk, up, good, sig, nsig, faults, orph, gerr, bit, 
                            exec, viol, stack, st, ix, tmo, nc, att, r, sent >>

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
                            nsig, faults, orph, gerr, exec, live, viol, stack, 
                            st, ix, tmo, nc, att, myw, ret >>

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
                     /\ ~(Await /\ Kind(self) = "priv")
                  /\ r' = [r EXCEPT ![self] = "erestartsys"]
                  /\ UNCHANGED <<toCli, faults, viol>>
            /\ pc' = [pc EXCEPT ![self] = "c7"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, wSt, wRef, 
                            wSock, wOpen, wOk, boff, boffT, up, good, sig, 
                            nsig, orph, gerr, bit, exec, live, stack, st, ix, 
                            tmo, nc, att, myw, ret, sent >>

c7(self) == /\ pc[self] = "c7"
            /\ IF r[self] = "ok"
                  THEN /\ boff' = FALSE
                       /\ ret' = [ret EXCEPT ![self] = "ok"]
                       /\ pc' = [pc EXCEPT ![self] = "c9"]
                       /\ UNCHANGED << sk, sopen, toSrv, toCli, boffT, orph, 
                                       live, att, sent >>
                  ELSE /\ IF Chg(self) /\ sent[self]
                             THEN /\ IF toSrv[(held[self])] # <<>> /\ Head(toSrv[(held[self])])[3] = "priv"
                                        THEN /\ orph' = [orph EXCEPT ![Head(toSrv[(held[self])])[1]] = orph[Head(toSrv[(held[self])])[1]] + 1]
                                        ELSE /\ TRUE
                                             /\ orph' = orph
                                  /\ sk' = [sk EXCEPT ![(held[self])] = FALSE]
                                  /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                  /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                  /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                  /\ live' = live - 1
                                  /\ IF r[self] = "erestartsys"
                                        THEN /\ ret' = [ret EXCEPT ![self] = "eintr"]
                                             /\ UNCHANGED << boff, boffT >>
                                        ELSE /\ boff' = TRUE
                                             /\ boffT' = TRUE
                                             /\ ret' = [ret EXCEPT ![self] = r[self]]
                                  /\ pc' = [pc EXCEPT ![self] = "c9"]
                                  /\ UNCHANGED << att, sent >>
                             ELSE /\ LET intr == r[self] = "erestartsys" \/ sig[self] IN
                                       LET again == att[self] = 0 /\ ~intr /\ r[self] \in {"econnreset", "epipe"} IN
                                         /\ IF Drop
                                               THEN /\ IF toSrv[(held[self])] # <<>> /\ Head(toSrv[(held[self])])[3] = "priv"
                                                          THEN /\ orph' = [orph EXCEPT ![Head(toSrv[(held[self])])[1]] = orph[Head(toSrv[(held[self])])[1]] + 1]
                                                          ELSE /\ TRUE
                                                               /\ orph' = orph
                                                    /\ sk' = [sk EXCEPT ![(held[self])] = FALSE]
                                                    /\ sopen' = [sopen EXCEPT ![(held[self])] = FALSE]
                                                    /\ toSrv' = [toSrv EXCEPT ![(held[self])] = <<>>]
                                                    /\ toCli' = [toCli EXCEPT ![(held[self])] = <<>>]
                                                    /\ live' = live - 1
                                               ELSE /\ TRUE
                                                    /\ UNCHANGED << sk, sopen, 
                                                                    toSrv, 
                                                                    toCli, 
                                                                    orph, live >>
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
                            stack, st, ix, tmo, nc, myw, r >>

c9(self) == /\ pc[self] = "c9"
            /\ lk' = [lk EXCEPT ![held[self]] = NoProc]
            /\ held' = [held EXCEPT ![self] = 0]
            /\ pc' = [pc EXCEPT ![self] = "c10"]
            /\ UNCHANGED << cq, cst, sk, sopen, toSrv, toCli, wSt, wRef, wSock, 
                            wOpen, wOk, boff, boffT, up, good, sig, nsig, 
                            faults, orph, gerr, bit, exec, live, viol, stack, 
                            st, ix, tmo, nc, att, myw, r, ret, sent >>

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
                             nsig, faults, orph, gerr, bit, exec, live, viol, 
                             stack, st, ix, tmo, nc, att, myw, r, ret, sent >>

cR(self) == /\ pc[self] = "cR"
            /\ \/ /\ IF ret[self] \in {"ok", "erestartsys", "eintr"}
                        THEN /\ nc' = [nc EXCEPT ![self] = nc[self] + 1]
                        ELSE /\ TRUE
                             /\ nc' = nc
                  /\ exec' = [exec EXCEPT ![self] = 0]
                  /\ orph' = [orph EXCEPT ![self] = 0]
               \/ /\ ret[self] = "erestartsys" /\ Kind(self) = "priv"
                  /\ UNCHANGED <<orph, exec, nc>>
            /\ sig' = [sig EXCEPT ![self] = FALSE]
            /\ gerr' = [gerr EXCEPT ![self] = "none"]
            /\ att' = [att EXCEPT ![self] = 0]
            /\ r' = [r EXCEPT ![self] = "none"]
            /\ ret' = [ret EXCEPT ![self] = "none"]
            /\ sent' = [sent EXCEPT ![self] = FALSE]
            /\ pc' = [pc EXCEPT ![self] = "c0"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wSt, 
                            wRef, wSock, wOpen, wOk, boff, boffT, up, good, 
                            nsig, faults, bit, live, viol, stack, st, ix, tmo, 
                            myw >>

cl(self) == c0(self) \/ c1(self) \/ c2(self) \/ c3(self) \/ c4(self)
               \/ c5(self) \/ c6(self) \/ c7(self) \/ c9(self) \/ c10(self)
               \/ cR(self)

k0(self) == /\ pc[self] = "k0"
            /\ wSt[self] = "queued"
            /\ IF up
                  THEN /\ wSock' = [wSock EXCEPT ![self] = TRUE]
                       /\ wOpen' = [wOpen EXCEPT ![self] = TRUE]
                       /\ wOk' = [wOk EXCEPT ![self] = TRUE]
                       /\ live' = live + 1
                  ELSE /\ TRUE
                       /\ UNCHANGED << wSock, wOpen, wOk, live >>
            /\ wSt' = [wSt EXCEPT ![self] = "done"]
            /\ pc' = [pc EXCEPT ![self] = "k1"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wRef, 
                            boff, boffT, up, good, sig, nsig, faults, orph, 
                            gerr, bit, exec, viol, stack, st, ix, tmo, nc, att, 
                            myw, r, ret, sent >>

k1(self) == /\ pc[self] = "k1"
            /\ LET o == wRef[self] IN
                 /\ wRef' = [wRef EXCEPT ![self] = o - 1]
                 /\ IF o = 1
                       THEN /\ IF wSock[self] /\ Release
                                  THEN /\ live' = live - 1
                                  ELSE /\ TRUE
                                       /\ live' = live
                            /\ wSock' = [wSock EXCEPT ![self] = FALSE]
                            /\ wSt' = [wSt EXCEPT ![self] = "free"]
                       ELSE /\ TRUE
                            /\ UNCHANGED << wSt, wSock, live >>
            /\ pc' = [pc EXCEPT ![self] = "k0"]
            /\ UNCHANGED << lk, held, cq, cst, sk, sopen, toSrv, toCli, wOpen, 
                            wOk, boff, boffT, up, good, sig, nsig, faults, 
                            orph, gerr, bit, exec, viol, stack, st, ix, tmo, 
                            nc, att, myw, r, ret, sent >>

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
                  /\ UNCHANGED <<sopen, wOpen, up, faults, orph>>
               \/ /\ \E t \in {x \in Clients : up /\ orph[x] > 0}:
                       /\ orph' = [orph EXCEPT ![t] = orph[t] - 1]
                       /\ exec' = [exec EXCEPT ![t] = exec[t] + 1]
                  /\ UNCHANGED <<sopen, toSrv, toCli, wOpen, up, faults>>
               \/ /\ ~good /\ up /\ faults < MaxFaults
                  /\ faults' = faults + 1
                  /\ up' = FALSE
                  /\ sopen' = [c \in Conns |-> FALSE]
                  /\ toSrv' = [c \in Conns |-> <<>>]
                  /\ wOpen' = [w \in Works |-> FALSE]
                  /\ orph' = [t \in Clients |-> 0]
                  /\ UNCHANGED <<toCli, exec>>
               \/ /\ ~good /\ ~up
                  /\ up' = TRUE
                  /\ UNCHANGED <<sopen, toSrv, toCli, wOpen, faults, orph, exec>>
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
                  /\ UNCHANGED <<toCli, wOpen, up, orph>>
            /\ pc' = [pc EXCEPT ![self] = "s0"]
            /\ UNCHANGED << lk, held, cq, cst, sk, wSt, wRef, wSock, wOk, boff, 
                            boffT, good, sig, nsig, gerr, bit, live, viol, 
                            stack, st, ix, tmo, nc, att, myw, r, ret, sent >>

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
               \/ /\ AllDone
                  /\ UNCHANGED <<cst, boffT, up, good, sig, nsig>>
            /\ pc' = [pc EXCEPT ![self] = "e0"]
            /\ UNCHANGED << lk, held, cq, sk, sopen, toSrv, toCli, wSt, wRef, 
                            wSock, wOpen, wOk, boff, faults, orph, gerr, bit, 
                            exec, live, viol, stack, st, ix, tmo, nc, att, myw, 
                            r, ret, sent >>

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
    /\ held \in [Clients -> 0..NC]
    /\ cst \in [Clients -> {"run", "intr"}]
    /\ wRef \in [Works -> 0..2]
    /\ live \in 0..(NC + MaxWorks)
    /\ Len(cq) <= Cardinality(Clients)

\* Every answer a request reads is the answer to that request: a reader
\* never gets the data of another one, whatever was interrupted, timed out
\* or restarted before.
ResponseMatch == "Mismatch" \notin viol

\* A privileged command is carried out at most once: one that went out is
\* never sent again, by esdm_cdev_invoke() or by a restart of the system
\* call. exec counts what the ESDM carries out, also of connections the
\* module has closed.
SentOnce == \A t \in Clients : exec[t] <= 1

\* The answer to a privileged command that went out is waited for despite
\* signals: no call ends with -EINTR, which the code keeps for a fatal
\* signal, and there is none in the model.
AnswerAwaited == \A t \in Clients : ret[t] # "eintr"

\* A connection serves one request at a time: no two tasks have the same
\* one, and what is on its way on it, in either direction, is the one
\* request of the task that has it, or the answer to it.
OnConn(c) == {toSrv[c][k] : k \in 1..Len(toSrv[c])}
             \cup {toCli[c][k] : k \in 1..Len(toCli[c])}
ExclusiveUse ==
    /\ \A t, u \in Clients : t # u /\ held[t] # 0 => held[t] # held[u]
    /\ \A c \in Conns :
           /\ Len(toSrv[c]) + Len(toCli[c]) <= 1
           /\ \A m \in OnConn(c) : held[m[1]] = c

\* No socket is left behind and none is released twice: the sockets that
\* exist are those of the connections and those of the connects nobody
\* took yet. A connect is freed with its last reference, of its waiter and
\* of its work, and not before.
NoSockLeak ==
    /\ live = Count({c \in Conns : sk[c]}) + Count({w \in Works : wSock[w]})
    /\ \A w \in Works :
           /\ wRef[w] = Count({t \in Clients : myw[t] = w})
                        + (IF wSt[w] = "queued" \/ pc[w] = "k1"
                           THEN 1 ELSE 0)
           /\ wSt[w] = "free" <=> wRef[w] = 0
           /\ wSock[w] => wSt[w] # "free"

\* The entries of the wait queue are those of tasks in
\* esdm_cdev_conn_get(), one each: an entry lives on the stack of that
\* function.
NoStaleEntry ==
    \A k \in 1..Len(cq) :
        /\ pc[cq[k]] \in {"g1", "gB", "g2", "g3", "g4", "g6"}
        /\ \A l \in 1..Len(cq) : cq[l] = cq[k] => l = k

\* Once the ESDM is good, no task sleeps for a connection while nothing but
\* time can happen.
NoStrandedWaiter ==
    good /\ (\E t \in Clients : pc[t] = "g3" /\ cst[t] = "intr")
        => \/ \E t \in Clients : ENABLED (cl(t) \/ connGet(t))
           \/ \E w \in Works : ENABLED wk(w)
           \/ ENABLED sv("esdm")

\* A task sleeps for a connection, and neither is a wakeup on its way nor
\* a task about to look for a connection or to pass a wakeup on.
Asleep == \E t \in Clients : pc[t] = "g3" /\ cst[t] = "intr"
Unattended ==
    /\ Asleep
    /\ \A q \in Clients :
           /\ pc[q] \notin {"c10", "g0", "gA", "g1", "gB", "g2", "g4", "g6"}
           /\ ~(pc[q] = "g3" /\ cst[q] = "run")

\* No task is left asleep by a pool that is idle: while tasks sleep
\* unattended, a connection is in use, and its release wakes one of them.
NoSleeperByIdlePool == ~(Unattended /\ \A c \in Conns : lk[c] = NoProc)

\* No free connection is left with sleepers, the aim esdm_cdev_conn_get()
\* states for passing a wakeup on. It holds with one connection, where it
\* is NoSleeperByIdlePool. With several it does not hold for the code: the
\* scan of esdm_cdev_conn_try() is not atomic. A waiter has looked at a
\* connection that is freed behind its scan; the wakeup for that one goes
\* to another waiter, which takes the connection the first one was about
\* to look at. The first one then sleeps by the free connection until the
\* other one releases its connection (configuration ScanRace).
NoSleeperByFreeConn == ~(Unattended /\ \E c \in Conns : lk[c] = NoProc)

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
CallsSucceed == <>[]good => <>AllDone
=============================================================================
