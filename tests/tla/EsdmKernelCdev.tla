--------------------------- MODULE EsdmKernelCdev ---------------------------
(***************************************************************************)
(* The devices of the kernel module esdm_cdev: esdm_cdev_read() and the    *)
(* poll functions of kernel/esdm_cdev/esdm_cdev_main.c with the flag that  *)
(* the ESDM is operational, its waiters and watcher, and the back-off of   *)
(* /dev/esdm_pr after an empty prediction resistant read. One step is one  *)
(* atomic variable access, one wait queue operation or one request to the  *)
(* ESDM; the labels name the C functions they come from.                   *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - A request to the ESDM, esdm_cdev_egd_read() or                        *)
(*   esdm_cdev_egd_get_state(), is one step with the contract of           *)
(*   esdm_cdev.h: data, none, an error, or -ERESTARTSYS with a signal      *)
(*   pending; the model EsdmKernelCdevConn checks the connections behind  *)
(*   it. The answer reflects the ESDM at that step, and the caller acts on *)
(*   it in later steps.                                                    *)
(* - The ESDM: reachable or not (stopped, restarting), operational or not, *)
(*   its prediction resistance DRNG with data or not. Until the            *)
(*   environment turns good these change at any time, and any request may *)
(*   fail (timeout, no free connection) or come back empty; once good, the *)
(*   ESDM is reachable and operational, delivers prediction resistant data *)
(*   and nothing changes any more. Signals come only before that.         *)
(* - Time: the 50 ms after an empty prediction resistant read are a flag   *)
(*   that time clears; the wake work fires no earlier. The delays of the   *)
(*   watcher and the back-off of its interval only delay it and are left   *)
(*   out. A blocking prediction resistant read retries at once.            *)
(* - Wait queues: a waiter on esdm_cdev_wait is removed by its wakeup, a   *)
(*   poller stays registered until its poll() returns; a wakeup sets the   *)
(*   woken flag that schedule() and poll_schedule_timeout() wait for.      *)
(* - A read asks for one chunk; copy_to_user() and kvmalloc() succeed.     *)
(*   Not modelled: writes, the ioctls, /proc/esdm, module unload.          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Readers,     \* reader threads, named after their device and mode, RK
    Pollers,     \* poll() callers: "rp" /dev/esdm_random, "pp" /dev/esdm_pr
    MaxReads,    \* reads per reader
    MaxPolls,    \* poll() calls per poller
    MaxSig,      \* signals in all
    Liveness,    \* the environment eventually turns good
    KickOnUnset  \* turning the flag off kicks the watcher for waiters (the
                 \* code since the fix)

\* device and O_NONBLOCK of each reader; "pr" is /dev/esdm_pr
RK == [rb |-> [dev |-> "random", nb |-> FALSE],
       rb2 |-> [dev |-> "random", nb |-> FALSE],
       rn |-> [dev |-> "random", nb |-> TRUE],
       ub |-> [dev |-> "urandom", nb |-> FALSE],
       un |-> [dev |-> "urandom", nb |-> TRUE],
       pb |-> [dev |-> "pr", nb |-> FALSE],
       pn |-> [dev |-> "pr", nb |-> TRUE]]
Pr(r) == RK[r].dev = "pr"
Ur(r) == RK[r].dev = "urandom"
Nb(r) == RK[r].nb
Watch == "watch"
PrWake == "prwake"
Env == "env"

\* what a read may return: data, or -EAGAIN, -ERESTARTSYS and, for
\* /dev/esdm_urandom, the error of the request; /dev/esdm_pr with
\* O_NONBLOCK data or -EAGAIN only
Allowed(r) ==
    IF Pr(r) /\ Nb(r) THEN {"data", "eagain"}
    ELSE {"data", "erestartsys"}
         \cup (IF Nb(r) THEN {"eagain"} ELSE {})
         \cup (IF Ur(r) THEN {"err"} ELSE {})

(* --algorithm EsdmKernelCdev {
variables
    opF = FALSE,       \* esdm_cdev_operational
    waiters = 0,       \* esdm_cdev_waiters
    onQ = {},          \* tasks queued on esdm_cdev_wait
    onPrQ = {},        \* ... on esdm_cdev_pr_wait
    wk = {},           \* tasks woken
    wPend = TRUE,      \* the watcher queued; module init kicks it
    prEmpty = FALSE,   \* time_before(jiffies, esdm_cdev_pr_empty_until)
    prPend = FALSE,    \* esdm_cdev_pr_wake_work queued
    \* the ESDM and the environment
    srvUp = FALSE,
    srvOp = FALSE,
    prData = FALSE,
    good = FALSE,
    sig = [r \in Readers |-> FALSE],
    nsig = 0,
    viol = {};

define {
    \* the answer to esdm_cdev_egd_read()
    ReadAns(r) ==
        (IF sig[r] THEN {"erestartsys"} ELSE {})
        \cup (IF good THEN {"data"}
              ELSE IF ~srvUp THEN {"err"}
              ELSE {"err", "zero"}
                   \cup (IF srvOp /\ (prData \/ ~Pr(r)) THEN {"data"} ELSE {}))
    \* the answer to esdm_cdev_egd_get_state()
    StateAns ==
        IF good THEN {"op"}
        ELSE IF ~srvUp THEN {"err"}
        ELSE {"err", IF srvOp THEN "op" ELSE "noop"}
    \* somebody waits: esdm_cdev_waiters or wq_has_sleeper()
    Waiting == waiters > 0 \/ onQ # {}
}

\* wake_up_interruptible_all(&esdm_cdev_wait): wait_event entries are
\* removed, poll entries stay
macro wakeAll() {
    wk := wk \cup onQ;
    onQ := onQ \cap Pollers;
}

\* esdm_cdev_read() of a reader's device
fair process (rd \in Readers)
    variables nr = 0, got = "none", ret = "none", old = FALSE, bo = FALSE,
              sg = FALSE;
{
r0: while (nr < MaxReads) {
        nr := nr + 1;
        \* the loop: a signal ends the read
r1:     if (sig[self]) {
            ret := "erestartsys";
            sg := TRUE;
            goto rE;
        };
        \* esdm_cdev_egd_read()
r2:     with (a \in ReadAns(self)) got := a;
        \* an interrupted request ends the read, an unreachable ESDM a read
        \* of /dev/esdm_urandom; otherwise the answer tells the state
r3:     if (got = "erestartsys" \/ (got = "err" /\ Ur(self))) {
            ret := got;
            sg := got = "erestartsys";
            goto rE;
        } else if (~Pr(self)) {
            \* esdm_cdev_set_operational(got)
            old := opF;
            opF := got = "data";
        } else if (got = "data") {
            \* esdm_cdev_pr_result(true)
            prEmpty := FALSE;
        } else {
            \* esdm_cdev_pr_result(false): esdm_cdev_pr_empty_until
            prEmpty := TRUE;
            bo := TRUE;
        };
        \* ... the wakeup of a change to operational, or the wake work
r4:     if (~Pr(self) /\ got = "data" /\ ~old) {
            wakeAll();
        } else if (~Pr(self) /\ got # "data" /\ old /\ KickOnUnset
                   /\ Waiting) {
            wPend := TRUE;
        } else if (Pr(self) /\ got # "data") {
            \* mod_delayed_work()
            prPend := TRUE;
        };
r5:     if (got = "data") {
            ret := "data";
            goto rE;
        } else if (Nb(self)) {
            ret := "eagain";
            goto rE;
        } else if (Pr(self)) {
            \* schedule_timeout_interruptible() for the rest
            if (sig[self]) {
                ret := "erestartsys";
                sg := TRUE;
                goto rE;
            } else {
                goto r1;
            };
        };
        \* esdm_cdev_wait_operational(): esdm_cdev_set_operational(false)
r6:     old := opF;
        opF := FALSE;
r6a:    if (old /\ KickOnUnset /\ Waiting) wPend := TRUE;
r7:     waiters := waiters + 1;
        \* esdm_cdev_watch_kick()
r8:     wPend := TRUE;
        \* wait_event_interruptible(): prepare_to_wait_event()
r9:     onQ := onQ \cup {self};
        wk := wk \ {self};
        \* ... the condition, the signal
r10:    if (opF) {
            onQ := onQ \ {self};
            goto r12;
        } else if (sig[self]) {
            onQ := onQ \ {self};
            ret := "erestartsys";
            sg := TRUE;
            goto r12;
        };
        \* ... schedule() until woken or signalled
r11:    await self \in wk \/ sig[self];
        goto r9;
r12:    waiters := waiters - 1;
        if (ret = "erestartsys") goto rE else goto r1;
        \* what the read returns; /dev/esdm_pr with O_NONBLOCK -EAGAIN for
        \* anything but data
rE:     with (rv = IF Pr(self) /\ Nb(self) /\ ret # "data" THEN "eagain"
                   ELSE ret) {
            viol := viol
                \cup (IF rv \notin Allowed(self) THEN {"Result"} ELSE {})
                \cup (IF Pr(self) /\ Nb(self) /\ rv = "eagain" /\ ~sg /\ ~bo
                      THEN {"PrNoBackoff"} ELSE {});
        };
        sig[self] := FALSE;
        got := "none";
        ret := "none";
        old := FALSE;
        bo := FALSE;
        sg := FALSE;
    };
}

\* poll() of /dev/esdm_random (esdm_cdev_poll) or /dev/esdm_pr
\* (esdm_cdev_pr_poll), until readable
fair process (pl \in Pollers)
    variables np = 0, rdbl = FALSE;
{
p0: while (np < MaxPolls) {
        np := np + 1;
        \* poll_wait(): queued before the condition
p1:     onQ := onQ \cup {self};
        if (self = "pp") onPrQ := onPrQ \cup {self};
        wk := wk \ {self};
        \* the poll function
p2:     if (~opF) {
            \* esdm_cdev_watch_kick()
            wPend := TRUE;
            rdbl := FALSE;
        } else {
            rdbl := self = "rp" \/ ~prEmpty;
        };
p3:     if (rdbl) {
            \* readable: poll_freewait()
            onQ := onQ \ {self};
            onPrQ := onPrQ \ {self};
            rdbl := FALSE;
        } else {
            \* poll_schedule_timeout(): until a wakeup triggers it
            await self \in wk;
            wk := wk \ {self};
            goto p2;
        };
    };
}

\* esdm_cdev_watch(), a delayed work item: never run twice at once
fair process (wa \in {Watch})
    variables ans = "none", wold = FALSE;
{
w0: while (TRUE) {
        await wPend;
        wPend := FALSE;
        \* esdm_cdev_egd_get_state()
w1:     with (a \in StateAns) ans := a;
        \* esdm_cdev_set_operational()
w2:     wold := opF;
        opF := ans = "op";
w3:     if (ans = "op" /\ ~wold) {
            wakeAll();
        } else if (ans # "op" /\ wold /\ KickOnUnset /\ Waiting) {
            wPend := TRUE;
        };
        ans := "none";
        wold := FALSE;
        \* done once operational, else again while somebody waits
w4:     if (~opF) {
w5:         if (Waiting) wPend := TRUE;
        };
    };
}

\* esdm_cdev_pr_wake(): after the 50 ms
fair process (pw \in {PrWake})
{
x0: while (TRUE) {
        await prPend /\ ~prEmpty;
        prPend := FALSE;
        wk := wk \cup onPrQ;
    };
}

\* the ESDM, signals and time
fair process (e \in {Env})
{
e0: while (TRUE) {
        either {
            \* ESDM_CDEV_PR_RETRY_MS pass
            await prEmpty;
            prEmpty := FALSE;
        } or {
            \* the ESDM stops, or starts again, not operational
            await ~good;
            srvUp := ~srvUp;
            srvOp := FALSE;
        } or {
            await ~good /\ srvUp;
            srvOp := ~srvOp;
        } or {
            await ~good;
            prData := ~prData;
        } or {
            await ~good /\ nsig < MaxSig;
            with (r \in {x \in Readers : pc[x] \notin {"r0", "Done"}
                                         /\ ~sig[x]})
                sig[r] := TRUE;
            nsig := nsig + 1;
        } or {
            await Liveness /\ ~good;
            good := TRUE;
            srvUp := TRUE;
            srvOp := TRUE;
            prData := TRUE;
        };
    };
}

} *)
\* BEGIN TRANSLATION
VARIABLES opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, srvUp, srvOp, 
          prData, good, sig, nsig, viol, pc

(* define statement *)
ReadAns(r) ==
    (IF sig[r] THEN {"erestartsys"} ELSE {})
    \cup (IF good THEN {"data"}
          ELSE IF ~srvUp THEN {"err"}
          ELSE {"err", "zero"}
               \cup (IF srvOp /\ (prData \/ ~Pr(r)) THEN {"data"} ELSE {}))

StateAns ==
    IF good THEN {"op"}
    ELSE IF ~srvUp THEN {"err"}
    ELSE {"err", IF srvOp THEN "op" ELSE "noop"}

Waiting == waiters > 0 \/ onQ # {}

VARIABLES nr, got, ret, old, bo, sg, np, rdbl, ans, wold

vars == << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, srvUp, srvOp, 
           prData, good, sig, nsig, viol, pc, nr, got, ret, old, bo, sg, np, 
           rdbl, ans, wold >>

ProcSet == (Readers) \cup (Pollers) \cup ({Watch}) \cup ({PrWake}) \cup ({Env})

Init == (* Global variables *)
        /\ opF = FALSE
        /\ waiters = 0
        /\ onQ = {}
        /\ onPrQ = {}
        /\ wk = {}
        /\ wPend = TRUE
        /\ prEmpty = FALSE
        /\ prPend = FALSE
        /\ srvUp = FALSE
        /\ srvOp = FALSE
        /\ prData = FALSE
        /\ good = FALSE
        /\ sig = [r \in Readers |-> FALSE]
        /\ nsig = 0
        /\ viol = {}
        (* Process rd *)
        /\ nr = [self \in Readers |-> 0]
        /\ got = [self \in Readers |-> "none"]
        /\ ret = [self \in Readers |-> "none"]
        /\ old = [self \in Readers |-> FALSE]
        /\ bo = [self \in Readers |-> FALSE]
        /\ sg = [self \in Readers |-> FALSE]
        (* Process pl *)
        /\ np = [self \in Pollers |-> 0]
        /\ rdbl = [self \in Pollers |-> FALSE]
        (* Process wa *)
        /\ ans = [self \in {Watch} |-> "none"]
        /\ wold = [self \in {Watch} |-> FALSE]
        /\ pc = [self \in ProcSet |-> CASE self \in Readers -> "r0"
                                        [] self \in Pollers -> "p0"
                                        [] self \in {Watch} -> "w0"
                                        [] self \in {PrWake} -> "x0"
                                        [] self \in {Env} -> "e0"]

r0(self) == /\ pc[self] = "r0"
            /\ IF nr[self] < MaxReads
                  THEN /\ nr' = [nr EXCEPT ![self] = nr[self] + 1]
                       /\ pc' = [pc EXCEPT ![self] = "r1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ nr' = nr
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, got, ret, old, bo, sg, np, rdbl, ans, wold >>

r1(self) == /\ pc[self] = "r1"
            /\ IF sig[self]
                  THEN /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                       /\ sg' = [sg EXCEPT ![self] = TRUE]
                       /\ pc' = [pc EXCEPT ![self] = "rE"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "r2"]
                       /\ UNCHANGED << ret, sg >>
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, nr, got, old, bo, np, rdbl, ans, wold >>

r2(self) == /\ pc[self] = "r2"
            /\ \E a \in ReadAns(self):
                 got' = [got EXCEPT ![self] = a]
            /\ pc' = [pc EXCEPT ![self] = "r3"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, nr, ret, old, bo, sg, np, rdbl, ans, wold >>

r3(self) == /\ pc[self] = "r3"
            /\ IF got[self] = "erestartsys" \/ (got[self] = "err" /\ Ur(self))
                  THEN /\ ret' = [ret EXCEPT ![self] = got[self]]
                       /\ sg' = [sg EXCEPT ![self] = got[self] = "erestartsys"]
                       /\ pc' = [pc EXCEPT ![self] = "rE"]
                       /\ UNCHANGED << opF, prEmpty, old, bo >>
                  ELSE /\ IF ~Pr(self)
                             THEN /\ old' = [old EXCEPT ![self] = opF]
                                  /\ opF' = (got[self] = "data")
                                  /\ UNCHANGED << prEmpty, bo >>
                             ELSE /\ IF got[self] = "data"
                                        THEN /\ prEmpty' = FALSE
                                             /\ bo' = bo
                                        ELSE /\ prEmpty' = TRUE
                                             /\ bo' = [bo EXCEPT ![self] = TRUE]
                                  /\ UNCHANGED << opF, old >>
                       /\ pc' = [pc EXCEPT ![self] = "r4"]
                       /\ UNCHANGED << ret, sg >>
            /\ UNCHANGED << waiters, onQ, onPrQ, wk, wPend, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, viol, nr, got, np, 
                            rdbl, ans, wold >>

r4(self) == /\ pc[self] = "r4"
            /\ IF ~Pr(self) /\ got[self] = "data" /\ ~old[self]
                  THEN /\ wk' = (wk \cup onQ)
                       /\ onQ' = (onQ \cap Pollers)
                       /\ UNCHANGED << wPend, prPend >>
                  ELSE /\ IF ~Pr(self) /\ got[self] # "data" /\ old[self] /\ KickOnUnset
                             /\ Waiting
                             THEN /\ wPend' = TRUE
                                  /\ UNCHANGED prPend
                             ELSE /\ IF Pr(self) /\ got[self] # "data"
                                        THEN /\ prPend' = TRUE
                                        ELSE /\ TRUE
                                             /\ UNCHANGED prPend
                                  /\ wPend' = wPend
                       /\ UNCHANGED << onQ, wk >>
            /\ pc' = [pc EXCEPT ![self] = "r5"]
            /\ UNCHANGED << opF, waiters, onPrQ, prEmpty, srvUp, srvOp, prData, 
                            good, sig, nsig, viol, nr, got, ret, old, bo, sg, 
                            np, rdbl, ans, wold >>

r5(self) == /\ pc[self] = "r5"
            /\ IF got[self] = "data"
                  THEN /\ ret' = [ret EXCEPT ![self] = "data"]
                       /\ pc' = [pc EXCEPT ![self] = "rE"]
                       /\ sg' = sg
                  ELSE /\ IF Nb(self)
                             THEN /\ ret' = [ret EXCEPT ![self] = "eagain"]
                                  /\ pc' = [pc EXCEPT ![self] = "rE"]
                                  /\ sg' = sg
                             ELSE /\ IF Pr(self)
                                        THEN /\ IF sig[self]
                                                   THEN /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                                                        /\ sg' = [sg EXCEPT ![self] = TRUE]
                                                        /\ pc' = [pc EXCEPT ![self] = "rE"]
                                                   ELSE /\ pc' = [pc EXCEPT ![self] = "r1"]
                                                        /\ UNCHANGED << ret, 
                                                                        sg >>
                                        ELSE /\ pc' = [pc EXCEPT ![self] = "r6"]
                                             /\ UNCHANGED << ret, sg >>
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, nr, got, old, bo, np, rdbl, ans, wold >>

r6(self) == /\ pc[self] = "r6"
            /\ old' = [old EXCEPT ![self] = opF]
            /\ opF' = FALSE
            /\ pc' = [pc EXCEPT ![self] = "r6a"]
            /\ UNCHANGED << waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                            got, ret, bo, sg, np, rdbl, ans, wold >>

r6a(self) == /\ pc[self] = "r6a"
             /\ IF old[self] /\ KickOnUnset /\ Waiting
                   THEN /\ wPend' = TRUE
                   ELSE /\ TRUE
                        /\ wPend' = wPend
             /\ pc' = [pc EXCEPT ![self] = "r7"]
             /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                             got, ret, old, bo, sg, np, rdbl, ans, wold >>

r7(self) == /\ pc[self] = "r7"
            /\ waiters' = waiters + 1
            /\ pc' = [pc EXCEPT ![self] = "r8"]
            /\ UNCHANGED << opF, onQ, onPrQ, wk, wPend, prEmpty, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, viol, nr, got, ret, 
                            old, bo, sg, np, rdbl, ans, wold >>

r8(self) == /\ pc[self] = "r8"
            /\ wPend' = TRUE
            /\ pc' = [pc EXCEPT ![self] = "r9"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                            got, ret, old, bo, sg, np, rdbl, ans, wold >>

r9(self) == /\ pc[self] = "r9"
            /\ onQ' = (onQ \cup {self})
            /\ wk' = wk \ {self}
            /\ pc' = [pc EXCEPT ![self] = "r10"]
            /\ UNCHANGED << opF, waiters, onPrQ, wPend, prEmpty, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, viol, nr, got, ret, 
                            old, bo, sg, np, rdbl, ans, wold >>

r10(self) == /\ pc[self] = "r10"
             /\ IF opF
                   THEN /\ onQ' = onQ \ {self}
                        /\ pc' = [pc EXCEPT ![self] = "r12"]
                        /\ UNCHANGED << ret, sg >>
                   ELSE /\ IF sig[self]
                              THEN /\ onQ' = onQ \ {self}
                                   /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                                   /\ sg' = [sg EXCEPT ![self] = TRUE]
                                   /\ pc' = [pc EXCEPT ![self] = "r12"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "r11"]
                                   /\ UNCHANGED << onQ, ret, sg >>
             /\ UNCHANGED << opF, waiters, onPrQ, wk, wPend, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                             got, old, bo, np, rdbl, ans, wold >>

r11(self) == /\ pc[self] = "r11"
             /\ self \in wk \/ sig[self]
             /\ pc' = [pc EXCEPT ![self] = "r9"]
             /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                             prPend, srvUp, srvOp, prData, good, sig, nsig, 
                             viol, nr, got, ret, old, bo, sg, np, rdbl, ans, 
                             wold >>

r12(self) == /\ pc[self] = "r12"
             /\ waiters' = waiters - 1
             /\ IF ret[self] = "erestartsys"
                   THEN /\ pc' = [pc EXCEPT ![self] = "rE"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "r1"]
             /\ UNCHANGED << opF, onQ, onPrQ, wk, wPend, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                             got, ret, old, bo, sg, np, rdbl, ans, wold >>

rE(self) == /\ pc[self] = "rE"
            /\ LET rv == IF Pr(self) /\ Nb(self) /\ ret[self] # "data" THEN "eagain"
                         ELSE ret[self] IN
                 viol' =     viol
                         \cup (IF rv \notin Allowed(self) THEN {"Result"} ELSE {})
                         \cup (IF Pr(self) /\ Nb(self) /\ rv = "eagain" /\ ~sg[self] /\ ~bo[self]
                               THEN {"PrNoBackoff"} ELSE {})
            /\ sig' = [sig EXCEPT ![self] = FALSE]
            /\ got' = [got EXCEPT ![self] = "none"]
            /\ ret' = [ret EXCEPT ![self] = "none"]
            /\ old' = [old EXCEPT ![self] = FALSE]
            /\ bo' = [bo EXCEPT ![self] = FALSE]
            /\ sg' = [sg EXCEPT ![self] = FALSE]
            /\ pc' = [pc EXCEPT ![self] = "r0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, nsig, nr, np, 
                            rdbl, ans, wold >>

rd(self) == r0(self) \/ r1(self) \/ r2(self) \/ r3(self) \/ r4(self)
               \/ r5(self) \/ r6(self) \/ r6a(self) \/ r7(self) \/ r8(self)
               \/ r9(self) \/ r10(self) \/ r11(self) \/ r12(self)
               \/ rE(self)

p0(self) == /\ pc[self] = "p0"
            /\ IF np[self] < MaxPolls
                  THEN /\ np' = [np EXCEPT ![self] = np[self] + 1]
                       /\ pc' = [pc EXCEPT ![self] = "p1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ np' = np
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, nr, got, ret, old, bo, sg, rdbl, ans, wold >>

p1(self) == /\ pc[self] = "p1"
            /\ onQ' = (onQ \cup {self})
            /\ IF self = "pp"
                  THEN /\ onPrQ' = (onPrQ \cup {self})
                  ELSE /\ TRUE
                       /\ onPrQ' = onPrQ
            /\ wk' = wk \ {self}
            /\ pc' = [pc EXCEPT ![self] = "p2"]
            /\ UNCHANGED << opF, waiters, wPend, prEmpty, prPend, srvUp, srvOp, 
                            prData, good, sig, nsig, viol, nr, got, ret, old, 
                            bo, sg, np, rdbl, ans, wold >>

p2(self) == /\ pc[self] = "p2"
            /\ IF ~opF
                  THEN /\ wPend' = TRUE
                       /\ rdbl' = [rdbl EXCEPT ![self] = FALSE]
                  ELSE /\ rdbl' = [rdbl EXCEPT ![self] = self = "rp" \/ ~prEmpty]
                       /\ wPend' = wPend
            /\ pc' = [pc EXCEPT ![self] = "p3"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                            got, ret, old, bo, sg, np, ans, wold >>

p3(self) == /\ pc[self] = "p3"
            /\ IF rdbl[self]
                  THEN /\ onQ' = onQ \ {self}
                       /\ onPrQ' = onPrQ \ {self}
                       /\ rdbl' = [rdbl EXCEPT ![self] = FALSE]
                       /\ pc' = [pc EXCEPT ![self] = "p0"]
                       /\ wk' = wk
                  ELSE /\ self \in wk
                       /\ wk' = wk \ {self}
                       /\ pc' = [pc EXCEPT ![self] = "p2"]
                       /\ UNCHANGED << onQ, onPrQ, rdbl >>
            /\ UNCHANGED << opF, waiters, wPend, prEmpty, prPend, srvUp, srvOp, 
                            prData, good, sig, nsig, viol, nr, got, ret, old, 
                            bo, sg, np, ans, wold >>

pl(self) == p0(self) \/ p1(self) \/ p2(self) \/ p3(self)

w0(self) == /\ pc[self] = "w0"
            /\ wPend
            /\ wPend' = FALSE
            /\ pc' = [pc EXCEPT ![self] = "w1"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                            got, ret, old, bo, sg, np, rdbl, ans, wold >>

w1(self) == /\ pc[self] = "w1"
            /\ \E a \in StateAns:
                 ans' = [ans EXCEPT ![self] = a]
            /\ pc' = [pc EXCEPT ![self] = "w2"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, nr, got, ret, old, bo, sg, np, rdbl, wold >>

w2(self) == /\ pc[self] = "w2"
            /\ wold' = [wold EXCEPT ![self] = opF]
            /\ opF' = (ans[self] = "op")
            /\ pc' = [pc EXCEPT ![self] = "w3"]
            /\ UNCHANGED << waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                            got, ret, old, bo, sg, np, rdbl, ans >>

w3(self) == /\ pc[self] = "w3"
            /\ IF ans[self] = "op" /\ ~wold[self]
                  THEN /\ wk' = (wk \cup onQ)
                       /\ onQ' = (onQ \cap Pollers)
                       /\ wPend' = wPend
                  ELSE /\ IF ans[self] # "op" /\ wold[self] /\ KickOnUnset /\ Waiting
                             THEN /\ wPend' = TRUE
                             ELSE /\ TRUE
                                  /\ wPend' = wPend
                       /\ UNCHANGED << onQ, wk >>
            /\ ans' = [ans EXCEPT ![self] = "none"]
            /\ wold' = [wold EXCEPT ![self] = FALSE]
            /\ pc' = [pc EXCEPT ![self] = "w4"]
            /\ UNCHANGED << opF, waiters, onPrQ, prEmpty, prPend, srvUp, srvOp, 
                            prData, good, sig, nsig, viol, nr, got, ret, old, 
                            bo, sg, np, rdbl >>

w4(self) == /\ pc[self] = "w4"
            /\ IF ~opF
                  THEN /\ pc' = [pc EXCEPT ![self] = "w5"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "w0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            viol, nr, got, ret, old, bo, sg, np, rdbl, ans, 
                            wold >>

w5(self) == /\ pc[self] = "w5"
            /\ IF Waiting
                  THEN /\ wPend' = TRUE
                  ELSE /\ TRUE
                       /\ wPend' = wPend
            /\ pc' = [pc EXCEPT ![self] = "w0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, viol, nr, 
                            got, ret, old, bo, sg, np, rdbl, ans, wold >>

wa(self) == w0(self) \/ w1(self) \/ w2(self) \/ w3(self) \/ w4(self)
               \/ w5(self)

x0(self) == /\ pc[self] = "x0"
            /\ prPend /\ ~prEmpty
            /\ prPend' = FALSE
            /\ wk' = (wk \cup onPrQ)
            /\ pc' = [pc EXCEPT ![self] = "x0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wPend, prEmpty, srvUp, 
                            srvOp, prData, good, sig, nsig, viol, nr, got, ret, 
                            old, bo, sg, np, rdbl, ans, wold >>

pw(self) == x0(self)

e0(self) == /\ pc[self] = "e0"
            /\ \/ /\ prEmpty
                  /\ prEmpty' = FALSE
                  /\ UNCHANGED <<srvUp, srvOp, prData, good, sig, nsig>>
               \/ /\ ~good
                  /\ srvUp' = ~srvUp
                  /\ srvOp' = FALSE
                  /\ UNCHANGED <<prEmpty, prData, good, sig, nsig>>
               \/ /\ ~good /\ srvUp
                  /\ srvOp' = ~srvOp
                  /\ UNCHANGED <<prEmpty, srvUp, prData, good, sig, nsig>>
               \/ /\ ~good
                  /\ prData' = ~prData
                  /\ UNCHANGED <<prEmpty, srvUp, srvOp, good, sig, nsig>>
               \/ /\ ~good /\ nsig < MaxSig
                  /\ \E r \in {x \in Readers : pc[x] \notin {"r0", "Done"}
                                               /\ ~sig[x]}:
                       sig' = [sig EXCEPT ![r] = TRUE]
                  /\ nsig' = nsig + 1
                  /\ UNCHANGED <<prEmpty, srvUp, srvOp, prData, good>>
               \/ /\ Liveness /\ ~good
                  /\ good' = TRUE
                  /\ srvUp' = TRUE
                  /\ srvOp' = TRUE
                  /\ prData' = TRUE
                  /\ UNCHANGED <<prEmpty, sig, nsig>>
            /\ pc' = [pc EXCEPT ![self] = "e0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prPend, viol, 
                            nr, got, ret, old, bo, sg, np, rdbl, ans, wold >>

e(self) == e0(self)

Next == (\E self \in Readers: rd(self))
           \/ (\E self \in Pollers: pl(self))
           \/ (\E self \in {Watch}: wa(self))
           \/ (\E self \in {PrWake}: pw(self))
           \/ (\E self \in {Env}: e(self))

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Readers : WF_vars(rd(self))
        /\ \A self \in Pollers : WF_vars(pl(self))
        /\ \A self \in {Watch} : WF_vars(wa(self))
        /\ \A self \in {PrWake} : WF_vars(pw(self))
        /\ \A self \in {Env} : WF_vars(e(self))

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ opF \in BOOLEAN
    /\ waiters \in 0..Cardinality(Readers)
    /\ onQ \subseteq Readers \cup Pollers
    /\ onPrQ \subseteq Pollers

\* Every read returns data, -EAGAIN, -ERESTARTSYS or, from
\* /dev/esdm_urandom, the error of the ESDM: a blocking read of
\* /dev/esdm_random or /dev/esdm_pr waits for an ESDM it cannot reach, and
\* a read of /dev/esdm_pr with O_NONBLOCK gives data or -EAGAIN only.
ReadResult == "Result" \notin viol

\* A read of /dev/esdm_pr with O_NONBLOCK that returns -EAGAIN without a
\* signal has the poll report the device not readable for the next 50 ms.
PrBackoff == "PrNoBackoff" \notin viol

\* esdm_cdev_waiters counts the readers in esdm_cdev_wait_operational().
WaitersCount ==
    waiters = Cardinality({r \in Readers :
                           pc[r] \in {"r8", "r9", "r10", "r11", "r12"}})

\* Once the ESDM is good, no reader sleeps for it to turn operational while
\* nothing but time can happen: somebody is left to wake it.
NoLostWakeup ==
    good /\ (\E r \in Readers : pc[r] = "r11" /\ r \notin wk /\ ~sig[r])
        => \/ \E q \in Readers : ENABLED rd(q)
           \/ \E q \in Pollers : ENABLED pl(q)
           \/ ENABLED wa(Watch)
           \/ ENABLED pw(PrWake)

-----------------------------------------------------------------------------
(* Liveness, once the environment stays good *)

\* Every read returns.
ReadsReturn ==
    <>[]good => \A r \in Readers :
                    [](pc[r] \notin {"r0", "Done"}
                       => <>(pc[r] \in {"r0", "Done"}))

\* Every poll() returns readable: no poller sleeps on while the device is
\* readable.
PollsReturn ==
    <>[]good => \A q \in Pollers :
                    [](pc[q] \notin {"p0", "Done"}
                       => <>(pc[q] \in {"p0", "Done"}))
=============================================================================
