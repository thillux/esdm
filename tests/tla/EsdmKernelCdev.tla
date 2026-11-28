--------------------------- MODULE EsdmKernelCdev ---------------------------
(***************************************************************************)
(* The devices of the kernel module esdm_cdev: esdm_cdev_read() and the    *)
(* poll functions of kernel/esdm_cdev/esdm_cdev_main.c with the flag that  *)
(* the ESDM is operational, its waiters and watcher, and the back-off of   *)
(* /dev/esdm_pr after a prediction resistant read that found nothing. One  *)
(* step is one atomic variable access, one wait queue operation or one     *)
(* request to the ESDM; the labels name the C functions they come from.    *)
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
(*   and nothing changes any more. Signals come only before that. The     *)
(*   environment may turn good at any time and need not ever: a state in   *)
(*   which the module hangs has the same one with a good ESDM as its       *)
(*   successor, where TLC reports the deadlock. Once good and with every   *)
(*   read and poll() returned, the environment idles: the one state        *)
(*   without anything left to do that is no deadlock.                      *)
(* - Time: the 50 ms after a prediction resistant read that found nothing  *)
(*   are a flag that time clears; the wake work fires no earlier. One step *)
(*   of time ends the 50 ms of everything before it. The delays of the     *)
(*   watcher and the back-off of its interval only delay it and are left   *)
(*   out. The 50 ms a blocking prediction resistant read sleeps are one    *)
(*   step.                                                                 *)
(* - Wait queues: a waiter on esdm_cdev_wait is removed by its wakeup, a   *)
(*   poller stays registered until its poll() returns; a wakeup sets the   *)
(*   woken flag that schedule() and poll_schedule_timeout() wait for.      *)
(*   wait_event_interruptible() looks at its condition once more before it *)
(*   queues the task, which the look after queuing covers.                 *)
(* - A read asks for one chunk; copy_to_user() succeeds, kvmalloc() fails  *)
(*   where AllocFail says so. A poll() asks for readability, without       *)
(*   timeout or signal. The file flag O_SYNC makes a read of               *)
(*   /dev/esdm_random one of the prediction resistance DRNG; the poll      *)
(*   function of the device does not look at it.                           *)
(*   Not modelled: writes, the ioctls, /proc/esdm, module unload.          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Readers,      \* reader threads, named after their device and mode, RK
    Pollers,      \* poll() callers: "rp" /dev/esdm_random, "pp" /dev/esdm_pr,
                  \* "sp" /dev/esdm_random opened with O_SYNC
    MaxReads,     \* reads per reader
    MaxPolls,     \* poll() calls per poller
    MaxSig,       \* signals in all
    AllocFail,    \* kvmalloc() of a read may fail
    KickOnUnset,  \* turning the flag off kicks the watcher for waiters (the
                  \* code since the fix)
    AllocBackoff, \* a non-blocking read of /dev/esdm_pr without memory arms
                  \* the back-off (the code since the fix)
    SleepFix      \* a blocking prediction resistant read woken early looks
                  \* for the signal (the code since the fix) instead of
                  \* taking any early wakeup for one

\* device, O_NONBLOCK and O_SYNC of each reader; "pr" is /dev/esdm_pr
RK == [rb |-> [dev |-> "random", nb |-> FALSE, sync |-> FALSE],
       rb2 |-> [dev |-> "random", nb |-> FALSE, sync |-> FALSE],
       rn |-> [dev |-> "random", nb |-> TRUE, sync |-> FALSE],
       sb |-> [dev |-> "random", nb |-> FALSE, sync |-> TRUE],
       sn |-> [dev |-> "random", nb |-> TRUE, sync |-> TRUE],
       ub |-> [dev |-> "urandom", nb |-> FALSE, sync |-> FALSE],
       un |-> [dev |-> "urandom", nb |-> TRUE, sync |-> FALSE],
       pb |-> [dev |-> "pr", nb |-> FALSE, sync |-> FALSE],
       pn |-> [dev |-> "pr", nb |-> TRUE, sync |-> FALSE]]
PrDev(r) == RK[r].dev = "pr"
\* the read is one of the prediction resistance DRNG
Pr(r) == PrDev(r) \/ RK[r].sync
Ur(r) == RK[r].dev = "urandom"
Nb(r) == RK[r].nb
\* /dev/esdm_pr with O_NONBLOCK: data or -EAGAIN only
PrNb(r) == PrDev(r) /\ Nb(r)
Watch == "watch"
PrWake == "prwake"
Env == "env"

\* what a read may return: data, or -EAGAIN, -ERESTARTSYS, -ENOMEM and, for
\* /dev/esdm_urandom, the error of the request; /dev/esdm_pr with
\* O_NONBLOCK data or -EAGAIN only
Allowed(r) ==
    IF PrNb(r) THEN {"data", "eagain"}
    ELSE {"data", "erestartsys", "enomem"}
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
    \* what the properties go by, none of it read by the module:
    \* a non-blocking prediction resistant read found nothing - no data in
    \* the answer, or no memory - less than 50 ms ago
    fresh = [r \in Readers |-> FALSE],
    \* such a read returned -EAGAIN less than 50 ms after it found nothing,
    \* and no read recorded data since: poll() owes "not readable"
    owed = FALSE,
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
    NoFresh == [r \in Readers |-> FALSE]
}

\* wake_up_interruptible_all(&esdm_cdev_wait): wait_event entries are
\* removed, poll entries stay
macro wakeAll() {
    wk := wk \cup onQ;
    onQ := onQ \cap Pollers;
}

\* esdm_cdev_read() of a reader's device
fair process (rd \in Readers)
    variables nr = 0, got = "none", ret = "none", old = FALSE, intr = FALSE;
{
r0: while (nr < MaxReads) {
        nr := nr + 1;
        \* kvmalloc()
rA:     if (AllocFail) {
            either skip
            or {
                ret := "enomem";
                if (PrNb(self)) fresh[self] := TRUE;
                goto rM;
            };
        };
        \* the loop: a signal ends the read
r1:     if (sig[self]) {
            ret := "erestartsys";
            goto rE;
        };
        \* esdm_cdev_egd_read()
r2:     with (a \in ReadAns(self)) {
            got := a;
            if (Pr(self) /\ Nb(self) /\ a \in {"zero", "err"})
                fresh[self] := TRUE;
        };
        \* an interrupted request ends the read, an unreachable ESDM a read
        \* of /dev/esdm_urandom; otherwise the answer tells the state
r3:     if (got = "erestartsys" \/ (got = "err" /\ Ur(self))) {
            ret := got;
            goto rE;
        } else if (~Pr(self)) {
            \* esdm_cdev_set_operational(got)
            old := opF;
            opF := got = "data";
        } else if (got = "data") {
            \* esdm_cdev_pr_result(true): data recorded
            prEmpty := FALSE;
            owed := FALSE;
            fresh := NoFresh;
        } else {
            \* esdm_cdev_pr_result(false): esdm_cdev_pr_empty_until
            prEmpty := TRUE;
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
            goto rS;
        };
        \* esdm_cdev_wait_operational(): esdm_cdev_set_operational(false)
r6:     old := opF;
        opF := FALSE;
r6a:    if (old /\ KickOnUnset /\ Waiting) wPend := TRUE;
r7:     waiters := waiters + 1;
        \* esdm_cdev_watch_kick()
r8:     wPend := TRUE;
        \* wait_event_interruptible(): prepare_to_wait_event() queues the
        \* task unless a signal is pending
r9:     if (sig[self]) {
            onQ := onQ \ {self};
            intr := TRUE;
        } else {
            onQ := onQ \cup {self};
            wk := wk \ {self};
        };
        \* ... the condition, then the signal prepare_to_wait_event() found
r10:    if (opF) {
            \* finish_wait()
            onQ := onQ \ {self};
            goto r12;
        } else if (intr) {
            ret := "erestartsys";
            goto r12;
        };
        \* ... schedule() until woken or signalled
r11:    await self \in wk \/ sig[self];
        goto r9;
r12:    waiters := waiters - 1;
        if (ret = "erestartsys") goto rE else goto r1;
        \* schedule_timeout_interruptible() for the rest of a blocking
        \* prediction resistant read: the 50 ms pass, or a signal or any
        \* other wakeup ends it early. The loop looks for the signal; the
        \* code before the fix took every early end for one.
rS:     if (SleepFix) {
            goto r1;
        } else if (sig[self]) {
            ret := "erestartsys";
            goto rE;
        } else {
            either goto r1
            or {
                ret := "erestartsys";
                goto rE;
            };
        };
        \* no memory: /dev/esdm_pr with O_NONBLOCK returns -EAGAIN, since
        \* the fix after esdm_cdev_pr_result(false)
rM:     if (PrNb(self) /\ AllocBackoff) prEmpty := TRUE else goto rE;
rM2:    prPend := TRUE;
        \* what the read returns; /dev/esdm_pr with O_NONBLOCK -EAGAIN for
        \* anything but data
rE:     with (rv = IF PrNb(self) /\ ret # "data" THEN "eagain" ELSE ret) {
            viol := viol
                \cup (IF rv \notin Allowed(self) THEN {"Result"} ELSE {})
                \cup (IF rv = "erestartsys" /\ ~sig[self] THEN {"Restart"}
                      ELSE {});
            if (rv = "eagain" /\ fresh[self]) owed := TRUE;
        };
        fresh[self] := FALSE;
        sig[self] := FALSE;
        got := "none";
        ret := "none";
        old := FALSE;
        intr := FALSE;
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
        \* the poll function: the flag
p2:     if (~opF) {
            rdbl := FALSE;
            goto p2k;
        } else if (self # "pp") {
            \* esdm_cdev_poll(): readable, whatever the file flags
            rdbl := TRUE;
            if (self = "sp" /\ owed) viol := viol \cup {"SyncNoBackoff"};
            goto p4;
        };
        \* esdm_cdev_pr_poll(): not readable within the 50 ms
p3:     rdbl := ~prEmpty;
        if (~prEmpty /\ owed) viol := viol \cup {"PrNoBackoff"};
        goto p4;
        \* esdm_cdev_watch_kick()
p2k:    wPend := TRUE;
p4:     if (rdbl) {
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
            await prEmpty \/ owed \/ fresh # NoFresh;
            prEmpty := FALSE;
            owed := FALSE;
            fresh := NoFresh;
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
            await ~good;
            good := TRUE;
            srvUp := TRUE;
            srvOp := TRUE;
            prData := TRUE;
        } or {
            \* every read and poll() returned from a good ESDM: idle
            await good /\ \A p \in Readers \cup Pollers : pc[p] = "Done";
            skip;
        };
    };
}

} *)
\* BEGIN TRANSLATION
VARIABLES opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, srvUp, srvOp, 
          prData, good, sig, nsig, fresh, owed, viol, pc

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
NoFresh == [r \in Readers |-> FALSE]

VARIABLES nr, got, ret, old, intr, np, rdbl, ans, wold

vars == << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, srvUp, srvOp, 
           prData, good, sig, nsig, fresh, owed, viol, pc, nr, got, ret, old, 
           intr, np, rdbl, ans, wold >>

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
        /\ fresh = [r \in Readers |-> FALSE]
        /\ owed = FALSE
        /\ viol = {}
        (* Process rd *)
        /\ nr = [self \in Readers |-> 0]
        /\ got = [self \in Readers |-> "none"]
        /\ ret = [self \in Readers |-> "none"]
        /\ old = [self \in Readers |-> FALSE]
        /\ intr = [self \in Readers |-> FALSE]
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
                       /\ pc' = [pc EXCEPT ![self] = "rA"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ nr' = nr
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, got, ret, old, intr, np, rdbl, 
                            ans, wold >>

rA(self) == /\ pc[self] = "rA"
            /\ IF AllocFail
                  THEN /\ \/ /\ TRUE
                             /\ pc' = [pc EXCEPT ![self] = "r1"]
                             /\ UNCHANGED <<fresh, ret>>
                          \/ /\ ret' = [ret EXCEPT ![self] = "enomem"]
                             /\ IF PrNb(self)
                                   THEN /\ fresh' = [fresh EXCEPT ![self] = TRUE]
                                   ELSE /\ TRUE
                                        /\ fresh' = fresh
                             /\ pc' = [pc EXCEPT ![self] = "rM"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "r1"]
                       /\ UNCHANGED << fresh, ret >>
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            owed, viol, nr, got, old, intr, np, rdbl, ans, 
                            wold >>

r1(self) == /\ pc[self] = "r1"
            /\ IF sig[self]
                  THEN /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                       /\ pc' = [pc EXCEPT ![self] = "rE"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "r2"]
                       /\ ret' = ret
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, nr, got, old, intr, np, rdbl, 
                            ans, wold >>

r2(self) == /\ pc[self] = "r2"
            /\ \E a \in ReadAns(self):
                 /\ got' = [got EXCEPT ![self] = a]
                 /\ IF Pr(self) /\ Nb(self) /\ a \in {"zero", "err"}
                       THEN /\ fresh' = [fresh EXCEPT ![self] = TRUE]
                       ELSE /\ TRUE
                            /\ fresh' = fresh
            /\ pc' = [pc EXCEPT ![self] = "r3"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            owed, viol, nr, ret, old, intr, np, rdbl, ans, 
                            wold >>

r3(self) == /\ pc[self] = "r3"
            /\ IF got[self] = "erestartsys" \/ (got[self] = "err" /\ Ur(self))
                  THEN /\ ret' = [ret EXCEPT ![self] = got[self]]
                       /\ pc' = [pc EXCEPT ![self] = "rE"]
                       /\ UNCHANGED << opF, prEmpty, fresh, owed, old >>
                  ELSE /\ IF ~Pr(self)
                             THEN /\ old' = [old EXCEPT ![self] = opF]
                                  /\ opF' = (got[self] = "data")
                                  /\ UNCHANGED << prEmpty, fresh, owed >>
                             ELSE /\ IF got[self] = "data"
                                        THEN /\ prEmpty' = FALSE
                                             /\ owed' = FALSE
                                             /\ fresh' = NoFresh
                                        ELSE /\ prEmpty' = TRUE
                                             /\ UNCHANGED << fresh, owed >>
                                  /\ UNCHANGED << opF, old >>
                       /\ pc' = [pc EXCEPT ![self] = "r4"]
                       /\ ret' = ret
            /\ UNCHANGED << waiters, onQ, onPrQ, wk, wPend, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, viol, nr, got, 
                            intr, np, rdbl, ans, wold >>

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
                            good, sig, nsig, fresh, owed, viol, nr, got, ret, 
                            old, intr, np, rdbl, ans, wold >>

r5(self) == /\ pc[self] = "r5"
            /\ IF got[self] = "data"
                  THEN /\ ret' = [ret EXCEPT ![self] = "data"]
                       /\ pc' = [pc EXCEPT ![self] = "rE"]
                  ELSE /\ IF Nb(self)
                             THEN /\ ret' = [ret EXCEPT ![self] = "eagain"]
                                  /\ pc' = [pc EXCEPT ![self] = "rE"]
                             ELSE /\ IF Pr(self)
                                        THEN /\ pc' = [pc EXCEPT ![self] = "rS"]
                                        ELSE /\ pc' = [pc EXCEPT ![self] = "r6"]
                                  /\ ret' = ret
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, nr, got, old, intr, np, rdbl, 
                            ans, wold >>

r6(self) == /\ pc[self] = "r6"
            /\ old' = [old EXCEPT ![self] = opF]
            /\ opF' = FALSE
            /\ pc' = [pc EXCEPT ![self] = "r6a"]
            /\ UNCHANGED << waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, fresh, owed, 
                            viol, nr, got, ret, intr, np, rdbl, ans, wold >>

r6a(self) == /\ pc[self] = "r6a"
             /\ IF old[self] /\ KickOnUnset /\ Waiting
                   THEN /\ wPend' = TRUE
                   ELSE /\ TRUE
                        /\ wPend' = wPend
             /\ pc' = [pc EXCEPT ![self] = "r7"]
             /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, fresh, 
                             owed, viol, nr, got, ret, old, intr, np, rdbl, 
                             ans, wold >>

r7(self) == /\ pc[self] = "r7"
            /\ waiters' = waiters + 1
            /\ pc' = [pc EXCEPT ![self] = "r8"]
            /\ UNCHANGED << opF, onQ, onPrQ, wk, wPend, prEmpty, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, fresh, owed, viol, 
                            nr, got, ret, old, intr, np, rdbl, ans, wold >>

r8(self) == /\ pc[self] = "r8"
            /\ wPend' = TRUE
            /\ pc' = [pc EXCEPT ![self] = "r9"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, fresh, owed, 
                            viol, nr, got, ret, old, intr, np, rdbl, ans, wold >>

r9(self) == /\ pc[self] = "r9"
            /\ IF sig[self]
                  THEN /\ onQ' = onQ \ {self}
                       /\ intr' = [intr EXCEPT ![self] = TRUE]
                       /\ wk' = wk
                  ELSE /\ onQ' = (onQ \cup {self})
                       /\ wk' = wk \ {self}
                       /\ intr' = intr
            /\ pc' = [pc EXCEPT ![self] = "r10"]
            /\ UNCHANGED << opF, waiters, onPrQ, wPend, prEmpty, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, fresh, owed, viol, 
                            nr, got, ret, old, np, rdbl, ans, wold >>

r10(self) == /\ pc[self] = "r10"
             /\ IF opF
                   THEN /\ onQ' = onQ \ {self}
                        /\ pc' = [pc EXCEPT ![self] = "r12"]
                        /\ ret' = ret
                   ELSE /\ IF intr[self]
                              THEN /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                                   /\ pc' = [pc EXCEPT ![self] = "r12"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "r11"]
                                   /\ ret' = ret
                        /\ onQ' = onQ
             /\ UNCHANGED << opF, waiters, onPrQ, wk, wPend, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, fresh, 
                             owed, viol, nr, got, old, intr, np, rdbl, ans, 
                             wold >>

r11(self) == /\ pc[self] = "r11"
             /\ self \in wk \/ sig[self]
             /\ pc' = [pc EXCEPT ![self] = "r9"]
             /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                             prPend, srvUp, srvOp, prData, good, sig, nsig, 
                             fresh, owed, viol, nr, got, ret, old, intr, np, 
                             rdbl, ans, wold >>

r12(self) == /\ pc[self] = "r12"
             /\ waiters' = waiters - 1
             /\ IF ret[self] = "erestartsys"
                   THEN /\ pc' = [pc EXCEPT ![self] = "rE"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "r1"]
             /\ UNCHANGED << opF, onQ, onPrQ, wk, wPend, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, fresh, 
                             owed, viol, nr, got, ret, old, intr, np, rdbl, 
                             ans, wold >>

rS(self) == /\ pc[self] = "rS"
            /\ IF SleepFix
                  THEN /\ pc' = [pc EXCEPT ![self] = "r1"]
                       /\ ret' = ret
                  ELSE /\ IF sig[self]
                             THEN /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                                  /\ pc' = [pc EXCEPT ![self] = "rE"]
                             ELSE /\ \/ /\ pc' = [pc EXCEPT ![self] = "r1"]
                                        /\ ret' = ret
                                     \/ /\ ret' = [ret EXCEPT ![self] = "erestartsys"]
                                        /\ pc' = [pc EXCEPT ![self] = "rE"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, nr, got, old, intr, np, rdbl, 
                            ans, wold >>

rM(self) == /\ pc[self] = "rM"
            /\ IF PrNb(self) /\ AllocBackoff
                  THEN /\ prEmpty' = TRUE
                       /\ pc' = [pc EXCEPT ![self] = "rM2"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "rE"]
                       /\ UNCHANGED prEmpty
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prPend, srvUp, 
                            srvOp, prData, good, sig, nsig, fresh, owed, viol, 
                            nr, got, ret, old, intr, np, rdbl, ans, wold >>

rM2(self) == /\ pc[self] = "rM2"
             /\ prPend' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "rE"]
             /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                             srvUp, srvOp, prData, good, sig, nsig, fresh, 
                             owed, viol, nr, got, ret, old, intr, np, rdbl, 
                             ans, wold >>

rE(self) == /\ pc[self] = "rE"
            /\ LET rv == IF PrNb(self) /\ ret[self] # "data" THEN "eagain" ELSE ret[self] IN
                 /\ viol' =     viol
                            \cup (IF rv \notin Allowed(self) THEN {"Result"} ELSE {})
                            \cup (IF rv = "erestartsys" /\ ~sig[self] THEN {"Restart"}
                                  ELSE {})
                 /\ IF rv = "eagain" /\ fresh[self]
                       THEN /\ owed' = TRUE
                       ELSE /\ TRUE
                            /\ owed' = owed
            /\ fresh' = [fresh EXCEPT ![self] = FALSE]
            /\ sig' = [sig EXCEPT ![self] = FALSE]
            /\ got' = [got EXCEPT ![self] = "none"]
            /\ ret' = [ret EXCEPT ![self] = "none"]
            /\ old' = [old EXCEPT ![self] = FALSE]
            /\ intr' = [intr EXCEPT ![self] = FALSE]
            /\ pc' = [pc EXCEPT ![self] = "r0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, nsig, nr, np, 
                            rdbl, ans, wold >>

rd(self) == r0(self) \/ rA(self) \/ r1(self) \/ r2(self) \/ r3(self)
               \/ r4(self) \/ r5(self) \/ r6(self) \/ r6a(self) \/ r7(self)
               \/ r8(self) \/ r9(self) \/ r10(self) \/ r11(self)
               \/ r12(self) \/ rS(self) \/ rM(self) \/ rM2(self)
               \/ rE(self)

p0(self) == /\ pc[self] = "p0"
            /\ IF np[self] < MaxPolls
                  THEN /\ np' = [np EXCEPT ![self] = np[self] + 1]
                       /\ pc' = [pc EXCEPT ![self] = "p1"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                       /\ np' = np
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, nr, got, ret, old, intr, rdbl, 
                            ans, wold >>

p1(self) == /\ pc[self] = "p1"
            /\ onQ' = (onQ \cup {self})
            /\ IF self = "pp"
                  THEN /\ onPrQ' = (onPrQ \cup {self})
                  ELSE /\ TRUE
                       /\ onPrQ' = onPrQ
            /\ wk' = wk \ {self}
            /\ pc' = [pc EXCEPT ![self] = "p2"]
            /\ UNCHANGED << opF, waiters, wPend, prEmpty, prPend, srvUp, srvOp, 
                            prData, good, sig, nsig, fresh, owed, viol, nr, 
                            got, ret, old, intr, np, rdbl, ans, wold >>

p2(self) == /\ pc[self] = "p2"
            /\ IF ~opF
                  THEN /\ rdbl' = [rdbl EXCEPT ![self] = FALSE]
                       /\ pc' = [pc EXCEPT ![self] = "p2k"]
                       /\ viol' = viol
                  ELSE /\ IF self # "pp"
                             THEN /\ rdbl' = [rdbl EXCEPT ![self] = TRUE]
                                  /\ IF self = "sp" /\ owed
                                        THEN /\ viol' = (viol \cup {"SyncNoBackoff"})
                                        ELSE /\ TRUE
                                             /\ viol' = viol
                                  /\ pc' = [pc EXCEPT ![self] = "p4"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "p3"]
                                  /\ UNCHANGED << viol, rdbl >>
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, nr, got, ret, old, intr, np, ans, 
                            wold >>

p3(self) == /\ pc[self] = "p3"
            /\ rdbl' = [rdbl EXCEPT ![self] = ~prEmpty]
            /\ IF ~prEmpty /\ owed
                  THEN /\ viol' = (viol \cup {"PrNoBackoff"})
                  ELSE /\ TRUE
                       /\ viol' = viol
            /\ pc' = [pc EXCEPT ![self] = "p4"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, nr, got, ret, old, intr, np, ans, 
                            wold >>

p2k(self) == /\ pc[self] = "p2k"
             /\ wPend' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "p4"]
             /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                             srvUp, srvOp, prData, good, sig, nsig, fresh, 
                             owed, viol, nr, got, ret, old, intr, np, rdbl, 
                             ans, wold >>

p4(self) == /\ pc[self] = "p4"
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
                            prData, good, sig, nsig, fresh, owed, viol, nr, 
                            got, ret, old, intr, np, ans, wold >>

pl(self) == p0(self) \/ p1(self) \/ p2(self) \/ p3(self) \/ p2k(self)
               \/ p4(self)

w0(self) == /\ pc[self] = "w0"
            /\ wPend
            /\ wPend' = FALSE
            /\ pc' = [pc EXCEPT ![self] = "w1"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, fresh, owed, 
                            viol, nr, got, ret, old, intr, np, rdbl, ans, wold >>

w1(self) == /\ pc[self] = "w1"
            /\ \E a \in StateAns:
                 ans' = [ans EXCEPT ![self] = a]
            /\ pc' = [pc EXCEPT ![self] = "w2"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, nr, got, ret, old, intr, np, 
                            rdbl, wold >>

w2(self) == /\ pc[self] = "w2"
            /\ wold' = [wold EXCEPT ![self] = opF]
            /\ opF' = (ans[self] = "op")
            /\ pc' = [pc EXCEPT ![self] = "w3"]
            /\ UNCHANGED << waiters, onQ, onPrQ, wk, wPend, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, fresh, owed, 
                            viol, nr, got, ret, old, intr, np, rdbl, ans >>

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
                            prData, good, sig, nsig, fresh, owed, viol, nr, 
                            got, ret, old, intr, np, rdbl >>

w4(self) == /\ pc[self] = "w4"
            /\ IF ~opF
                  THEN /\ pc' = [pc EXCEPT ![self] = "w5"]
                  ELSE /\ pc' = [pc EXCEPT ![self] = "w0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prEmpty, 
                            prPend, srvUp, srvOp, prData, good, sig, nsig, 
                            fresh, owed, viol, nr, got, ret, old, intr, np, 
                            rdbl, ans, wold >>

w5(self) == /\ pc[self] = "w5"
            /\ IF Waiting
                  THEN /\ wPend' = TRUE
                  ELSE /\ TRUE
                       /\ wPend' = wPend
            /\ pc' = [pc EXCEPT ![self] = "w0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, prEmpty, prPend, 
                            srvUp, srvOp, prData, good, sig, nsig, fresh, owed, 
                            viol, nr, got, ret, old, intr, np, rdbl, ans, wold >>

wa(self) == w0(self) \/ w1(self) \/ w2(self) \/ w3(self) \/ w4(self)
               \/ w5(self)

x0(self) == /\ pc[self] = "x0"
            /\ prPend /\ ~prEmpty
            /\ prPend' = FALSE
            /\ wk' = (wk \cup onPrQ)
            /\ pc' = [pc EXCEPT ![self] = "x0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wPend, prEmpty, srvUp, 
                            srvOp, prData, good, sig, nsig, fresh, owed, viol, 
                            nr, got, ret, old, intr, np, rdbl, ans, wold >>

pw(self) == x0(self)

e0(self) == /\ pc[self] = "e0"
            /\ \/ /\ prEmpty \/ owed \/ fresh # NoFresh
                  /\ prEmpty' = FALSE
                  /\ owed' = FALSE
                  /\ fresh' = NoFresh
                  /\ UNCHANGED <<srvUp, srvOp, prData, good, sig, nsig>>
               \/ /\ ~good
                  /\ srvUp' = ~srvUp
                  /\ srvOp' = FALSE
                  /\ UNCHANGED <<prEmpty, prData, good, sig, nsig, fresh, owed>>
               \/ /\ ~good /\ srvUp
                  /\ srvOp' = ~srvOp
                  /\ UNCHANGED <<prEmpty, srvUp, prData, good, sig, nsig, fresh, owed>>
               \/ /\ ~good
                  /\ prData' = ~prData
                  /\ UNCHANGED <<prEmpty, srvUp, srvOp, good, sig, nsig, fresh, owed>>
               \/ /\ ~good /\ nsig < MaxSig
                  /\ \E r \in {x \in Readers : pc[x] \notin {"r0", "Done"}
                                               /\ ~sig[x]}:
                       sig' = [sig EXCEPT ![r] = TRUE]
                  /\ nsig' = nsig + 1
                  /\ UNCHANGED <<prEmpty, srvUp, srvOp, prData, good, fresh, owed>>
               \/ /\ ~good
                  /\ good' = TRUE
                  /\ srvUp' = TRUE
                  /\ srvOp' = TRUE
                  /\ prData' = TRUE
                  /\ UNCHANGED <<prEmpty, sig, nsig, fresh, owed>>
               \/ /\ good /\ \A p \in Readers \cup Pollers : pc[p] = "Done"
                  /\ TRUE
                  /\ UNCHANGED <<prEmpty, srvUp, srvOp, prData, good, sig, nsig, fresh, owed>>
            /\ pc' = [pc EXCEPT ![self] = "e0"]
            /\ UNCHANGED << opF, waiters, onQ, onPrQ, wk, wPend, prPend, viol, 
                            nr, got, ret, old, intr, np, rdbl, ans, wold >>

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
    /\ wk \subseteq Readers \cup Pollers
    /\ wPend \in BOOLEAN /\ prEmpty \in BOOLEAN /\ prPend \in BOOLEAN
    /\ nsig \in 0..MaxSig
    /\ fresh \in [Readers -> BOOLEAN]
    /\ owed \in BOOLEAN
    /\ viol \subseteq {"Result", "Restart", "PrNoBackoff", "SyncNoBackoff"}

\* Every read returns data, -EAGAIN, -ERESTARTSYS, -ENOMEM or, from
\* /dev/esdm_urandom, the error of the ESDM: a blocking read of
\* /dev/esdm_random or /dev/esdm_pr waits for an ESDM it cannot reach, and
\* a read of /dev/esdm_pr with O_NONBLOCK gives data or -EAGAIN only.
ReadResult == "Result" \notin viol

\* A read returns -ERESTARTSYS only with a signal pending: without one the
\* system call is not restarted and the caller sees the value.
RestartSignal == "Restart" \notin viol

\* After a non-blocking prediction resistant read returned -EAGAIN because
\* it found nothing - no signal -, poll() of /dev/esdm_pr does not report
\* the device readable until 50 ms after the read found nothing, or until a
\* read records data. Recorded when the poll function decides, from what
\* the reads did in other steps.
PrBackoff == "PrNoBackoff" \notin viol

\* The same of poll() of /dev/esdm_random through a file opened with
\* O_SYNC. Not what the code does: esdm_cdev_poll() does not look at the
\* file flags. Only the configuration that shows it lists this property.
SyncBackoff == "SyncNoBackoff" \notin viol

\* esdm_cdev_waiters counts the readers in esdm_cdev_wait_operational().
WaitersCount ==
    waiters = Cardinality({r \in Readers :
                           pc[r] \in {"r8", "r9", "r10", "r11", "r12"}})

\* Nothing stays behind on the wait queues: a queued reader is in its
\* wait_event_interruptible(), a queued poller in its poll().
WaitQueue ==
    /\ \A r \in onQ \cap Readers : pc[r] \in {"r9", "r10", "r11"}
    /\ \A q \in onQ \cap Pollers : pc[q] \in {"p2", "p2k", "p3", "p4"}
    /\ onPrQ \subseteq onQ \cap {"pp"}

\* Once the ESDM is good, no reader sleeps for it to turn operational while
\* nothing but time can happen: somebody is left to wake it.
NoLostWakeup ==
    good /\ (\E r \in Readers : pc[r] = "r11" /\ r \notin wk /\ ~sig[r])
        => \/ \E q \in Readers : ENABLED rd(q)
           \/ \E q \in Pollers : ENABLED pl(q)
           \/ ENABLED wa(Watch)
           \/ ENABLED pw(PrWake)

-----------------------------------------------------------------------------
(* Liveness *)

\* Once the ESDM stays good, every read returns.
ReadsReturn ==
    <>[]good => \A r \in Readers :
                    [](pc[r] \notin {"r0", "Done"}
                       => <>(pc[r] \in {"r0", "Done"}))

\* Once the ESDM stays good, every poll() returns readable: no poller
\* sleeps on while the device is readable.
PollsReturn ==
    <>[]good => \A q \in Pollers :
                    [](pc[q] \notin {"p0", "Done"}
                       => <>(pc[q] \in {"p0", "Done"}))

\* A signal ends the read it finds, whatever the state of the ESDM: the
\* read returns, with data, -EAGAIN or -ERESTARTSYS.
SignalEnds == \A r \in Readers : [](sig[r] => <>(~sig[r]))

\* Once every read and poll() has returned, the watcher stops asking the
\* ESDM, whatever its state.
WatcherStops ==
    <>[](\A p \in Readers \cup Pollers : pc[p] = "Done")
        => <>[](pc[Watch] = "w0" /\ ~wPend)
=============================================================================
