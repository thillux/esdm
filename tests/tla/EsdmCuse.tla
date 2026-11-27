------------------------------- MODULE EsdmCuse -------------------------------
(***************************************************************************)
(* The CUSE daemons behind /dev/random and /dev/urandom:                   *)
(* frontends/cuse/cuse_device.c with cuse_random.c and cuse_urandom.c, at  *)
(* the granularity of their locks: read(), poll(), the privileged ioctls,  *)
(* the poll checker thread and the FUSE worker threads, together with the  *)
(* kernel's side of FUSE poll and interrupts. One step is one atomic       *)
(* variable access, one lock operation or one request or reply; the labels *)
(* name the C functions they come from.                                    *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - The server is an environment process. It changes its state (the truth *)
(*   an RPC answers from), then publishes it in the status segment and     *)
(*   posts the daemon's semaphore if it is 0, as EsdmShmStatus.tla         *)
(*   verifies; it exits (the suspend trigger, the status stays) and starts *)
(*   again (not operational, the semaphore re-synchronized), and raises    *)
(*   the suspend trigger. A bounded number of each.                        *)
(* - An RPC with the reader lock held is one step. It answers from the     *)
(*   server's state: data, -EAGAIN, or an error that sends the read to the *)
(*   kernel's device, which always has data (the kernel CRNG is ready).    *)
(* - All threads use one open file, so one fh and one kernel poll handle   *)
(*   (kh) for the file: a notification on any handle of the file wakes all *)
(*   its pollers. The kernel asks for a notification (a non-NULL handle)   *)
(*   iff a thread waits on the file's poll waitqueue (fuse_file_poll()). A *)
(*   probe is a poll() that found another fd ready first: it asks once     *)
(*   without waiting. Poll timeouts are left out.                          *)
(* - libfuse runs at most Workers requests at a time (max_threads, 10 by   *)
(*   default); the kernel hands out a queued FUSE_INTERRUPT first, and     *)
(*   libfuse marks the request it names as interrupted.                    *)
(* - The registration list holds at most one node, as all requests use one *)
(*   fh. Time is left out: esdm_cuse_poll_wait() is one step.              *)
(* - Not modelled: O_SYNC, write() (it never waits), RNDGETENTCNT and the  *)
(*   ESDM ioctls 42-44, release(), the init handshake, shutdown.           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Urandom,        \* esdm-cuse-urandom, else esdm-cuse-random
    PollIn,         \* threads in poll() for POLLIN, waiting until ready
    PollOut,        \* threads in poll() for POLLOUT
    Probe,          \* threads whose poll() asks once for POLLIN, not waiting
    Readers,        \* threads in read()
    NbReaders,      \* threads in read() with O_NONBLOCK
    Ioctls,         \* threads issuing a privileged ioctl (RNDADDENTROPY ...)
    Signalled,      \* threads getting a signal while in read()
    Workers,        \* FUSE worker threads
    StartOp,        \* the ESDM is operational at the start
    OpChanges,      \* operational state changes
    NeedChanges,    \* need_entropy changes
    SpentChanges,   \* every DRNG awaits its reseed, and no longer
    SrvChanges,     \* server exits and starts
    Suspends,       \* SIGUSR1 suspend triggers
    HonorNonblock,  \* fix: a read with O_NONBLOCK returns -EAGAIN
    KeepNullPh,     \* fix: a poll without a handle keeps the registration
    PollFallback,   \* fix: poll() follows the kernel's device where reads
                    \* use it; the exit withdraws the version, and the
                    \* checker passes every second while no server publishes
    UrandomNoSwitch \* fix: /dev/urandom keeps its getter while it waits

NoProc == "none"
NoReg == [ev |-> {}, ph |-> "none"]
PollC == PollIn \cup PollOut
ReadC == Readers \cup NbReaders
Ev(c) == IF c \in PollOut THEN {"out"} ELSE {"in"}
Post(v) == IF v = 0 THEN 1 ELSE v
NoReq == [t |-> "none", c |-> "none", ph |-> "none"]

(* --algorithm EsdmCuse {
variables
    \* the server: its state and the status it published
    srvUp = TRUE,
    esdmOp = StartOp,
    spent = FALSE,
    shmOp = StartOp,
    shmNeed = FALSE,
    shmAvail = TRUE,
    susp = FALSE,
    sem = 0,
    \* the kernel: the file's poll waitqueue, woken pollers, queued requests,
    \* replies
    onWQ = {},
    woken = [c \in PollC |-> FALSE],
    reqs = {},
    pgot = [c \in PollC \cup Probe |-> FALSE],
    pmask = [c \in PollC \cup Probe |-> {}],
    rreply = [c \in ReadC |-> "none"],
    ireply = [c \in Ioctls |-> FALSE],
    \* libfuse: requests marked interrupted
    intrd = [c \in ReadC |-> FALSE],
    \* the daemon: the registration of the fh, esdm_cuse_ph_lock and
    \* esdm_cuse_priv (writer-preferring)
    reg = NoReg,
    phLock = NoProc,
    rdrs = {},
    wrr = NoProc,
    wwait = {},
    viol = {};

define {
    \* poll() of the kernel's device, its CRNG ready
    KMask == IF Urandom THEN {"in", "out"} ELSE {"in"}
    \* esdm_cuse_get_pollmask()
    Mask == (IF PollFallback /\ ~shmAvail THEN KMask
             ELSE (IF shmOp \/ (PollFallback /\ Urandom) THEN {"in"} ELSE {})
                  \cup (IF shmNeed THEN {"out"} ELSE {}))
            \cup (IF susp THEN {"in", "out"} ELSE {})
    \* what one RPC of the read loop yields: w is the waiting getter
    \* (esdm_rpcc_get_random_bytes_full_noblock_int()), else
    \* esdm_rpcc_get_random_bytes_int(); an error goes to the kernel's device
    Rpc(w) == IF ~srvUp THEN "data"
              ELSE IF esdmOp /\ ~spent THEN "data"
              ELSE IF ~w /\ ~esdmOp THEN "data"
              ELSE "eagain"
    \* a read would not wait
    NoWait == IF Urandom THEN ~(srvUp /\ esdmOp /\ spent)
              ELSE ~srvUp \/ (esdmOp /\ ~spent)
}

\* fuse_lowlevel_notify_poll(): a handle wakes every poller of the file
macro notify(p) {
    if (p = "real") woken := [c \in PollC |-> woken[c] \/ c \in onWQ];
}

\* esdm_cuse_poll()
procedure pollH(pcl, pph)
    variables sysm = {}, evs = {};
{
     \* esdm_cuse_get_pollmask(), fuse_reply_poll()
ph1: sysm := Mask;
     pgot[pcl] := TRUE;
     pmask[pcl] := Mask \cap Ev(pcl);
     if ("in" \in Mask \cap Ev(pcl) /\ ~shmOp /\ srvUp /\ ~esdmOp)
         viol := viol \cup {"SpuriousReadable"};
     \* under esdm_cuse_ph_lock: esdm_cuse_poll_remove_fh() keeps the events
ph2: await phLock = NoProc;
     if (KeepNullPh /\ pph = "null") {
         return;
     } else if (sysm \cap (Ev(pcl) \cup reg.ev) # {}) {
         notify(pph);
         reg := NoReg;
         return;
     } else {
         evs := Ev(pcl) \cup reg.ev;
         reg := [ev |-> Ev(pcl) \cup reg.ev, ph |-> pph];
         phLock := self;
     };
     \* the re-check closing the register-after-reply window
ph3: if (Mask \cap evs # {}) {
         notify(pph);
         reg := NoReg;
     };
     phLock := NoProc;
     return;
}

\* esdm_cuse_read_internal()
procedure readH(rcl)
    variables wmode = FALSE, res = "none";
{
rh0: wmode := ~Urandom;
     \* esdm_cuse_unpriv_call_start()
rh1: await wrr = NoProc /\ wwait = {};
     rdrs := rdrs \cup {self};
     \* the RPC, esdm_cuse_unpriv_call_end()
rh2: res := Rpc(wmode);
     rdrs := rdrs \ {self};
     if (Rpc(wmode) = "eagain" /\ Urandom /\ wmode /\ ~esdmOp)
         viol := viol \cup {"UrandomWaitsNonop"};
rh3: if (res = "eagain" /\ intrd[rcl]) {
         rreply[rcl] := "eintr";
         return;
     } else if (res = "eagain" /\ HonorNonblock /\ rcl \in NbReaders) {
         rreply[rcl] := "eagain";
         return;
     } else if (res = "eagain") {
         \* -EAGAIN of esdm_rpcc_get_random_bytes_int() switches to the
         \* waiting getter; esdm_cuse_poll_wait()
         if (rcl \in NbReaders) viol := viol \cup {"NonblockWaits"};
         if (~UrandomNoSwitch) wmode := TRUE;
         res := "none";
         goto rh1;
     } else {
         rreply[rcl] := "data";
         return;
     };
}

\* esdm_cuse_ioctl(): a privileged command
procedure ioctlH(icl)
{
     \* esdm_cuse_raise_privilege_transient()
io1: wwait := wwait \cup {self};
io2: await rdrs = {} /\ wrr = NoProc;
     wrr := self;
     wwait := wwait \ {self};
     \* the RPC, the kernel's ioctl, esdm_cuse_drop_privilege_transient()
io3: wrr := NoProc;
     ireply[icl] := TRUE;
     return;
}

\* libfuse's worker threads (fuse_session_loop_mt())
fair+ process (k \in Workers)
    variables r = NoReq;
{
wk1: while (TRUE) {
         await reqs # {};
         with (q \in IF \E x \in reqs : x.t = "intr"
                     THEN {x \in reqs : x.t = "intr"} ELSE reqs) {
             r := q;
             reqs := reqs \ {q};
         };
wk2:     if (r.t = "poll") {
             call pollH(r.c, r.ph);
         } else if (r.t = "read") {
             call readH(r.c);
         } else if (r.t = "ioctl") {
             call ioctlH(r.c);
         } else {
             \* do_interrupt()
             intrd[r.c] := TRUE;
         };
wk3:     r := NoReq;
     }
}

\* esdm_cuse_poll_checker(): a pass under esdm_cuse_ph_lock, then
\* esdm_cuse_shm_status_down()
fair+ process (ck = "ck")
{
ck1: while (TRUE) {
         await phLock = NoProc;
         if (reg # NoReg /\ Mask \cap reg.ev # {}) {
             notify(reg.ph);
             reg := NoReg;
         };
         susp := FALSE;
ck2:     if (PollFallback /\ ~shmAvail) {
             \* no server publishes: another pass after a second
             goto ck1;
         } else {
             await sem > 0;
             sem := sem - 1;
         };
     }
}

\* threads in poll(): fuse_file_poll() and do_poll()
fair process (pl \in PollC)
{
     \* poll_wait() puts the thread on the waitqueue, so the request asks
     \* for a notification
pl1: onWQ := onWQ \cup {self};
     reqs := reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]};
pl2: await pgot[self];
     pgot[self] := FALSE;
     if (pmask[self] # {}) {
         onWQ := onWQ \ {self};
         woken[self] := FALSE;
         goto plDone;
     } else if (woken[self]) {
         woken[self] := FALSE;
         reqs := reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]};
         goto pl2;
     };
     \* asleep on the waitqueue
pl3: await woken[self];
     woken[self] := FALSE;
     reqs := reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]};
     goto pl2;
plDone: skip;
}

\* a poll() that found another fd ready: no poll_wait(), so a handle only if
\* another thread waits on the file
fair process (pr \in Probe)
{
pr1: reqs := reqs \cup {[t |-> "poll", c |-> self,
                         ph |-> IF onWQ = {} THEN "null" ELSE "real"]};
pr2: await pgot[self];
}

\* threads in read(), perhaps getting a signal
fair process (rd \in ReadC)
    variables sigd = FALSE;
{
rc1: reqs := reqs \cup {[t |-> "read", c |-> self, ph |-> "none"]};
rc2: either {
         await rreply[self] # "none";
     } or {
         \* the kernel queues FUSE_INTERRUPT and waits on
         await self \in Signalled /\ ~sigd /\ rreply[self] = "none";
         sigd := TRUE;
         reqs := reqs \cup {[t |-> "intr", c |-> self, ph |-> "none"]};
         goto rc2;
     };
rcDone: skip;
}

fair process (io \in Ioctls)
{
ic1: reqs := reqs \cup {[t |-> "ioctl", c |-> self, ph |-> "none"]};
ic2: await ireply[self];
}

\* the server
fair process (env = "env")
    variables opc = 0, ndc = 0, spc = 0, svc = 0, ssc = 0;
{
en1: while (TRUE) {
         either {
             \* the initial DRNG changes state, then
             \* esdm_shm_status_set_operational() publishes it
             await srvUp /\ opc < OpChanges;
             opc := opc + 1;
             esdmOp := ~esdmOp;
en2:         shmOp := esdmOp;
             sem := Post(sem);
         } or {
             \* esdm_shm_status_set_need_entropy()
             await srvUp /\ ndc < NeedChanges;
             ndc := ndc + 1;
             shmNeed := ~shmNeed;
             sem := Post(sem);
         } or {
             \* operational, every DRNG awaits its reseed
             await srvUp /\ esdmOp /\ spc < SpentChanges;
             spc := spc + 1;
             spent := ~spent;
         } or {
             \* esdm_shm_status_signal_suspend()
             await srvUp /\ ssc < Suspends;
             ssc := ssc + 1;
             susp := TRUE;
             sem := Post(sem);
         } or {
             \* the exit: the version withdrawn with PollFallback, else the
             \* status stays; esdm_shm_status_server_exit()
             await srvUp /\ svc < SrvChanges;
             svc := svc + 1;
             srvUp := FALSE;
             esdmOp := FALSE;
             spent := FALSE;
             if (PollFallback) shmAvail := FALSE;
             susp := TRUE;
             sem := Post(sem);
         } or {
             \* a new server: esdm_shm_status_init() publishes, posting, then
             \* the RPC sockets serve
             await ~srvUp /\ svc < SrvChanges;
             svc := svc + 1;
             shmOp := FALSE;
             shmAvail := TRUE;
             sem := Post(sem);
en3:         srvUp := TRUE;
         };
     }
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, susp, sem, onWQ, 
          woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, phLock, rdrs, 
          wrr, wwait, viol, pc, stack

(* define statement *)
KMask == IF Urandom THEN {"in", "out"} ELSE {"in"}

Mask == (IF PollFallback /\ ~shmAvail THEN KMask
         ELSE (IF shmOp \/ (PollFallback /\ Urandom) THEN {"in"} ELSE {})
              \cup (IF shmNeed THEN {"out"} ELSE {}))
        \cup (IF susp THEN {"in", "out"} ELSE {})



Rpc(w) == IF ~srvUp THEN "data"
          ELSE IF esdmOp /\ ~spent THEN "data"
          ELSE IF ~w /\ ~esdmOp THEN "data"
          ELSE "eagain"

NoWait == IF Urandom THEN ~(srvUp /\ esdmOp /\ spent)
          ELSE ~srvUp \/ (esdmOp /\ ~spent)

VARIABLES pcl, pph, sysm, evs, rcl, wmode, res, icl, r, sigd, opc, ndc, spc, 
          svc, ssc

vars == << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, susp, sem, onWQ, 
           woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, phLock, rdrs, 
           wrr, wwait, viol, pc, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
           icl, r, sigd, opc, ndc, spc, svc, ssc >>

ProcSet == (Workers) \cup {"ck"} \cup (PollC) \cup (Probe) \cup (ReadC) \cup (Ioctls) \cup {"env"}

Init == (* Global variables *)
        /\ srvUp = TRUE
        /\ esdmOp = StartOp
        /\ spent = FALSE
        /\ shmOp = StartOp
        /\ shmNeed = FALSE
        /\ shmAvail = TRUE
        /\ susp = FALSE
        /\ sem = 0
        /\ onWQ = {}
        /\ woken = [c \in PollC |-> FALSE]
        /\ reqs = {}
        /\ pgot = [c \in PollC \cup Probe |-> FALSE]
        /\ pmask = [c \in PollC \cup Probe |-> {}]
        /\ rreply = [c \in ReadC |-> "none"]
        /\ ireply = [c \in Ioctls |-> FALSE]
        /\ intrd = [c \in ReadC |-> FALSE]
        /\ reg = NoReg
        /\ phLock = NoProc
        /\ rdrs = {}
        /\ wrr = NoProc
        /\ wwait = {}
        /\ viol = {}
        (* Procedure pollH *)
        /\ pcl = [ self \in ProcSet |-> defaultInitValue]
        /\ pph = [ self \in ProcSet |-> defaultInitValue]
        /\ sysm = [ self \in ProcSet |-> {}]
        /\ evs = [ self \in ProcSet |-> {}]
        (* Procedure readH *)
        /\ rcl = [ self \in ProcSet |-> defaultInitValue]
        /\ wmode = [ self \in ProcSet |-> FALSE]
        /\ res = [ self \in ProcSet |-> "none"]
        (* Procedure ioctlH *)
        /\ icl = [ self \in ProcSet |-> defaultInitValue]
        (* Process k *)
        /\ r = [self \in Workers |-> NoReq]
        (* Process rd *)
        /\ sigd = [self \in ReadC |-> FALSE]
        (* Process env *)
        /\ opc = 0
        /\ ndc = 0
        /\ spc = 0
        /\ svc = 0
        /\ ssc = 0
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Workers -> "wk1"
                                        [] self = "ck" -> "ck1"
                                        [] self \in PollC -> "pl1"
                                        [] self \in Probe -> "pr1"
                                        [] self \in ReadC -> "rc1"
                                        [] self \in Ioctls -> "ic1"
                                        [] self = "env" -> "en1"]

ph1(self) == /\ pc[self] = "ph1"
             /\ sysm' = [sysm EXCEPT ![self] = Mask]
             /\ pgot' = [pgot EXCEPT ![pcl[self]] = TRUE]
             /\ pmask' = [pmask EXCEPT ![pcl[self]] = Mask \cap Ev(pcl[self])]
             /\ IF "in" \in Mask \cap Ev(pcl[self]) /\ ~shmOp /\ srvUp /\ ~esdmOp
                   THEN /\ viol' = (viol \cup {"SpuriousReadable"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = "ph2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, rreply, ireply, 
                             intrd, reg, phLock, rdrs, wrr, wwait, stack, pcl, 
                             pph, evs, rcl, wmode, res, icl, r, sigd, opc, ndc, 
                             spc, svc, ssc >>

ph2(self) == /\ pc[self] = "ph2"
             /\ phLock = NoProc
             /\ IF KeepNullPh /\ pph[self] = "null"
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ sysm' = [sysm EXCEPT ![self] = Head(stack[self]).sysm]
                        /\ evs' = [evs EXCEPT ![self] = Head(stack[self]).evs]
                        /\ pcl' = [pcl EXCEPT ![self] = Head(stack[self]).pcl]
                        /\ pph' = [pph EXCEPT ![self] = Head(stack[self]).pph]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << woken, reg, phLock >>
                   ELSE /\ IF sysm[self] \cap (Ev(pcl[self]) \cup reg.ev) # {}
                              THEN /\ IF pph[self] = "real"
                                         THEN /\ woken' = [c \in PollC |-> woken[c] \/ c \in onWQ]
                                         ELSE /\ TRUE
                                              /\ woken' = woken
                                   /\ reg' = NoReg
                                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ sysm' = [sysm EXCEPT ![self] = Head(stack[self]).sysm]
                                   /\ evs' = [evs EXCEPT ![self] = Head(stack[self]).evs]
                                   /\ pcl' = [pcl EXCEPT ![self] = Head(stack[self]).pcl]
                                   /\ pph' = [pph EXCEPT ![self] = Head(stack[self]).pph]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                   /\ UNCHANGED phLock
                              ELSE /\ evs' = [evs EXCEPT ![self] = Ev(pcl[self]) \cup reg.ev]
                                   /\ reg' = [ev |-> Ev(pcl[self]) \cup reg.ev, ph |-> pph[self]]
                                   /\ phLock' = self
                                   /\ pc' = [pc EXCEPT ![self] = "ph3"]
                                   /\ UNCHANGED << woken, stack, pcl, pph, 
                                                   sysm >>
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, reqs, pgot, pmask, rreply, 
                             ireply, intrd, rdrs, wrr, wwait, viol, rcl, wmode, 
                             res, icl, r, sigd, opc, ndc, spc, svc, ssc >>

ph3(self) == /\ pc[self] = "ph3"
             /\ IF Mask \cap evs[self] # {}
                   THEN /\ IF pph[self] = "real"
                              THEN /\ woken' = [c \in PollC |-> woken[c] \/ c \in onWQ]
                              ELSE /\ TRUE
                                   /\ woken' = woken
                        /\ reg' = NoReg
                   ELSE /\ TRUE
                        /\ UNCHANGED << woken, reg >>
             /\ phLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ sysm' = [sysm EXCEPT ![self] = Head(stack[self]).sysm]
             /\ evs' = [evs EXCEPT ![self] = Head(stack[self]).evs]
             /\ pcl' = [pcl EXCEPT ![self] = Head(stack[self]).pcl]
             /\ pph' = [pph EXCEPT ![self] = Head(stack[self]).pph]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, reqs, pgot, pmask, rreply, 
                             ireply, intrd, rdrs, wrr, wwait, viol, rcl, wmode, 
                             res, icl, r, sigd, opc, ndc, spc, svc, ssc >>

pollH(self) == ph1(self) \/ ph2(self) \/ ph3(self)

rh0(self) == /\ pc[self] = "rh0"
             /\ wmode' = [wmode EXCEPT ![self] = ~Urandom]
             /\ pc' = [pc EXCEPT ![self] = "rh1"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, res, icl, 
                             r, sigd, opc, ndc, spc, svc, ssc >>

rh1(self) == /\ pc[self] = "rh1"
             /\ wrr = NoProc /\ wwait = {}
             /\ rdrs' = (rdrs \cup {self})
             /\ pc' = [pc EXCEPT ![self] = "rh2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, wrr, wwait, viol, 
                             stack, pcl, pph, sysm, evs, rcl, wmode, res, icl, 
                             r, sigd, opc, ndc, spc, svc, ssc >>

rh2(self) == /\ pc[self] = "rh2"
             /\ res' = [res EXCEPT ![self] = Rpc(wmode[self])]
             /\ rdrs' = rdrs \ {self}
             /\ IF Rpc(wmode[self]) = "eagain" /\ Urandom /\ wmode[self] /\ ~esdmOp
                   THEN /\ viol' = (viol \cup {"UrandomWaitsNonop"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = "rh3"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, wrr, wwait, stack, 
                             pcl, pph, sysm, evs, rcl, wmode, icl, r, sigd, 
                             opc, ndc, spc, svc, ssc >>

rh3(self) == /\ pc[self] = "rh3"
             /\ IF res[self] = "eagain" /\ intrd[rcl[self]]
                   THEN /\ rreply' = [rreply EXCEPT ![rcl[self]] = "eintr"]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ wmode' = [wmode EXCEPT ![self] = Head(stack[self]).wmode]
                        /\ res' = [res EXCEPT ![self] = Head(stack[self]).res]
                        /\ rcl' = [rcl EXCEPT ![self] = Head(stack[self]).rcl]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ viol' = viol
                   ELSE /\ IF res[self] = "eagain" /\ HonorNonblock /\ rcl[self] \in NbReaders
                              THEN /\ rreply' = [rreply EXCEPT ![rcl[self]] = "eagain"]
                                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ wmode' = [wmode EXCEPT ![self] = Head(stack[self]).wmode]
                                   /\ res' = [res EXCEPT ![self] = Head(stack[self]).res]
                                   /\ rcl' = [rcl EXCEPT ![self] = Head(stack[self]).rcl]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                   /\ viol' = viol
                              ELSE /\ IF res[self] = "eagain"
                                         THEN /\ IF rcl[self] \in NbReaders
                                                    THEN /\ viol' = (viol \cup {"NonblockWaits"})
                                                    ELSE /\ TRUE
                                                         /\ viol' = viol
                                              /\ IF ~UrandomNoSwitch
                                                    THEN /\ wmode' = [wmode EXCEPT ![self] = TRUE]
                                                    ELSE /\ TRUE
                                                         /\ wmode' = wmode
                                              /\ res' = [res EXCEPT ![self] = "none"]
                                              /\ pc' = [pc EXCEPT ![self] = "rh1"]
                                              /\ UNCHANGED << rreply, stack, 
                                                              rcl >>
                                         ELSE /\ rreply' = [rreply EXCEPT ![rcl[self]] = "data"]
                                              /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                              /\ wmode' = [wmode EXCEPT ![self] = Head(stack[self]).wmode]
                                              /\ res' = [res EXCEPT ![self] = Head(stack[self]).res]
                                              /\ rcl' = [rcl EXCEPT ![self] = Head(stack[self]).rcl]
                                              /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                              /\ viol' = viol
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, ireply, 
                             intrd, reg, phLock, rdrs, wrr, wwait, pcl, pph, 
                             sysm, evs, icl, r, sigd, opc, ndc, spc, svc, ssc >>

readH(self) == rh0(self) \/ rh1(self) \/ rh2(self) \/ rh3(self)

io1(self) == /\ pc[self] = "io1"
             /\ wwait' = (wwait \cup {self})
             /\ pc' = [pc EXCEPT ![self] = "io2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, viol, 
                             stack, pcl, pph, sysm, evs, rcl, wmode, res, icl, 
                             r, sigd, opc, ndc, spc, svc, ssc >>

io2(self) == /\ pc[self] = "io2"
             /\ rdrs = {} /\ wrr = NoProc
             /\ wrr' = self
             /\ wwait' = wwait \ {self}
             /\ pc' = [pc EXCEPT ![self] = "io3"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, viol, stack, 
                             pcl, pph, sysm, evs, rcl, wmode, res, icl, r, 
                             sigd, opc, ndc, spc, svc, ssc >>

io3(self) == /\ pc[self] = "io3"
             /\ wrr' = NoProc
             /\ ireply' = [ireply EXCEPT ![icl[self]] = TRUE]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ icl' = [icl EXCEPT ![self] = Head(stack[self]).icl]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             intrd, reg, phLock, rdrs, wwait, viol, pcl, pph, 
                             sysm, evs, rcl, wmode, res, r, sigd, opc, ndc, 
                             spc, svc, ssc >>

ioctlH(self) == io1(self) \/ io2(self) \/ io3(self)

wk1(self) == /\ pc[self] = "wk1"
             /\ reqs # {}
             /\ \E q \in IF \E x \in reqs : x.t = "intr"
                         THEN {x \in reqs : x.t = "intr"} ELSE reqs:
                  /\ r' = [r EXCEPT ![self] = q]
                  /\ reqs' = reqs \ {q}
             /\ pc' = [pc EXCEPT ![self] = "wk2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, sigd, opc, ndc, spc, svc, ssc >>

wk2(self) == /\ pc[self] = "wk2"
             /\ IF r[self].t = "poll"
                   THEN /\ /\ pcl' = [pcl EXCEPT ![self] = r[self].c]
                           /\ pph' = [pph EXCEPT ![self] = r[self].ph]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "pollH",
                                                                    pc        |->  "wk3",
                                                                    sysm      |->  sysm[self],
                                                                    evs       |->  evs[self],
                                                                    pcl       |->  pcl[self],
                                                                    pph       |->  pph[self] ] >>
                                                                \o stack[self]]
                        /\ sysm' = [sysm EXCEPT ![self] = {}]
                        /\ evs' = [evs EXCEPT ![self] = {}]
                        /\ pc' = [pc EXCEPT ![self] = "ph1"]
                        /\ UNCHANGED << intrd, rcl, wmode, res, icl >>
                   ELSE /\ IF r[self].t = "read"
                              THEN /\ /\ rcl' = [rcl EXCEPT ![self] = r[self].c]
                                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "readH",
                                                                               pc        |->  "wk3",
                                                                               wmode     |->  wmode[self],
                                                                               res       |->  res[self],
                                                                               rcl       |->  rcl[self] ] >>
                                                                           \o stack[self]]
                                   /\ wmode' = [wmode EXCEPT ![self] = FALSE]
                                   /\ res' = [res EXCEPT ![self] = "none"]
                                   /\ pc' = [pc EXCEPT ![self] = "rh0"]
                                   /\ UNCHANGED << intrd, icl >>
                              ELSE /\ IF r[self].t = "ioctl"
                                         THEN /\ /\ icl' = [icl EXCEPT ![self] = r[self].c]
                                                 /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ioctlH",
                                                                                          pc        |->  "wk3",
                                                                                          icl       |->  icl[self] ] >>
                                                                                      \o stack[self]]
                                              /\ pc' = [pc EXCEPT ![self] = "io1"]
                                              /\ intrd' = intrd
                                         ELSE /\ intrd' = [intrd EXCEPT ![r[self].c] = TRUE]
                                              /\ pc' = [pc EXCEPT ![self] = "wk3"]
                                              /\ UNCHANGED << stack, icl >>
                                   /\ UNCHANGED << rcl, wmode, res >>
                        /\ UNCHANGED << pcl, pph, sysm, evs >>
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, reg, phLock, rdrs, wrr, wwait, viol, r, 
                             sigd, opc, ndc, spc, svc, ssc >>

wk3(self) == /\ pc[self] = "wk3"
             /\ r' = [r EXCEPT ![self] = NoReq]
             /\ pc' = [pc EXCEPT ![self] = "wk1"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, sigd, opc, ndc, spc, svc, ssc >>

k(self) == wk1(self) \/ wk2(self) \/ wk3(self)

ck1 == /\ pc["ck"] = "ck1"
       /\ phLock = NoProc
       /\ IF reg # NoReg /\ Mask \cap reg.ev # {}
             THEN /\ IF (reg.ph) = "real"
                        THEN /\ woken' = [c \in PollC |-> woken[c] \/ c \in onWQ]
                        ELSE /\ TRUE
                             /\ woken' = woken
                  /\ reg' = NoReg
             ELSE /\ TRUE
                  /\ UNCHANGED << woken, reg >>
       /\ susp' = FALSE
       /\ pc' = [pc EXCEPT !["ck"] = "ck2"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, sem, 
                       onWQ, reqs, pgot, pmask, rreply, ireply, intrd, phLock, 
                       rdrs, wrr, wwait, viol, stack, pcl, pph, sysm, evs, rcl, 
                       wmode, res, icl, r, sigd, opc, ndc, spc, svc, ssc >>

ck2 == /\ pc["ck"] = "ck2"
       /\ IF PollFallback /\ ~shmAvail
             THEN /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
                  /\ sem' = sem
             ELSE /\ sem > 0
                  /\ sem' = sem - 1
                  /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, susp, 
                       onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, viol, stack, pcl, pph, 
                       sysm, evs, rcl, wmode, res, icl, r, sigd, opc, ndc, spc, 
                       svc, ssc >>

ck == ck1 \/ ck2

pl1(self) == /\ pc[self] = "pl1"
             /\ onWQ' = (onWQ \cup {self})
             /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]})
             /\ pc' = [pc EXCEPT ![self] = "pl2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, woken, pgot, pmask, rreply, ireply, 
                             intrd, reg, phLock, rdrs, wrr, wwait, viol, stack, 
                             pcl, pph, sysm, evs, rcl, wmode, res, icl, r, 
                             sigd, opc, ndc, spc, svc, ssc >>

pl2(self) == /\ pc[self] = "pl2"
             /\ pgot[self]
             /\ pgot' = [pgot EXCEPT ![self] = FALSE]
             /\ IF pmask[self] # {}
                   THEN /\ onWQ' = onWQ \ {self}
                        /\ woken' = [woken EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "plDone"]
                        /\ reqs' = reqs
                   ELSE /\ IF woken[self]
                              THEN /\ woken' = [woken EXCEPT ![self] = FALSE]
                                   /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]})
                                   /\ pc' = [pc EXCEPT ![self] = "pl2"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "pl3"]
                                   /\ UNCHANGED << woken, reqs >>
                        /\ onWQ' = onWQ
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, pmask, rreply, ireply, intrd, reg, 
                             phLock, rdrs, wrr, wwait, viol, stack, pcl, pph, 
                             sysm, evs, rcl, wmode, res, icl, r, sigd, opc, 
                             ndc, spc, svc, ssc >>

pl3(self) == /\ pc[self] = "pl3"
             /\ woken[self]
             /\ woken' = [woken EXCEPT ![self] = FALSE]
             /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]})
             /\ pc' = [pc EXCEPT ![self] = "pl2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, pgot, pmask, rreply, ireply, 
                             intrd, reg, phLock, rdrs, wrr, wwait, viol, stack, 
                             pcl, pph, sysm, evs, rcl, wmode, res, icl, r, 
                             sigd, opc, ndc, spc, svc, ssc >>

plDone(self) == /\ pc[self] = "plDone"
                /\ TRUE
                /\ pc' = [pc EXCEPT ![self] = "Done"]
                /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                                susp, sem, onWQ, woken, reqs, pgot, pmask, 
                                rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                                wwait, viol, stack, pcl, pph, sysm, evs, rcl, 
                                wmode, res, icl, r, sigd, opc, ndc, spc, svc, 
                                ssc >>

pl(self) == pl1(self) \/ pl2(self) \/ pl3(self) \/ plDone(self)

pr1(self) == /\ pc[self] = "pr1"
             /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self,
                                     ph |-> IF onWQ = {} THEN "null" ELSE "real"]})
             /\ pc' = [pc EXCEPT ![self] = "pr2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, r, sigd, opc, ndc, spc, svc, ssc >>

pr2(self) == /\ pc[self] = "pr2"
             /\ pgot[self]
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, r, sigd, opc, ndc, spc, svc, ssc >>

pr(self) == pr1(self) \/ pr2(self)

rc1(self) == /\ pc[self] = "rc1"
             /\ reqs' = (reqs \cup {[t |-> "read", c |-> self, ph |-> "none"]})
             /\ pc' = [pc EXCEPT ![self] = "rc2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, r, sigd, opc, ndc, spc, svc, ssc >>

rc2(self) == /\ pc[self] = "rc2"
             /\ \/ /\ rreply[self] # "none"
                   /\ pc' = [pc EXCEPT ![self] = "rcDone"]
                   /\ UNCHANGED <<reqs, sigd>>
                \/ /\ self \in Signalled /\ ~sigd[self] /\ rreply[self] = "none"
                   /\ sigd' = [sigd EXCEPT ![self] = TRUE]
                   /\ reqs' = (reqs \cup {[t |-> "intr", c |-> self, ph |-> "none"]})
                   /\ pc' = [pc EXCEPT ![self] = "rc2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, r, opc, ndc, spc, svc, ssc >>

rcDone(self) == /\ pc[self] = "rcDone"
                /\ TRUE
                /\ pc' = [pc EXCEPT ![self] = "Done"]
                /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                                susp, sem, onWQ, woken, reqs, pgot, pmask, 
                                rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                                wwait, viol, stack, pcl, pph, sysm, evs, rcl, 
                                wmode, res, icl, r, sigd, opc, ndc, spc, svc, 
                                ssc >>

rd(self) == rc1(self) \/ rc2(self) \/ rcDone(self)

ic1(self) == /\ pc[self] = "ic1"
             /\ reqs' = (reqs \cup {[t |-> "ioctl", c |-> self, ph |-> "none"]})
             /\ pc' = [pc EXCEPT ![self] = "ic2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, r, sigd, opc, ndc, spc, svc, ssc >>

ic2(self) == /\ pc[self] = "ic2"
             /\ ireply[self]
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, 
                             susp, sem, onWQ, woken, reqs, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             viol, stack, pcl, pph, sysm, evs, rcl, wmode, res, 
                             icl, r, sigd, opc, ndc, spc, svc, ssc >>

io(self) == ic1(self) \/ ic2(self)

en1 == /\ pc["env"] = "en1"
       /\ \/ /\ srvUp /\ opc < OpChanges
             /\ opc' = opc + 1
             /\ esdmOp' = ~esdmOp
             /\ pc' = [pc EXCEPT !["env"] = "en2"]
             /\ UNCHANGED <<srvUp, spent, shmOp, shmNeed, shmAvail, susp, sem, ndc, spc, svc, ssc>>
          \/ /\ srvUp /\ ndc < NeedChanges
             /\ ndc' = ndc + 1
             /\ shmNeed' = ~shmNeed
             /\ sem' = Post(sem)
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmOp, shmAvail, susp, opc, spc, svc, ssc>>
          \/ /\ srvUp /\ esdmOp /\ spc < SpentChanges
             /\ spc' = spc + 1
             /\ spent' = ~spent
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, shmOp, shmNeed, shmAvail, susp, sem, opc, ndc, svc, ssc>>
          \/ /\ srvUp /\ ssc < Suspends
             /\ ssc' = ssc + 1
             /\ susp' = TRUE
             /\ sem' = Post(sem)
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmOp, shmNeed, shmAvail, opc, ndc, spc, svc>>
          \/ /\ srvUp /\ svc < SrvChanges
             /\ svc' = svc + 1
             /\ srvUp' = FALSE
             /\ esdmOp' = FALSE
             /\ spent' = FALSE
             /\ IF PollFallback
                   THEN /\ shmAvail' = FALSE
                   ELSE /\ TRUE
                        /\ UNCHANGED shmAvail
             /\ susp' = TRUE
             /\ sem' = Post(sem)
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<shmOp, shmNeed, opc, ndc, spc, ssc>>
          \/ /\ ~srvUp /\ svc < SrvChanges
             /\ svc' = svc + 1
             /\ shmOp' = FALSE
             /\ shmAvail' = TRUE
             /\ sem' = Post(sem)
             /\ pc' = [pc EXCEPT !["env"] = "en3"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmNeed, susp, opc, ndc, spc, ssc>>
       /\ UNCHANGED << onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, viol, stack, pcl, pph, 
                       sysm, evs, rcl, wmode, res, icl, r, sigd >>

en2 == /\ pc["env"] = "en2"
       /\ shmOp' = esdmOp
       /\ sem' = Post(sem)
       /\ pc' = [pc EXCEPT !["env"] = "en1"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmNeed, shmAvail, susp, onWQ, 
                       woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, 
                       phLock, rdrs, wrr, wwait, viol, stack, pcl, pph, sysm, 
                       evs, rcl, wmode, res, icl, r, sigd, opc, ndc, spc, svc, 
                       ssc >>

en3 == /\ pc["env"] = "en3"
       /\ srvUp' = TRUE
       /\ pc' = [pc EXCEPT !["env"] = "en1"]
       /\ UNCHANGED << esdmOp, spent, shmOp, shmNeed, shmAvail, susp, sem, 
                       onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, viol, stack, pcl, pph, 
                       sysm, evs, rcl, wmode, res, icl, r, sigd, opc, ndc, spc, 
                       svc, ssc >>

env == en1 \/ en2 \/ en3

Next == ck \/ env
           \/ (\E self \in ProcSet: pollH(self) \/ readH(self) \/ ioctlH(self))
           \/ (\E self \in Workers: k(self))
           \/ (\E self \in PollC: pl(self))
           \/ (\E self \in Probe: pr(self))
           \/ (\E self \in ReadC: rd(self))
           \/ (\E self \in Ioctls: io(self))

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Workers : /\ SF_vars(k(self))
                                 /\ SF_vars(pollH(self))
                                 /\ SF_vars(readH(self))
                                 /\ SF_vars(ioctlH(self))
        /\ SF_vars(ck)
        /\ \A self \in PollC : WF_vars(pl(self))
        /\ \A self \in Probe : WF_vars(pr(self))
        /\ \A self \in ReadC : WF_vars(rd(self))
        /\ \A self \in Ioctls : WF_vars(io(self))
        /\ WF_vars(env)

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ reg.ph \in {"none", "real", "null"}
    /\ \A c \in Readers : rreply[c] \in {"none", "data", "eintr"}
    /\ \A c \in NbReaders : rreply[c] \in {"none", "data", "eintr", "eagain"}

\* A thread asleep in poll() can be woken: a registration with a handle
\* covers its events, or a poll request of the file is still under way.
Covered(c) ==
    \/ reg.ph = "real" /\ Ev(c) \subseteq reg.ev
    \/ \E q \in reqs : q.t = "poll"
    \/ \E x \in Workers : pc[x] \in {"ph1", "ph2", "ph3"}
WaiterCovered == \A c \in PollC : (pc[c] = "pl3" /\ ~woken[c]) => Covered(c)

\* poll() reports POLLIN only for a read that would not wait.
PollReadable == "SpuriousReadable" \notin viol

\* A read with O_NONBLOCK never waits.
NonblockNeverWaits == "NonblockWaits" \notin viol

\* /dev/urandom waits only while the ESDM is operational; otherwise it reads
\* the kernel's device, as its first request does.
UrandomFallback == "UrandomWaitsNonop" \notin viol

\* Witnesses of the liveness defects, for the configurations demonstrating
\* them (TLC names violated invariants only): nothing changes any more and
\* a poller sleeps, though a read would not wait ...
PollNotStuck == ~ENABLED Next => \A c \in PollIn : pc[c] = "pl3" => ~NoWait

\* ... or the server changes nothing any more, reads wait, and every worker
\* loops in a read while a signalled reader's FUSE_INTERRUPT is queued.
InterruptNotStuck ==
    (~ENABLED env /\ ~NoWait)
        => \A c \in Signalled :
               (sigd[c] /\ ~intrd[c] /\ pc[c] = "rc2")
                   => \E x \in Workers : pc[x] \notin {"rh0", "rh1", "rh2", "rh3"}

-----------------------------------------------------------------------------
(* Liveness *)

\* A poller wakes once the status shows its event for good ...
Returned(c) == pc[c] \in {"plDone", "rcDone", "Done"}

PollWakes ==
    /\ \A c \in PollIn : <>[]shmOp => <>Returned(c)
    /\ \A c \in PollOut : <>[]shmNeed => <>Returned(c)

\* ... and once a read would not wait for good.
PollLive == \A c \in PollIn : <>[]NoWait => <>Returned(c)

\* A read returns once it would not wait for good, an interrupted read in
\* any case, and so does a privileged ioctl.
ReadsReturn == \A c \in ReadC : <>[]NoWait => <>Returned(c)
InterruptHonored == \A c \in Signalled : [](sigd[c] => <>Returned(c))
IoctlsReturn == \A c \in Ioctls : <>Returned(c)
=============================================================================
