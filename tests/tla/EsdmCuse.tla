------------------------------- MODULE EsdmCuse -------------------------------
(***************************************************************************)
(* The CUSE daemons behind /dev/random and /dev/urandom:                   *)
(* frontends/cuse/cuse_device.c with cuse_random.c and cuse_urandom.c, at  *)
(* the granularity of their locks and of their accesses to the status      *)
(* segment: read(), poll(), the privileged ioctls, the poll checker thread *)
(* and the FUSE worker threads, together with the kernel's side of FUSE    *)
(* poll and interrupts. One step is one access to a variable shared with   *)
(* another thread or process, one lock operation or one request or reply;  *)
(* the labels name the C functions they come from. A lock operation shares *)
(* its step with an adjoining access where it commutes with the steps of   *)
(* the other threads (taking a lock with what follows, releasing it with   *)
(* what precedes), and so do the operations on the registration list,      *)
(* which only the holder of esdm_cuse_ph_lock sees.                        *)
(*                                                                         *)
(* The status segment is read without a lock: esdm_cuse_get_pollmask()     *)
(* reads the version, the operational flag (or polls the kernel's device), *)
(* the need for entropy and the suspend generation one after the other,    *)
(* and the server may change any of them in between. The poll checker      *)
(* reads the suspend generation, the mask, marks the generation as acted   *)
(* on, looks at the version and waits on the semaphore, each in a step of  *)
(* its own.                                                                *)
(*                                                                         *)
(* A suspend notification is a new generation of a counter in the segment  *)
(* (SuspendGen), which only the server counts up and a starting server     *)
(* keeps. The daemon keeps the generation it has acted on                  *)
(* (esdm_cuse_suspend_seen): the mask shows every event while the two      *)
(* differ, and the poll checker sets its own to the generation it loaded   *)
(* at the start of the pass. esdm_cuse_poll() notifies in its re-check     *)
(* also when the generation is newer than the one it answered with         *)
(* (RecheckGen): the checker may have acted on it while the poll was not   *)
(* registered. Before, the notification was a one-shot trigger in the      *)
(* segment, which the checker cleared there and a starting server reset.   *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - The server is an environment process. It changes its state (the truth *)
(*   an RPC answers from), then publishes it in the status segment and     *)
(*   posts the daemon's semaphore if it is 0, in one step: the protocol of *)
(*   the posts is the subject of EsdmShmStatus.tla, and a daemon cannot    *)
(*   tell a store followed by its post from both at once, except that the  *)
(*   checker may pass earlier, which the interleaving allows anyway.       *)
(* - The server's exit and start follow the code step by step:             *)
(*   esdm_rpc_server_fini() ends the RPCs, esdm_shm_status_exit()          *)
(*   withdraws the version, counts the suspend generation up and posts;    *)
(*   esdm_shm_status_init() clears the version, re-synchronizes the        *)
(*   semaphore, publishes the operational state and the need (posting only *)
(*   on a change against what the segment holds from the predecessor),     *)
(*   and publishes the version - with a post after it (PostAfterPublish;   *)
(*   one step with the store, as above), without which a checker that passed *)
(*   while the version was withdrawn may block with nothing owed; then the *)
(*   RPC sockets serve. A server may also be killed: nothing is published. *)
(*   esdm_reinit() (a library call the server does not make) is left out.  *)
(* - The environment need not begin a change (no fairness for that), but   *)
(*   completes one it began. All its changes are bounded.                  *)
(* - An RPC with the reader lock held is one step. It answers from the     *)
(*   server's state: data, -EAGAIN, or an error that sends the read to the *)
(*   kernel's device. The kernel's /dev/urandom always has data and always *)
(*   polls readable and writable; its /dev/random polls readable and has   *)
(*   data once the kernel's CRNG is ready, and polls writable before; a    *)
(*   read() of it blocks until then, whatever the flags of the request.    *)
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
(*   fh. Time is left out: esdm_cuse_poll_wait() and the second the poll   *)
(*   checker sleeps while no server publishes are one step each.           *)
(* - One daemon: the second one reading the same suspend generation is not *)
(*   modelled; no daemon writes it.                                        *)
(* - Not modelled: O_SYNC, write() (it never waits), RNDGETENTCNT and the  *)
(*   ESDM ioctls 42-44, release(), the init handshake, shutdown, a failed  *)
(*   allocation of the registration.                                       *)
(*                                                                         *)
(* Fairness: weak fairness for every thread, strong fairness only where a  *)
(* request handler takes esdm_cuse_ph_lock (ph2), which the poll checker   *)
(* takes and releases again and again while no server publishes. The       *)
(* process "idle" stutters in the states in which the model rests          *)
(* legitimately (Quiescent), so that every other state without a step is   *)
(* a deadlock.                                                             *)
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
    KernelReady,    \* the kernel's CRNG is ready at the start, else later
    OpChanges,      \* operational state changes
    NeedChanges,    \* need_entropy changes
    SpentChanges,   \* every DRNG awaits its reseed, and no longer
    SrvChanges,     \* server exits and starts
    Kills,          \* servers killed: no exit handling
    Suspends,       \* suspend notifications (SIGUSR1, kernel events)
    RestartOp,      \* operational states a new server may publish at once
    RestartNeed,    \* needs for entropy a new server may publish
    HonorNonblock,  \* fix: a read with O_NONBLOCK returns -EAGAIN
    KeepNullPh,     \* fix: a poll without a handle keeps the registration
    PollFallback,   \* fix: poll() follows the kernel's device where reads
                    \* use it; the exit withdraws the version, and the
                    \* checker passes every second while no server publishes
    UrandomNoSwitch, \* fix: /dev/urandom keeps its getter while it waits
    PostAfterPublish, \* fix: the server posts after publishing the version
    SuspendGen,     \* fix: a suspend generation, the daemon keeps the one
                    \* it acted on; else the one-shot trigger in the segment
    RecheckGen      \* fix: the re-check of esdm_cuse_poll() notifies for a
                    \* newer suspend generation than the one answered with

NoProc == "none"
NoReg == [ev |-> {}, ph |-> "none"]
PollC == PollIn \cup PollOut
ReadC == Readers \cup NbReaders
Ev(c) == IF c \in PollOut THEN {"out"} ELSE {"in"}
Post(v) == IF v = 0 THEN 1 ELSE v
NoReq == [t |-> "none", c |-> "none", ph |-> "none"]
MaskP == Workers \cup {"ck"}

(* --algorithm EsdmCuse {
variables
    \* the server: its state and the status it published
    srvUp = TRUE,
    esdmOp = StartOp,
    spent = FALSE,
    shmVer = TRUE,
    shmOp = StartOp,
    shmNeed = FALSE,
    \* the suspend generation (before the fix: 1 while the trigger is
    \* raised)
    sgen = 0,
    sem = 0,
    \* the kernel: its CRNG, the file's poll waitqueue, woken pollers, queued
    \* requests, replies
    kReady = KernelReady,
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
    \* esdm_cuse_priv (writer-preferring), the mask a thread read
    reg = NoReg,
    phLock = NoProc,
    rdrs = {},
    wrr = NoProc,
    wwait = {},
    gmask = [p \in MaskP |-> {}],
    \* ghosts: at one of the reads of its mask, a read would not have
    \* waited or the status showed the ESDM operational; violations
    \* the suspend generation the daemon acted on, the one a thread read
    cseen = 0,
    ggen = [p \in Workers |-> 0],
    gok = [p \in Workers |-> FALSE],
    viol = {};

define {
    \* the daemon takes the segment as published
    \* (esdm_cuse_shm_status_avail()); before the fix the mask ignored it
    Avail == shmVer \/ ~PollFallback
    \* what the status shows
    StatusOp == Avail /\ shmOp
    StatusNeed == Avail /\ shmNeed
    \* poll() of the kernel's device
    KMask == IF Urandom THEN {"in", "out"}
             ELSE IF kReady THEN {"in"} ELSE {"out"}
    \* what one RPC of the read loop yields: w is the waiting getter
    \* (esdm_rpcc_get_random_bytes_full_noblock_int()), else
    \* esdm_rpcc_get_random_bytes_int(); an error goes to the kernel's device
    Rpc(w) == IF ~srvUp THEN "kernel"
              ELSE IF esdmOp /\ ~spent THEN "data"
              ELSE IF ~w /\ ~esdmOp THEN "kernel"
              ELSE "eagain"
    \* a read would not wait
    NoWait == IF Urandom THEN ~(srvUp /\ esdmOp /\ spent)
              ELSE (~srvUp /\ kReady) \/ (srvUp /\ esdmOp /\ ~spent)
    \* a thread asleep in poll()
    Asleep(c) == pc[c] = "pl3" /\ ~woken[c]
    \* The model rests: every call returned, except a poll() whose event the
    \* status does not show while a read would wait.
    Quiescent ==
        /\ \A c \in PollIn :
               pc[c] = "Done" \/ (Asleep(c) /\ ~StatusOp /\ ~NoWait)
        /\ \A c \in PollOut : pc[c] = "Done" \/ (Asleep(c) /\ ~StatusNeed)
        /\ \A c \in Probe \cup ReadC \cup Ioctls : pc[c] = "Done"
}

\* fuse_lowlevel_notify_poll(): a handle wakes every poller of the file
macro notify(p) {
    if (p = "real") woken := [c \in PollC |-> woken[c] \/ c \in onWQ];
}

\* esdm_cuse_get_pollmask(): unlocked reads of the status segment
procedure getMask()
    variables gv = TRUE;
{
     \* esdm_cuse_shm_status_avail(): the version
gm1: gv := Avail;
     gmask[self] := {};
     if (self \in Workers) gok[self] := NoWait \/ StatusOp;
     \* esdm_cuse_fallback_pollmask(), or the operational flag - on
     \* /dev/urandom the kernel's device while it is not set
gm2: if (~gv) {
         gmask[self] := KMask;
         if (self \in Workers) gok[self] := gok[self] \/ NoWait \/ StatusOp;
         goto gm4;
     } else {
         if (shmOp) {
             gmask[self] := {"in"};
         } else if (PollFallback /\ Urandom) {
             gmask[self] := KMask \cap {"in"};
         };
         if (self \in Workers) gok[self] := gok[self] \/ NoWait \/ StatusOp;
         \* without a poller for POLLOUT nobody uses the next read
         if (PollOut = {}) {
             goto gm4;
         };
     };
     \* the need for entropy
gm3: if (shmNeed) gmask[self] := gmask[self] \cup {"out"};
     \* esdm_cuse_suspend_pending(): the suspend generation of the segment,
     \* then the one the daemon has acted on, which only the poll checker
     \* writes - its own read of it shares the step. Before the fix one read
     \* of the trigger.
gm4: if (SuspendGen /\ self \in Workers) ggen[self] := sgen;
     if (self \in Workers) gok[self] := gok[self] \/ NoWait \/ StatusOp;
     if (~SuspendGen \/ self = "ck") {
         if (sgen # cseen) gmask[self] := {"in", "out"};
         return;
     };
gm5: if (ggen[self] # cseen) gmask[self] := {"in", "out"};
     gok[self] := gok[self] \/ NoWait \/ StatusOp;
     return;
}

\* esdm_cuse_poll()
procedure pollH(pcl, pph)
    variables evs = {}, pg = 0;
{
ph0: call getMask();
     \* fuse_reply_poll(); a poll without a handle is done
ph1: pgot[pcl] := TRUE;
     pmask[pcl] := gmask[self] \cap Ev(pcl);
     if ("in" \in gmask[self] \cap Ev(pcl) /\ ~gok[self])
         viol := viol \cup {"SpuriousReadable"};
     gok[self] := FALSE;
     if (KeepNullPh /\ pph = "null") {
         gmask[self] := {};
         ggen[self] := 0;
         return;
     };
     \* under esdm_cuse_ph_lock: esdm_cuse_poll_remove_fh() keeps the events;
     \* the mask is the one replied
ph2:+ await phLock = NoProc;
     if (gmask[self] \cap (Ev(pcl) \cup reg.ev) # {}) {
         notify(pph);
         reg := NoReg;
         gmask[self] := {};
         ggen[self] := 0;
         return;
     } else {
         evs := Ev(pcl) \cup reg.ev;
         reg := [ev |-> Ev(pcl) \cup reg.ev, ph |-> pph];
         phLock := self;
         gmask[self] := {};
         \* the suspend generation the answer was made with
         if (RecheckGen) pg := ggen[self];
     };
     \* the re-check closing the register-after-reply window, for the status
     \* and (the fix) for a suspend generation newer than the one answered
     \* with, which the poll checker may have acted on meanwhile
ph3: call getMask();
ph4: if (gmask[self] \cap evs # {} \/ (RecheckGen /\ ggen[self] # pg)) {
         notify(pph);
         reg := NoReg;
     };
     gmask[self] := {};
     ggen[self] := 0;
     gok[self] := FALSE;
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
     if (Rpc(wmode) = "eagain" /\ Urandom /\ ~esdmOp)
         viol := viol \cup {"UrandomWaitsNonop"};
rh3: if (res = "eagain" /\ HonorNonblock /\ rcl \in NbReaders) {
         rreply[rcl] := "eagain";
         return;
     } else if (res = "eagain" /\ intrd[rcl]) {
         rreply[rcl] := "eintr";
         return;
     } else if (res = "eagain") {
         \* -EAGAIN of esdm_rpcc_get_random_bytes_int() switches to the
         \* waiting getter; esdm_cuse_poll_wait()
         if (rcl \in NbReaders) viol := viol \cup {"NonblockWaits"};
         if (~UrandomNoSwitch) wmode := TRUE;
         res := "none";
         goto rh1;
     } else if (res = "kernel" /\ ~Urandom /\ ~kReady) {
         \* read() of the kernel's /dev/random: the descriptor is a
         \* blocking one, whatever the flags of the request
         if (rcl \in NbReaders) viol := viol \cup {"NonblockWaits"};
     } else {
         rreply[rcl] := "data";
         return;
     };
rh4: await kReady;
     rreply[rcl] := "data";
     return;
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
fair process (k \in Workers)
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

\* esdm_cuse_poll_checker()
fair process (ck = "ck")
    variables cgen = 0;
{
ck1: while (TRUE) {
         \* mutex_w_lock(); the suspend generation of this pass (before the
         \* fix: whether the trigger is raised)
         await phLock = NoProc;
         phLock := "ck";
         cgen := sgen;
         \* the mask, once for the list
ck2:     if (reg # NoReg) {
             call getMask();
ck3:         if (gmask["ck"] \cap reg.ev # {}) {
                 notify(reg.ph);
                 reg := NoReg;
             };
             gmask["ck"] := {};
         };
         \* the generation of this pass marked as acted on, in the daemon
         \* (before the fix: the trigger cleared in the segment if this pass
         \* saw it); mutex_w_unlock()
ck4:     if (SuspendGen) {
             cseen := cgen;
         } else if (cgen # 0) {
             sgen := 0;
         };
         cgen := 0;
         phLock := NoProc;
         \* esdm_cuse_shm_status_down(): without the version another pass
         \* after a second (before the fix: no pass until it is there)
ck5:     if (PollFallback /\ ~shmVer) {
             goto ck1;
         } else {
             await shmVer;
         };
         \* sem_wait()
ck6:     await sem > 0;
         sem := sem - 1;
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

\* the server and the kernel's CRNG: no fairness for beginning a change
fair process (env = "env")
    variables opc = 0, ndc = 0, spc = 0, svc = 0, ssc = 0, klc = 0;
{
en1:- while (TRUE) {
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
             \* esdm_shm_status_signal_suspend(), esdm_shm_status_suspend()
             await srvUp /\ ssc < Suspends;
             ssc := ssc + 1;
             sgen := IF SuspendGen THEN sgen + 1 ELSE 1;
             sem := Post(sem);
         } or {
             \* the kernel's CRNG turns ready
             await ~kReady;
             kReady := TRUE;
         } or {
             \* the exit: esdm_rpc_server_fini() ends the RPCs
             await srvUp /\ svc < SrvChanges;
             svc := svc + 1;
             srvUp := FALSE;
             esdmOp := FALSE;
             spent := FALSE;
             \* esdm_shm_status_exit(): the version withdrawn (the fix; the
             \* status stayed before), then the suspend notification, the post
ex2:         if (PollFallback) shmVer := FALSE;
ex3:         sgen := IF SuspendGen THEN sgen + 1 ELSE 1;
             sem := Post(sem);
         } or {
             \* killed: nothing is published
             await srvUp /\ klc < Kills;
             klc := klc + 1;
             srvUp := FALSE;
             esdmOp := FALSE;
             spent := FALSE;
         } or {
             \* a new server, esdm_shm_status_init():
             \* esdm_shm_status_create_shm() clears the version
             await ~srvUp /\ svc < SrvChanges;
             svc := svc + 1;
             shmVer := FALSE;
             \* esdm_shm_status_create_sem() re-synchronizes
st2:         sem := Post(sem);
             \* esdm_shm_status_set_operational(): a post on a change
st3:         with (o \in RestartOp) {
                 esdmOp := o;
                 if (shmOp # o) {
                     shmOp := o;
                     sem := Post(sem);
                 };
             };
             \* esdm_shm_status_set_need_entropy(): a post on a change
st4:         with (n \in RestartNeed) {
                 if (shmNeed # n) {
                     shmNeed := n;
                     sem := Post(sem);
                 };
             };
             \* the suspend generation is kept (before the fix: the trigger
             \* cleared)
st5:         if (~SuspendGen) sgen := 0;
             \* the version published last, and the post after it
st6:         shmVer := TRUE;
             if (PostAfterPublish) sem := Post(sem);
             \* the RPC sockets serve
st7:         srvUp := TRUE;
         };
     }
}

\* the model at rest
process (idle = "idle")
{
id1: while (TRUE) {
         await Quiescent;
         skip;
     }
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, kReady, 
          onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, phLock, 
          rdrs, wrr, wwait, gmask, cseen, ggen, gok, viol, pc, stack

(* define statement *)
Avail == shmVer \/ ~PollFallback

StatusOp == Avail /\ shmOp
StatusNeed == Avail /\ shmNeed

KMask == IF Urandom THEN {"in", "out"}
         ELSE IF kReady THEN {"in"} ELSE {"out"}



Rpc(w) == IF ~srvUp THEN "kernel"
          ELSE IF esdmOp /\ ~spent THEN "data"
          ELSE IF ~w /\ ~esdmOp THEN "kernel"
          ELSE "eagain"

NoWait == IF Urandom THEN ~(srvUp /\ esdmOp /\ spent)
          ELSE (~srvUp /\ kReady) \/ (srvUp /\ esdmOp /\ ~spent)

Asleep(c) == pc[c] = "pl3" /\ ~woken[c]


Quiescent ==
    /\ \A c \in PollIn :
           pc[c] = "Done" \/ (Asleep(c) /\ ~StatusOp /\ ~NoWait)
    /\ \A c \in PollOut : pc[c] = "Done" \/ (Asleep(c) /\ ~StatusNeed)
    /\ \A c \in Probe \cup ReadC \cup Ioctls : pc[c] = "Done"

VARIABLES gv, pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, opc, 
          ndc, spc, svc, ssc, klc

vars == << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, kReady, 
           onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, phLock, 
           rdrs, wrr, wwait, gmask, cseen, ggen, gok, viol, pc, stack, gv, 
           pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, opc, ndc, 
           spc, svc, ssc, klc >>

ProcSet == (Workers) \cup {"ck"} \cup (PollC) \cup (Probe) \cup (ReadC) \cup (Ioctls) \cup {"env"} \cup {"idle"}

Init == (* Global variables *)
        /\ srvUp = TRUE
        /\ esdmOp = StartOp
        /\ spent = FALSE
        /\ shmVer = TRUE
        /\ shmOp = StartOp
        /\ shmNeed = FALSE
        /\ sgen = 0
        /\ sem = 0
        /\ kReady = KernelReady
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
        /\ gmask = [p \in MaskP |-> {}]
        /\ cseen = 0
        /\ ggen = [p \in Workers |-> 0]
        /\ gok = [p \in Workers |-> FALSE]
        /\ viol = {}
        (* Procedure getMask *)
        /\ gv = [ self \in ProcSet |-> TRUE]
        (* Procedure pollH *)
        /\ pcl = [ self \in ProcSet |-> defaultInitValue]
        /\ pph = [ self \in ProcSet |-> defaultInitValue]
        /\ evs = [ self \in ProcSet |-> {}]
        /\ pg = [ self \in ProcSet |-> 0]
        (* Procedure readH *)
        /\ rcl = [ self \in ProcSet |-> defaultInitValue]
        /\ wmode = [ self \in ProcSet |-> FALSE]
        /\ res = [ self \in ProcSet |-> "none"]
        (* Procedure ioctlH *)
        /\ icl = [ self \in ProcSet |-> defaultInitValue]
        (* Process k *)
        /\ r = [self \in Workers |-> NoReq]
        (* Process ck *)
        /\ cgen = 0
        (* Process rd *)
        /\ sigd = [self \in ReadC |-> FALSE]
        (* Process env *)
        /\ opc = 0
        /\ ndc = 0
        /\ spc = 0
        /\ svc = 0
        /\ ssc = 0
        /\ klc = 0
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in Workers -> "wk1"
                                        [] self = "ck" -> "ck1"
                                        [] self \in PollC -> "pl1"
                                        [] self \in Probe -> "pr1"
                                        [] self \in ReadC -> "rc1"
                                        [] self \in Ioctls -> "ic1"
                                        [] self = "env" -> "en1"
                                        [] self = "idle" -> "id1"]

gm1(self) == /\ pc[self] = "gm1"
             /\ gv' = [gv EXCEPT ![self] = Avail]
             /\ gmask' = [gmask EXCEPT ![self] = {}]
             /\ IF self \in Workers
                   THEN /\ gok' = [gok EXCEPT ![self] = NoWait \/ StatusOp]
                   ELSE /\ TRUE
                        /\ gok' = gok
             /\ pc' = [pc EXCEPT ![self] = "gm2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, cseen, ggen, viol, stack, pcl, pph, evs, 
                             pg, rcl, wmode, res, icl, r, cgen, sigd, opc, ndc, 
                             spc, svc, ssc, klc >>

gm2(self) == /\ pc[self] = "gm2"
             /\ IF ~gv[self]
                   THEN /\ gmask' = [gmask EXCEPT ![self] = KMask]
                        /\ IF self \in Workers
                              THEN /\ gok' = [gok EXCEPT ![self] = gok[self] \/ NoWait \/ StatusOp]
                              ELSE /\ TRUE
                                   /\ gok' = gok
                        /\ pc' = [pc EXCEPT ![self] = "gm4"]
                   ELSE /\ IF shmOp
                              THEN /\ gmask' = [gmask EXCEPT ![self] = {"in"}]
                              ELSE /\ IF PollFallback /\ Urandom
                                         THEN /\ gmask' = [gmask EXCEPT ![self] = KMask \cap {"in"}]
                                         ELSE /\ TRUE
                                              /\ gmask' = gmask
                        /\ IF self \in Workers
                              THEN /\ gok' = [gok EXCEPT ![self] = gok[self] \/ NoWait \/ StatusOp]
                              ELSE /\ TRUE
                                   /\ gok' = gok
                        /\ IF PollOut = {}
                              THEN /\ pc' = [pc EXCEPT ![self] = "gm4"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "gm3"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, cseen, ggen, viol, stack, gv, pcl, pph, 
                             evs, pg, rcl, wmode, res, icl, r, cgen, sigd, opc, 
                             ndc, spc, svc, ssc, klc >>

gm3(self) == /\ pc[self] = "gm3"
             /\ IF shmNeed
                   THEN /\ gmask' = [gmask EXCEPT ![self] = gmask[self] \cup {"out"}]
                   ELSE /\ TRUE
                        /\ gmask' = gmask
             /\ pc' = [pc EXCEPT ![self] = "gm4"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, cseen, ggen, gok, viol, stack, gv, pcl, 
                             pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

gm4(self) == /\ pc[self] = "gm4"
             /\ IF SuspendGen /\ self \in Workers
                   THEN /\ ggen' = [ggen EXCEPT ![self] = sgen]
                   ELSE /\ TRUE
                        /\ ggen' = ggen
             /\ IF self \in Workers
                   THEN /\ gok' = [gok EXCEPT ![self] = gok[self] \/ NoWait \/ StatusOp]
                   ELSE /\ TRUE
                        /\ gok' = gok
             /\ IF ~SuspendGen \/ self = "ck"
                   THEN /\ IF sgen # cseen
                              THEN /\ gmask' = [gmask EXCEPT ![self] = {"in", "out"}]
                              ELSE /\ TRUE
                                   /\ gmask' = gmask
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ gv' = [gv EXCEPT ![self] = Head(stack[self]).gv]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "gm5"]
                        /\ UNCHANGED << gmask, stack, gv >>
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, cseen, viol, pcl, pph, evs, pg, rcl, wmode, 
                             res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                             klc >>

gm5(self) == /\ pc[self] = "gm5"
             /\ IF ggen[self] # cseen
                   THEN /\ gmask' = [gmask EXCEPT ![self] = {"in", "out"}]
                   ELSE /\ TRUE
                        /\ gmask' = gmask
             /\ gok' = [gok EXCEPT ![self] = gok[self] \/ NoWait \/ StatusOp]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ gv' = [gv EXCEPT ![self] = Head(stack[self]).gv]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, cseen, ggen, viol, pcl, pph, evs, pg, rcl, 
                             wmode, res, icl, r, cgen, sigd, opc, ndc, spc, 
                             svc, ssc, klc >>

getMask(self) == gm1(self) \/ gm2(self) \/ gm3(self) \/ gm4(self)
                    \/ gm5(self)

ph0(self) == /\ pc[self] = "ph0"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getMask",
                                                      pc        |->  "ph1",
                                                      gv        |->  gv[self] ] >>
                                                  \o stack[self]]
             /\ gv' = [gv EXCEPT ![self] = TRUE]
             /\ pc' = [pc EXCEPT ![self] = "gm1"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, pcl, pph, 
                             evs, pg, rcl, wmode, res, icl, r, cgen, sigd, opc, 
                             ndc, spc, svc, ssc, klc >>

ph1(self) == /\ pc[self] = "ph1"
             /\ pgot' = [pgot EXCEPT ![pcl[self]] = TRUE]
             /\ pmask' = [pmask EXCEPT ![pcl[self]] = gmask[self] \cap Ev(pcl[self])]
             /\ IF "in" \in gmask[self] \cap Ev(pcl[self]) /\ ~gok[self]
                   THEN /\ viol' = (viol \cup {"SpuriousReadable"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ gok' = [gok EXCEPT ![self] = FALSE]
             /\ IF KeepNullPh /\ pph[self] = "null"
                   THEN /\ gmask' = [gmask EXCEPT ![self] = {}]
                        /\ ggen' = [ggen EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ evs' = [evs EXCEPT ![self] = Head(stack[self]).evs]
                        /\ pg' = [pg EXCEPT ![self] = Head(stack[self]).pg]
                        /\ pcl' = [pcl EXCEPT ![self] = Head(stack[self]).pcl]
                        /\ pph' = [pph EXCEPT ![self] = Head(stack[self]).pph]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ph2"]
                        /\ UNCHANGED << gmask, ggen, stack, pcl, pph, evs, pg >>
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             cseen, gv, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

ph2(self) == /\ pc[self] = "ph2"
             /\ phLock = NoProc
             /\ IF gmask[self] \cap (Ev(pcl[self]) \cup reg.ev) # {}
                   THEN /\ IF pph[self] = "real"
                              THEN /\ woken' = [c \in PollC |-> woken[c] \/ c \in onWQ]
                              ELSE /\ TRUE
                                   /\ woken' = woken
                        /\ reg' = NoReg
                        /\ gmask' = [gmask EXCEPT ![self] = {}]
                        /\ ggen' = [ggen EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ evs' = [evs EXCEPT ![self] = Head(stack[self]).evs]
                        /\ pg' = [pg EXCEPT ![self] = Head(stack[self]).pg]
                        /\ pcl' = [pcl EXCEPT ![self] = Head(stack[self]).pcl]
                        /\ pph' = [pph EXCEPT ![self] = Head(stack[self]).pph]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED phLock
                   ELSE /\ evs' = [evs EXCEPT ![self] = Ev(pcl[self]) \cup reg.ev]
                        /\ reg' = [ev |-> Ev(pcl[self]) \cup reg.ev, ph |-> pph[self]]
                        /\ phLock' = self
                        /\ gmask' = [gmask EXCEPT ![self] = {}]
                        /\ IF RecheckGen
                              THEN /\ pg' = [pg EXCEPT ![self] = ggen[self]]
                              ELSE /\ TRUE
                                   /\ pg' = pg
                        /\ pc' = [pc EXCEPT ![self] = "ph3"]
                        /\ UNCHANGED << woken, ggen, stack, pcl, pph >>
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, reqs, pgot, pmask, 
                             rreply, ireply, intrd, rdrs, wrr, wwait, cseen, 
                             gok, viol, gv, rcl, wmode, res, icl, r, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

ph3(self) == /\ pc[self] = "ph3"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "getMask",
                                                      pc        |->  "ph4",
                                                      gv        |->  gv[self] ] >>
                                                  \o stack[self]]
             /\ gv' = [gv EXCEPT ![self] = TRUE]
             /\ pc' = [pc EXCEPT ![self] = "gm1"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, pcl, pph, 
                             evs, pg, rcl, wmode, res, icl, r, cgen, sigd, opc, 
                             ndc, spc, svc, ssc, klc >>

ph4(self) == /\ pc[self] = "ph4"
             /\ IF gmask[self] \cap evs[self] # {} \/ (RecheckGen /\ ggen[self] # pg[self])
                   THEN /\ IF pph[self] = "real"
                              THEN /\ woken' = [c \in PollC |-> woken[c] \/ c \in onWQ]
                              ELSE /\ TRUE
                                   /\ woken' = woken
                        /\ reg' = NoReg
                   ELSE /\ TRUE
                        /\ UNCHANGED << woken, reg >>
             /\ gmask' = [gmask EXCEPT ![self] = {}]
             /\ ggen' = [ggen EXCEPT ![self] = 0]
             /\ gok' = [gok EXCEPT ![self] = FALSE]
             /\ phLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ evs' = [evs EXCEPT ![self] = Head(stack[self]).evs]
             /\ pg' = [pg EXCEPT ![self] = Head(stack[self]).pg]
             /\ pcl' = [pcl EXCEPT ![self] = Head(stack[self]).pcl]
             /\ pph' = [pph EXCEPT ![self] = Head(stack[self]).pph]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, reqs, pgot, pmask, 
                             rreply, ireply, intrd, rdrs, wrr, wwait, cseen, 
                             viol, gv, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

pollH(self) == ph0(self) \/ ph1(self) \/ ph2(self) \/ ph3(self)
                  \/ ph4(self)

rh0(self) == /\ pc[self] = "rh0"
             /\ wmode' = [wmode EXCEPT ![self] = ~Urandom]
             /\ pc' = [pc EXCEPT ![self] = "rh1"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

rh1(self) == /\ pc[self] = "rh1"
             /\ wrr = NoProc /\ wwait = {}
             /\ rdrs' = (rdrs \cup {self})
             /\ pc' = [pc EXCEPT ![self] = "rh2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, wrr, wwait, 
                             gmask, cseen, ggen, gok, viol, stack, gv, pcl, 
                             pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

rh2(self) == /\ pc[self] = "rh2"
             /\ res' = [res EXCEPT ![self] = Rpc(wmode[self])]
             /\ rdrs' = rdrs \ {self}
             /\ IF Rpc(wmode[self]) = "eagain" /\ Urandom /\ ~esdmOp
                   THEN /\ viol' = (viol \cup {"UrandomWaitsNonop"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = "rh3"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, wrr, wwait, 
                             gmask, cseen, ggen, gok, stack, gv, pcl, pph, evs, 
                             pg, rcl, wmode, icl, r, cgen, sigd, opc, ndc, spc, 
                             svc, ssc, klc >>

rh3(self) == /\ pc[self] = "rh3"
             /\ IF res[self] = "eagain" /\ HonorNonblock /\ rcl[self] \in NbReaders
                   THEN /\ rreply' = [rreply EXCEPT ![rcl[self]] = "eagain"]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ wmode' = [wmode EXCEPT ![self] = Head(stack[self]).wmode]
                        /\ res' = [res EXCEPT ![self] = Head(stack[self]).res]
                        /\ rcl' = [rcl EXCEPT ![self] = Head(stack[self]).rcl]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ viol' = viol
                   ELSE /\ IF res[self] = "eagain" /\ intrd[rcl[self]]
                              THEN /\ rreply' = [rreply EXCEPT ![rcl[self]] = "eintr"]
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
                                         ELSE /\ IF res[self] = "kernel" /\ ~Urandom /\ ~kReady
                                                    THEN /\ IF rcl[self] \in NbReaders
                                                               THEN /\ viol' = (viol \cup {"NonblockWaits"})
                                                               ELSE /\ TRUE
                                                                    /\ viol' = viol
                                                         /\ pc' = [pc EXCEPT ![self] = "rh4"]
                                                         /\ UNCHANGED << rreply, 
                                                                         stack, 
                                                                         rcl, 
                                                                         wmode, 
                                                                         res >>
                                                    ELSE /\ rreply' = [rreply EXCEPT ![rcl[self]] = "data"]
                                                         /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                                         /\ wmode' = [wmode EXCEPT ![self] = Head(stack[self]).wmode]
                                                         /\ res' = [res EXCEPT ![self] = Head(stack[self]).res]
                                                         /\ rcl' = [rcl EXCEPT ![self] = Head(stack[self]).rcl]
                                                         /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                                         /\ viol' = viol
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             gmask, cseen, ggen, gok, gv, pcl, pph, evs, pg, 
                             icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

rh4(self) == /\ pc[self] = "rh4"
             /\ kReady
             /\ rreply' = [rreply EXCEPT ![rcl[self]] = "data"]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ wmode' = [wmode EXCEPT ![self] = Head(stack[self]).wmode]
             /\ res' = [res EXCEPT ![self] = Head(stack[self]).res]
             /\ rcl' = [rcl EXCEPT ![self] = Head(stack[self]).rcl]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             gmask, cseen, ggen, gok, viol, gv, pcl, pph, evs, 
                             pg, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                             klc >>

readH(self) == rh0(self) \/ rh1(self) \/ rh2(self) \/ rh3(self)
                  \/ rh4(self)

io1(self) == /\ pc[self] = "io1"
             /\ wwait' = (wwait \cup {self})
             /\ pc' = [pc EXCEPT ![self] = "io2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             gmask, cseen, ggen, gok, viol, stack, gv, pcl, 
                             pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

io2(self) == /\ pc[self] = "io2"
             /\ rdrs = {} /\ wrr = NoProc
             /\ wrr' = self
             /\ wwait' = wwait \ {self}
             /\ pc' = [pc EXCEPT ![self] = "io3"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, gmask, 
                             cseen, ggen, gok, viol, stack, gv, pcl, pph, evs, 
                             pg, rcl, wmode, res, icl, r, cgen, sigd, opc, ndc, 
                             spc, svc, ssc, klc >>

io3(self) == /\ pc[self] = "io3"
             /\ wrr' = NoProc
             /\ ireply' = [ireply EXCEPT ![icl[self]] = TRUE]
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ icl' = [icl EXCEPT ![self] = Head(stack[self]).icl]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, intrd, reg, phLock, rdrs, wwait, gmask, 
                             cseen, ggen, gok, viol, gv, pcl, pph, evs, pg, 
                             rcl, wmode, res, r, cgen, sigd, opc, ndc, spc, 
                             svc, ssc, klc >>

ioctlH(self) == io1(self) \/ io2(self) \/ io3(self)

wk1(self) == /\ pc[self] = "wk1"
             /\ reqs # {}
             /\ \E q \in IF \E x \in reqs : x.t = "intr"
                         THEN {x \in reqs : x.t = "intr"} ELSE reqs:
                  /\ r' = [r EXCEPT ![self] = q]
                  /\ reqs' = reqs \ {q}
             /\ pc' = [pc EXCEPT ![self] = "wk2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

wk2(self) == /\ pc[self] = "wk2"
             /\ IF r[self].t = "poll"
                   THEN /\ /\ pcl' = [pcl EXCEPT ![self] = r[self].c]
                           /\ pph' = [pph EXCEPT ![self] = r[self].ph]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "pollH",
                                                                    pc        |->  "wk3",
                                                                    evs       |->  evs[self],
                                                                    pg        |->  pg[self],
                                                                    pcl       |->  pcl[self],
                                                                    pph       |->  pph[self] ] >>
                                                                \o stack[self]]
                        /\ evs' = [evs EXCEPT ![self] = {}]
                        /\ pg' = [pg EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "ph0"]
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
                        /\ UNCHANGED << pcl, pph, evs, pg >>
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, reg, phLock, rdrs, wrr, wwait, 
                             gmask, cseen, ggen, gok, viol, gv, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

wk3(self) == /\ pc[self] = "wk3"
             /\ r' = [r EXCEPT ![self] = NoReq]
             /\ pc' = [pc EXCEPT ![self] = "wk1"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

k(self) == wk1(self) \/ wk2(self) \/ wk3(self)

ck1 == /\ pc["ck"] = "ck1"
       /\ phLock = NoProc
       /\ phLock' = "ck"
       /\ cgen' = sgen
       /\ pc' = [pc EXCEPT !["ck"] = "ck2"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                       viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, res, 
                       icl, r, sigd, opc, ndc, spc, svc, ssc, klc >>

ck2 == /\ pc["ck"] = "ck2"
       /\ IF reg # NoReg
             THEN /\ stack' = [stack EXCEPT !["ck"] = << [ procedure |->  "getMask",
                                                           pc        |->  "ck3",
                                                           gv        |->  gv["ck"] ] >>
                                                       \o stack["ck"]]
                  /\ gv' = [gv EXCEPT !["ck"] = TRUE]
                  /\ pc' = [pc EXCEPT !["ck"] = "gm1"]
             ELSE /\ pc' = [pc EXCEPT !["ck"] = "ck4"]
                  /\ UNCHANGED << stack, gv >>
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, pcl, pph, evs, pg, rcl, wmode, res, 
                       icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

ck3 == /\ pc["ck"] = "ck3"
       /\ IF gmask["ck"] \cap reg.ev # {}
             THEN /\ IF (reg.ph) = "real"
                        THEN /\ woken' = [c \in PollC |-> woken[c] \/ c \in onWQ]
                        ELSE /\ TRUE
                             /\ woken' = woken
                  /\ reg' = NoReg
             ELSE /\ TRUE
                  /\ UNCHANGED << woken, reg >>
       /\ gmask' = [gmask EXCEPT !["ck"] = {}]
       /\ pc' = [pc EXCEPT !["ck"] = "ck4"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, 
                       kReady, onWQ, reqs, pgot, pmask, rreply, ireply, intrd, 
                       phLock, rdrs, wrr, wwait, cseen, ggen, gok, viol, stack, 
                       gv, pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                       sigd, opc, ndc, spc, svc, ssc, klc >>

ck4 == /\ pc["ck"] = "ck4"
       /\ IF SuspendGen
             THEN /\ cseen' = cgen
                  /\ sgen' = sgen
             ELSE /\ IF cgen # 0
                        THEN /\ sgen' = 0
                        ELSE /\ TRUE
                             /\ sgen' = sgen
                  /\ cseen' = cseen
       /\ cgen' = 0
       /\ phLock' = NoProc
       /\ pc' = [pc EXCEPT !["ck"] = "ck5"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, rdrs, wrr, wwait, gmask, ggen, gok, viol, 
                       stack, gv, pcl, pph, evs, pg, rcl, wmode, res, icl, r, 
                       sigd, opc, ndc, spc, svc, ssc, klc >>

ck5 == /\ pc["ck"] = "ck5"
       /\ IF PollFallback /\ ~shmVer
             THEN /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
             ELSE /\ shmVer
                  /\ pc' = [pc EXCEPT !["ck"] = "ck6"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                       klc >>

ck6 == /\ pc["ck"] = "ck6"
       /\ sem > 0
       /\ sem' = sem - 1
       /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                       klc >>

ck == ck1 \/ ck2 \/ ck3 \/ ck4 \/ ck5 \/ ck6

pl1(self) == /\ pc[self] = "pl1"
             /\ onWQ' = (onWQ \cup {self})
             /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]})
             /\ pc' = [pc EXCEPT ![self] = "pl2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, woken, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             gmask, cseen, ggen, gok, viol, stack, gv, pcl, 
                             pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

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
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, pmask, rreply, ireply, intrd, 
                             reg, phLock, rdrs, wrr, wwait, gmask, cseen, ggen, 
                             gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                             wmode, res, icl, r, cgen, sigd, opc, ndc, spc, 
                             svc, ssc, klc >>

pl3(self) == /\ pc[self] = "pl3"
             /\ woken[self]
             /\ woken' = [woken EXCEPT ![self] = FALSE]
             /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self, ph |-> "real"]})
             /\ pc' = [pc EXCEPT ![self] = "pl2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, pgot, pmask, rreply, 
                             ireply, intrd, reg, phLock, rdrs, wrr, wwait, 
                             gmask, cseen, ggen, gok, viol, stack, gv, pcl, 
                             pph, evs, pg, rcl, wmode, res, icl, r, cgen, sigd, 
                             opc, ndc, spc, svc, ssc, klc >>

plDone(self) == /\ pc[self] = "plDone"
                /\ TRUE
                /\ pc' = [pc EXCEPT ![self] = "Done"]
                /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                                sgen, sem, kReady, onWQ, woken, reqs, pgot, 
                                pmask, rreply, ireply, intrd, reg, phLock, 
                                rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                                viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, 
                                res, icl, r, cgen, sigd, opc, ndc, spc, svc, 
                                ssc, klc >>

pl(self) == pl1(self) \/ pl2(self) \/ pl3(self) \/ plDone(self)

pr1(self) == /\ pc[self] = "pr1"
             /\ reqs' = (reqs \cup {[t |-> "poll", c |-> self,
                                     ph |-> IF onWQ = {} THEN "null" ELSE "real"]})
             /\ pc' = [pc EXCEPT ![self] = "pr2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

pr2(self) == /\ pc[self] = "pr2"
             /\ pgot[self]
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

pr(self) == pr1(self) \/ pr2(self)

rc1(self) == /\ pc[self] = "rc1"
             /\ reqs' = (reqs \cup {[t |-> "read", c |-> self, ph |-> "none"]})
             /\ pc' = [pc EXCEPT ![self] = "rc2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

rc2(self) == /\ pc[self] = "rc2"
             /\ \/ /\ rreply[self] # "none"
                   /\ pc' = [pc EXCEPT ![self] = "rcDone"]
                   /\ UNCHANGED <<reqs, sigd>>
                \/ /\ self \in Signalled /\ ~sigd[self] /\ rreply[self] = "none"
                   /\ sigd' = [sigd EXCEPT ![self] = TRUE]
                   /\ reqs' = (reqs \cup {[t |-> "intr", c |-> self, ph |-> "none"]})
                   /\ pc' = [pc EXCEPT ![self] = "rc2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                             opc, ndc, spc, svc, ssc, klc >>

rcDone(self) == /\ pc[self] = "rcDone"
                /\ TRUE
                /\ pc' = [pc EXCEPT ![self] = "Done"]
                /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                                sgen, sem, kReady, onWQ, woken, reqs, pgot, 
                                pmask, rreply, ireply, intrd, reg, phLock, 
                                rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                                viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, 
                                res, icl, r, cgen, sigd, opc, ndc, spc, svc, 
                                ssc, klc >>

rd(self) == rc1(self) \/ rc2(self) \/ rcDone(self)

ic1(self) == /\ pc[self] = "ic1"
             /\ reqs' = (reqs \cup {[t |-> "ioctl", c |-> self, ph |-> "none"]})
             /\ pc' = [pc EXCEPT ![self] = "ic2"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

ic2(self) == /\ pc[self] = "ic2"
             /\ ireply[self]
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, 
                             sgen, sem, kReady, onWQ, woken, reqs, pgot, pmask, 
                             rreply, ireply, intrd, reg, phLock, rdrs, wrr, 
                             wwait, gmask, cseen, ggen, gok, viol, stack, gv, 
                             pcl, pph, evs, pg, rcl, wmode, res, icl, r, cgen, 
                             sigd, opc, ndc, spc, svc, ssc, klc >>

io(self) == ic1(self) \/ ic2(self)

en1 == /\ pc["env"] = "en1"
       /\ \/ /\ srvUp /\ opc < OpChanges
             /\ opc' = opc + 1
             /\ esdmOp' = ~esdmOp
             /\ pc' = [pc EXCEPT !["env"] = "en2"]
             /\ UNCHANGED <<srvUp, spent, shmVer, shmNeed, sgen, sem, kReady, ndc, spc, svc, ssc, klc>>
          \/ /\ srvUp /\ ndc < NeedChanges
             /\ ndc' = ndc + 1
             /\ shmNeed' = ~shmNeed
             /\ sem' = Post(sem)
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmVer, sgen, kReady, opc, spc, svc, ssc, klc>>
          \/ /\ srvUp /\ esdmOp /\ spc < SpentChanges
             /\ spc' = spc + 1
             /\ spent' = ~spent
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, shmVer, shmNeed, sgen, sem, kReady, opc, ndc, svc, ssc, klc>>
          \/ /\ srvUp /\ ssc < Suspends
             /\ ssc' = ssc + 1
             /\ sgen' = IF SuspendGen THEN sgen + 1 ELSE 1
             /\ sem' = Post(sem)
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmVer, shmNeed, kReady, opc, ndc, spc, svc, klc>>
          \/ /\ ~kReady
             /\ kReady' = TRUE
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmVer, shmNeed, sgen, sem, opc, ndc, spc, svc, ssc, klc>>
          \/ /\ srvUp /\ svc < SrvChanges
             /\ svc' = svc + 1
             /\ srvUp' = FALSE
             /\ esdmOp' = FALSE
             /\ spent' = FALSE
             /\ pc' = [pc EXCEPT !["env"] = "ex2"]
             /\ UNCHANGED <<shmVer, shmNeed, sgen, sem, kReady, opc, ndc, spc, ssc, klc>>
          \/ /\ srvUp /\ klc < Kills
             /\ klc' = klc + 1
             /\ srvUp' = FALSE
             /\ esdmOp' = FALSE
             /\ spent' = FALSE
             /\ pc' = [pc EXCEPT !["env"] = "en1"]
             /\ UNCHANGED <<shmVer, shmNeed, sgen, sem, kReady, opc, ndc, spc, svc, ssc>>
          \/ /\ ~srvUp /\ svc < SrvChanges
             /\ svc' = svc + 1
             /\ shmVer' = FALSE
             /\ pc' = [pc EXCEPT !["env"] = "st2"]
             /\ UNCHANGED <<srvUp, esdmOp, spent, shmNeed, sgen, sem, kReady, opc, ndc, spc, ssc, klc>>
       /\ UNCHANGED << shmOp, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd >>

en2 == /\ pc["env"] = "en2"
       /\ shmOp' = esdmOp
       /\ sem' = Post(sem)
       /\ pc' = [pc EXCEPT !["env"] = "en1"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmNeed, sgen, kReady, 
                       onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                       viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, res, 
                       icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

ex2 == /\ pc["env"] = "ex2"
       /\ IF PollFallback
             THEN /\ shmVer' = FALSE
             ELSE /\ TRUE
                  /\ UNCHANGED shmVer
       /\ pc' = [pc EXCEPT !["env"] = "ex3"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, sgen, sem, kReady, 
                       onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                       viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, res, 
                       icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

ex3 == /\ pc["env"] = "ex3"
       /\ sgen' = IF SuspendGen THEN sgen + 1 ELSE 1
       /\ sem' = Post(sem)
       /\ pc' = [pc EXCEPT !["env"] = "en1"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, kReady, 
                       onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                       viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, res, 
                       icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

st2 == /\ pc["env"] = "st2"
       /\ sem' = Post(sem)
       /\ pc' = [pc EXCEPT !["env"] = "st3"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                       klc >>

st3 == /\ pc["env"] = "st3"
       /\ \E o \in RestartOp:
            /\ esdmOp' = o
            /\ IF shmOp # o
                  THEN /\ shmOp' = o
                       /\ sem' = Post(sem)
                  ELSE /\ TRUE
                       /\ UNCHANGED << shmOp, sem >>
       /\ pc' = [pc EXCEPT !["env"] = "st4"]
       /\ UNCHANGED << srvUp, spent, shmVer, shmNeed, sgen, kReady, onWQ, 
                       woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, 
                       phLock, rdrs, wrr, wwait, gmask, cseen, ggen, gok, viol, 
                       stack, gv, pcl, pph, evs, pg, rcl, wmode, res, icl, r, 
                       cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

st4 == /\ pc["env"] = "st4"
       /\ \E n \in RestartNeed:
            IF shmNeed # n
               THEN /\ shmNeed' = n
                    /\ sem' = Post(sem)
               ELSE /\ TRUE
                    /\ UNCHANGED << shmNeed, sem >>
       /\ pc' = [pc EXCEPT !["env"] = "st5"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, sgen, kReady, onWQ, 
                       woken, reqs, pgot, pmask, rreply, ireply, intrd, reg, 
                       phLock, rdrs, wrr, wwait, gmask, cseen, ggen, gok, viol, 
                       stack, gv, pcl, pph, evs, pg, rcl, wmode, res, icl, r, 
                       cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

st5 == /\ pc["env"] = "st5"
       /\ IF ~SuspendGen
             THEN /\ sgen' = 0
             ELSE /\ TRUE
                  /\ sgen' = sgen
       /\ pc' = [pc EXCEPT !["env"] = "st6"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                       klc >>

st6 == /\ pc["env"] = "st6"
       /\ shmVer' = TRUE
       /\ IF PostAfterPublish
             THEN /\ sem' = Post(sem)
             ELSE /\ TRUE
                  /\ sem' = sem
       /\ pc' = [pc EXCEPT !["env"] = "st7"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmOp, shmNeed, sgen, kReady, 
                       onWQ, woken, reqs, pgot, pmask, rreply, ireply, intrd, 
                       reg, phLock, rdrs, wrr, wwait, gmask, cseen, ggen, gok, 
                       viol, stack, gv, pcl, pph, evs, pg, rcl, wmode, res, 
                       icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, klc >>

st7 == /\ pc["env"] = "st7"
       /\ srvUp' = TRUE
       /\ pc' = [pc EXCEPT !["env"] = "en1"]
       /\ UNCHANGED << esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                       klc >>

env == en1 \/ en2 \/ ex2 \/ ex3 \/ st2 \/ st3 \/ st4 \/ st5 \/ st6 \/ st7

id1 == /\ pc["idle"] = "id1"
       /\ Quiescent
       /\ TRUE
       /\ pc' = [pc EXCEPT !["idle"] = "id1"]
       /\ UNCHANGED << srvUp, esdmOp, spent, shmVer, shmOp, shmNeed, sgen, sem, 
                       kReady, onWQ, woken, reqs, pgot, pmask, rreply, ireply, 
                       intrd, reg, phLock, rdrs, wrr, wwait, gmask, cseen, 
                       ggen, gok, viol, stack, gv, pcl, pph, evs, pg, rcl, 
                       wmode, res, icl, r, cgen, sigd, opc, ndc, spc, svc, ssc, 
                       klc >>

idle == id1

Next == ck \/ env \/ idle
           \/ (\E self \in ProcSet:  \/ getMask(self) \/ pollH(self)
                                     \/ readH(self) \/ ioctlH(self))
           \/ (\E self \in Workers: k(self))
           \/ (\E self \in PollC: pl(self))
           \/ (\E self \in Probe: pr(self))
           \/ (\E self \in ReadC: rd(self))
           \/ (\E self \in Ioctls: io(self))

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Workers : /\ WF_vars(k(self))
                                 /\ WF_vars(pollH(self)) /\ SF_vars(ph2(self))
                                 /\ WF_vars(readH(self))
                                 /\ WF_vars(ioctlH(self))
                                 /\ WF_vars(getMask(self))
        /\ WF_vars(ck) /\ WF_vars(getMask("ck"))
        /\ \A self \in PollC : WF_vars(pl(self))
        /\ \A self \in Probe : WF_vars(pr(self))
        /\ \A self \in ReadC : WF_vars(rd(self))
        /\ \A self \in Ioctls : WF_vars(io(self))
        /\ WF_vars((pc["env"] # "en1") /\ env)

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ reg.ph \in {"none", "real", "null"}
    /\ reg.ev \subseteq {"in", "out"}
    /\ sem \in {0, 1}
    /\ cseen <= sgen
    /\ \A p \in MaskP : gmask[p] \subseteq {"in", "out"}
    /\ \A c \in Readers : rreply[c] \in {"none", "data", "eintr"}
    /\ \A c \in NbReaders : rreply[c] \in {"none", "data", "eintr", "eagain"}

\* A thread asleep in poll() can be woken: a registration with a handle
\* covers its events, or a poll request of the file is still under way.
Covered(c) ==
    \/ reg.ph = "real" /\ Ev(c) \subseteq reg.ev
    \/ \E q \in reqs : q.t = "poll"
    \/ \E x \in Workers : pc[x] \in {"ph0", "ph1", "ph2", "ph3", "ph4",
                                      "gm1", "gm2", "gm3", "gm4"}
WaiterCovered == \A c \in PollC : Asleep(c) => Covered(c)

\* poll() reports POLLIN only if, at one of the reads its mask comes from, a
\* read would not have waited or the status showed the ESDM operational.
PollReadable == "SpuriousReadable" \notin viol

\* A read with O_NONBLOCK never waits.
NonblockNeverWaits == "NonblockWaits" \notin viol

\* /dev/urandom waits only while the ESDM is operational; otherwise it reads
\* the kernel's device, as its first request does.
UrandomFallback == "UrandomWaitsNonop" \notin viol

\* Witnesses of the liveness defects, for the configurations demonstrating
\* them (TLC names violated invariants only): nothing changes any more and
\* a poller sleeps, though the status shows its event or a read would not
\* wait ...
PollNotStuck ==
    ~ENABLED Next
        => /\ \A c \in PollIn : Asleep(c) => (~StatusOp /\ ~NoWait)
           /\ \A c \in PollOut : Asleep(c) => ~StatusNeed

\* ... or the server changes nothing any more, reads wait, and every worker
\* loops in a read while a signalled reader's FUSE_INTERRUPT is queued.
InterruptNotStuck ==
    (~ENABLED env /\ ~NoWait)
        => \A c \in Signalled :
               (sigd[c] /\ ~intrd[c] /\ pc[c] = "rc2")
                   => \E x \in Workers :
                          pc[x] \notin {"rh0", "rh1", "rh2", "rh3", "rh4"}

-----------------------------------------------------------------------------
(* Liveness *)

\* A poller wakes once the status shows its event for good ...
Returned(c) == pc[c] \in {"plDone", "rcDone", "Done"}

PollWakes ==
    /\ \A c \in PollIn : <>[]StatusOp => <>Returned(c)
    /\ \A c \in PollOut : <>[]StatusNeed => <>Returned(c)

\* ... and once a read would not wait for good.
PollLive == \A c \in PollIn : <>[]NoWait => <>Returned(c)

\* A suspend notification the daemon has not acted on yet wakes the pollers
\* registered meanwhile (with the one-shot trigger not across a start of
\* the server, which cleared the trigger its predecessor raised) ...
Pending == sgen # cseen
Registered(c) == reg.ph = "real" /\ Ev(c) \subseteq reg.ev
SuspendWakes ==
    \A c \in PollC :
        [](Pending /\ Asleep(c) /\ Registered(c) => <>~Asleep(c))

\* ... and every thread asleep in poll(), registered or not. Without the
\* generation in the re-check of esdm_cuse_poll() it does not: the checker
\* acts on the notification while a poll that was answered before it is not
\* registered yet, and the re-check of that poll then finds nothing.
SuspendReaches == \A c \in PollC : [](Pending /\ Asleep(c) => <>~Asleep(c))

\* A poll() that does not wait is answered.
ProbesReturn == \A c \in Probe : <>Returned(c)

\* A read returns once it would not wait for good, an interrupted read in
\* any case, and so does a privileged ioctl.
ReadsReturn == \A c \in ReadC : <>[]NoWait => <>Returned(c)
InterruptHonored == \A c \in Signalled : [](sigd[c] => <>Returned(c))
IoctlsReturn == \A c \in Ioctls : <>Returned(c)
=============================================================================
