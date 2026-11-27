---------------------------- MODULE EsdmShmStatus ----------------------------
(***************************************************************************)
(* The status the esdm-server publishes in shared memory for other         *)
(* processes: esdm/esdm_shm_status.c on the server side, its readers in    *)
(* frontends/cuse/cuse_device.c (the poll checker of a CUSE daemon) and    *)
(* frontends/aux-client/esdm_aux_need_entropy.c. One System V segment      *)
(* under a well-known ftok() key holds version, operational, need_entropy  *)
(* and suspend_trigger; POSIX named semaphores, one per CUSE daemon and    *)
(* the level-triggered need_entropy one, tell the readers to look again.   *)
(* One step is one atomic variable access or one system call; the labels   *)
(* name the C functions they come from.                                    *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - Of the two CUSE semaphores only the one of esdm-cuse-random ("R") is  *)
(*   modelled, the urandom one is the same. Segments and semaphores have   *)
(*   identities: IPC_RMID takes a segment off the key, it lives on while   *)
(*   attached; sem_unlink() takes a semaphore off its name, holders keep   *)
(*   it. Every process has the same uid, the ownership checks are left     *)
(*   out, and so are the info/infolen/unpriv_threads fields.               *)
(* - The server's threads: the one holding the initial DRNG's lock         *)
(*   (esdm_init_ops(), esdm_unset_fully_seeded()) flips the operational    *)
(*   state and publishes it; threads changing the auxiliary pool flip      *)
(*   esdm_need_entropy() and call esdm_shm_status_set_need_entropy(). The  *)
(*   SIGUSR1 handler is one atomic step on the thread it interrupts. All   *)
(*   of them are quiescent while esdm_shm_status_init() runs (the server   *)
(*   starts no thread before) and are joined before the exit.              *)
(* - A server restart is a new process: the ESDM is not operational, the   *)
(*   segment and semaphores stay (--keep_ipc) or                           *)
(*   esdm_shm_status_cleanup_ipc removes them. A failed shmat() makes the  *)
(*   server exit and start again.                                          *)
(* - The CUSE daemon's poll checker samples the status in each pass, as if *)
(*   a poller were always registered (EsdmCuse.tla models the list); its   *)
(*   wait for the version is an await, with ExitUnpublish another pass.    *)
(* - The aux client's timeout is a branch that may be taken at any time.   *)
(* - Not modelled: the uid eviction, the EINVAL resize path, the urandom   *)
(*   daemon, shutdown of the readers, esdm_reinit() but for                *)
(*   InitConcurrent.                                                       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Life,           \* server lifecycle: it starts, exits and restarts
    Leftover,       \* segment and semaphore of an earlier, operational server
    Restarts,       \* server restarts
    KeepIpc,        \* --keep_ipc (the stock unit): no IPC cleanup at the exit
    Overlap,        \* the CUSE daemon's start overlaps the server's
    NeedW,          \* threads changing the auxiliary pool
    NeedChanges,    \* changes per such thread
    OpChanges,      \* operational state changes
    Suspends,       \* SIGUSR1 suspend signals
    EarlySignal,    \* a signal may come before the handler is installed
    Aux,            \* aux clients waiting for need entropy
    InitConcurrent, \* the DRNG thread runs during esdm_shm_status_init(), as
                    \* in esdm_reinit() (library API, not called by the server)
    PublishLast,    \* fix: version published after operational, need_entropy
    NeedLocked,     \* fix: esdm_shm_status_set_need_entropy() serialized
    InitLocked,     \* fix: the initial DRNG's lock around the init's snapshot
    CuseNoRmid,     \* fix: the CUSE daemon never removes a segment
    SemFix,         \* fix: combined posts, re-synchronizing post only on 0
    AuxRecheck,     \* fix: an aux client checks the flag after waking and
                    \* passes the wakeup on while the need lasts
    IgnoreEarly,    \* fix: SIGUSR1 ignored until the handler is installed
    ExitUnpublish,  \* fix: the exit withdraws the version; the CUSE checker
                    \* passes every second while no server publishes
    MaxSeg,         \* segment identities
    MaxSem          \* semaphore identities

Ready == 2                      \* ESDM_SHM_STATUS_VERSION
NoProc == "none"
Names == IF Aux = {} THEN {"R"} ELSE {"R", "L"}
SemId(n) == IF n = "R" THEN 1 ELSE 2
Segs == 1..MaxSeg
Sems == 1..MaxSem
DrngProcs == IF OpChanges > 0 THEN {"drng"} ELSE {}
SigProcs == IF Suspends > 0 THEN {"sig"} ELSE {}
AuxProcs == Aux
Procs == {"srv", "ck"} \cup DrngProcs \cup NeedW \cup SigProcs \cup AuxProcs
InitSegs == IF Life /\ ~Leftover THEN {} ELSE {1}

(* --algorithm EsdmShmStatus {
variables
    \* System V segments: the one the ftok() key names (0: none), the live
    \* ones, those taken off the key, attachments and contents
    keyAt = IF InitSegs = {} THEN 0 ELSE 1,
    alive = [s \in Segs |-> s \in InitSegs],
    removed = [s \in Segs |-> FALSE],
    att = [s \in Segs |-> IF s = 1 /\ ~Life THEN {"srv", "ck"} \cup AuxProcs
                          ELSE {}],
    ver = [s \in Segs |-> IF s \in InitSegs THEN Ready ELSE 0],
    sop = [s \in Segs |-> s = 1 /\ Life /\ Leftover],
    sneed = [s \in Segs |-> FALSE],
    ssusp = [s \in Segs |-> FALSE],
    nextSeg = IF InitSegs = {} THEN 1 ELSE 2,
    \* POSIX semaphores: the one each name names (0: none) and the values
    semAt = [n \in Names |-> IF InitSegs = {} THEN 0 ELSE SemId(n)],
    sval = [o \in Sems |-> 0],
    nextSem = IF InitSegs = {} THEN 1 ELSE Cardinality(Names) + 1,
    \* the server: esdm_shm_status, esdm_semid_*, the ESDM state
    srvState = IF Life THEN "down" ELSE "up",
    srvSeg = IF Life THEN 0 ELSE 1,
    srvSem = [n \in Names |-> IF Life THEN 0 ELSE SemId(n)],
    esdmOp = FALSE,         \* esdm_state.esdm_operational
    needT = FALSE,          \* esdm_need_entropy()
    handler = ~Life,        \* the SIGUSR1 handler is installed
    dlock = NoProc,         \* the initial DRNG's lock
    nlock = NoProc,         \* fix NeedLocked
    req = [n \in Names |-> 0], \* fix SemFix: requests of the combined posts
    startLock = NoProc,     \* systemd orders the starts (~Overlap)
    \* the CUSE daemon (esdm_cuse_shm_status, esdm_cuse_semid) and the aux
    \* clients, attached from the start without Life
    cuseState = IF Life THEN "off" ELSE "run",
    cuseSeg = IF Life THEN 0 ELSE 1,
    cuseSem = IF Life THEN 0 ELSE 1,
    \* ghosts: what the checker last saw, the posts a writer owes after its
    \* store, the server's fields refreshed since it attached, violations
    seen = <<FALSE, FALSE>>,
    owe = [p \in Procs |-> {}],
    fresh = TRUE,
    viol = {};

define {
    Content(s) == <<sop[s], sneed[s]>>
    OnOff(b) == IF b THEN "on" ELSE "off"
    Changed == cuseSeg # 0 /\ (Content(cuseSeg) # seen \/ ssusp[cuseSeg])
    \* the segment after IPC_RMID: gone if nobody is attached
    AliveAfterRm(s) == alive[s] /\ att[s] # {}
}

\* IPC_RMID of segment s
macro rmid(s) {
    alive[s] := AliveAfterRm(s);
    removed[s] := TRUE;
    if (keyAt = s) keyAt := 0;
}

\* shmget(IPC_CREAT): a new zeroed segment unless the key names one
macro shmgetCreate(var) {
    if (keyAt = 0) {
        assert nextSeg <= MaxSeg;
        var := nextSeg;
        keyAt := nextSeg;
        alive[nextSeg] := TRUE;
        nextSeg := nextSeg + 1;
    } else {
        var := keyAt;
    };
}

\* sem_open(O_CREAT): a new semaphore of value 0 unless the name names one
macro semOpen(n, var) {
    if (semAt[n] = 0) {
        assert nextSem <= MaxSem;
        var := nextSem;
        semAt[n] := nextSem;
        nextSem := nextSem + 1;
    } else {
        var := semAt[n];
    };
}

\* _esdm_shm_status_up(): sem_getvalue(), then sem_post() if it is 0; with
\* SemFix a caller finding another one posting leaves it to that one, which
\* looks again until no request came in meanwhile
procedure up(un)
    variables uo = 0, rq = 0;
{
up0: if (srvSem[un] = 0) {
         owe[self] := owe[self] \ {un};
         return;
     } else if (SemFix /\ req[un] > 0) {
         \* atomic_fetch_add() finds an owner
         req[un] := req[un] + 1;
         owe[self] := owe[self] \ {un};
         return;
     } else {
         if (SemFix) req[un] := 1;
         uo := srvSem[un];
     };
     \* atomic_load(), sem_getvalue()
up1: rq := req[un];
     if (sval[uo] > 0) goto up3;
up2: sval[uo] := sval[uo] + 1;
     \* atomic_compare_exchange_strong()
up3: if (SemFix /\ req[un] # rq) {
         goto up1;
     } else {
         if (SemFix) req[un] := 0;
         owe[self] := owe[self] \ {un};
         return;
     };
}

\* esdm_shm_status_set_operational(): the pointer and the flag, the store;
\* en is "on" or "off"
procedure setOp(en)
    variables oseg = 0;
{
op1: if (srvSeg = 0 \/ sop[srvSeg] = (en = "on")) {
         return;
     } else {
         oseg := srvSeg;
     };
op2: sop[oseg] := en = "on";
     owe[self] := owe[self] \cup {"R"};
     call up("R");
     return;
}

\* esdm_shm_status_set_need_entropy()
procedure setNeed()
    variables nseg = 0, curr = FALSE, nw = FALSE;
{
ne0: if (NeedLocked) {
         await nlock = NoProc;
         nlock := self;
     };
ne1: if (srvSeg = 0) {
         goto ne5;
     } else {
         nseg := srvSeg;
         curr := sneed[srvSeg];
     };
     \* esdm_need_entropy()
ne2: nw := needT;
     if (needT /\ Aux # {}) owe[self] := owe[self] \cup {"L"};
ne3: if (curr # nw) {
         sneed[nseg] := nw;
         owe[self] := owe[self] \cup {"R"};
         call up("R");
     };
     \* the level-triggered semaphore
ne4: if (nw /\ Aux # {}) call up("L");
ne5: if (NeedLocked) nlock := NoProc;
     return;
}

\* esdm_shm_status_create_sem()
procedure createSem(cn)
{
cm1: if (semAt[cn] = 0) {
         \* sem_open(O_CREAT | O_EXCL)
         semOpen(cn, srvSem[cn]);
         return;
     };
     \* EEXIST: sem_open(O_CREAT), then re-synchronize
cm2: semOpen(cn, srvSem[cn]);
cm3: if (SemFix) {
         call up(cn);
         return;
     } else {
         sval[srvSem[cn]] := sval[srvSem[cn]] + 1;
         return;
     };
}

fair process (srv = "srv")
    variables sid = 0, restarts = 0;
{
sv0: if (~Life) goto svUp;
     \* esdm_shm_status_create_shm(): shmget() without IPC_CREAT, then with
cs1: if (~Overlap) {
         await startLock = NoProc;
         startLock := "srv";
     };
     srvState := "init";
     sid := keyAt;
cs2: if (sid = 0) shmgetCreate(sid);
     \* shmat(), then version 0
cs3: if (~alive[sid]) {
         \* esdm_init() fails, systemd starts the server again
         sid := 0;
         if (~Overlap) startLock := NoProc;
         goto cs1;
     } else {
         att[sid] := att[sid] \cup {"srv"};
         srvSeg := sid;
         ver[sid] := 0;
         fresh := FALSE;
         sid := 0;
         if (~Overlap) startLock := NoProc;
     };
     \* esdm_shm_status_init()
cs4: call createSem("R");
cs5: if (Aux # {}) call createSem("L");
in1: if (~PublishLast) ver[srvSeg] := Ready;
     \* esdm_shm_status_set_operational(esdm_state_operational())
in2: if (InitLocked) {
         await dlock = NoProc;
         dlock := "srv";
     };
in3: call setOp(OnOff(esdmOp));
in4: if (InitLocked) dlock := NoProc;
     call setNeed();
     \* esdm_shm_status_install_signal_suspend()
in5: fresh := TRUE;
     handler := TRUE;
in6: ssusp[srvSeg] := FALSE;
     if (PublishLast) ver[srvSeg] := Ready;
     srvState := "up";
svUp: await restarts < Restarts;
     srvState := "exit";
     \* esdm_fini() joins the threads first
sx1: await (\A d \in DrngProcs : pc[d] = "dr1")
           /\ (\A w \in NeedW : pc[w] = "wn1");
     \* esdm_shm_status_exit_common(): the version withdrawn, then
     \* esdm_shm_status_set_suspend()
sx1a: if (ExitUnpublish) ver[srvSeg] := 0;
sx2: ssusp[srvSeg] := TRUE;
     owe["srv"] := owe["srv"] \cup {"R"};
     call up("R");
sx3: if (Aux # {}) call up("L");
     \* esdm_shm_status_delete_shm(), esdm_shm_status_delete_sem()
sx4: with (a = att[srvSeg] \ {"srv"}) {
         att[srvSeg] := a;
         alive[srvSeg] := alive[srvSeg] /\ ~(removed[srvSeg] /\ a = {});
     };
     srvSeg := 0;
     srvSem := [n \in Names |-> 0];
     if (KeepIpc) goto sx9;
     \* esdm_shm_status_cleanup_ipc(), by the server or its supervisor:
     \* IPC_STAT, IPC_RMID if nobody is attached, sem_unlink()
cl1: sid := keyAt;
     if (sid # 0 /\ att[sid] # {}) goto sx9;
cl2: if (sid # 0) rmid(sid);
cl3: semAt := [n \in Names |-> 0];
     \* the process ends, systemd starts it again
sx9: restarts := restarts + 1;
     srvState := "down";
     req := [n \in Names |-> 0];
     esdmOp := FALSE;
     handler := FALSE;
     sid := 0;
     goto cs1;
}

\* the thread holding the initial DRNG's lock: esdm_init_ops() and
\* esdm_unset_fully_seeded() change the state, then publish it
fair process (dr \in DrngProcs)
    variables opc = 0;
{
dr1: while (TRUE) {
         await opc < OpChanges /\ dlock = NoProc
               /\ (srvState = "up"
                   \/ (InitConcurrent /\ srvState = "init" /\ srvSeg # 0));
         dlock := self;
         esdmOp := ~esdmOp;
         opc := opc + 1;
dr2:     call setOp(OnOff(esdmOp));
dr3:     dlock := NoProc;
     }
}

\* threads changing the auxiliary pool under its lock, then calling
\* esdm_shm_status_set_need_entropy() without it
fair process (pw \in NeedW)
    variables nc = 0;
{
wn1: while (TRUE) {
         await nc < NeedChanges /\ srvState = "up";
         nc := nc + 1;
         needT := ~needT;
wn2:     call setNeed();
     }
}

\* esdm_shm_status_signal_suspend()
fair process (sg \in SigProcs)
    variables sc = 0;
{
sg1: while (sc < Suspends) {
         await srvState # "down" /\ (handler \/ EarlySignal);
         sc := sc + 1;
         if (~handler /\ IgnoreEarly) {
             \* ignored, install_term()
             skip;
         } else if (~handler) {
             \* SIGUSR1's default action ends the server
             viol := viol \cup {"SuspendKills"};
         } else if (srvSeg # 0) {
             \* with SemFix, an owner in its loop posts for the handler
             ssusp[srvSeg] := TRUE;
             sval := [o \in Sems |->
                         IF /\ \E n \in Names : /\ srvSem[n] = o
                                                /\ ~(SemFix /\ req[n] > 0)
                            /\ sval[o] = 0
                         THEN 1 ELSE sval[o]];
             req := [n \in Names |-> IF SemFix /\ req[n] > 0 THEN req[n] + 1
                                     ELSE req[n]];
         };
     }
}

\* the esdm-cuse-random daemon
fair process (ck = "ck")
    variables cseg = 0, cr = FALSE, susp = FALSE;
{
ck0: if (~Life) goto ck1;
     \* esdm_cuse_init_done(): esdm_cuse_shm_status_create_sem()
cu1: if (~Overlap) {
         await startLock = NoProc;
         startLock := "ck";
     };
     if (semAt["R"] = 0) {
         semOpen("R", cuseSem);
         goto cu3;
     };
cu2: semOpen("R", cuseSem);
     \* esdm_cuse_shm_status_create_shm(): shmget(), IPC_STAT
cu3: cseg := keyAt;
     cr := keyAt = 0;
cu4: if (cseg = 0 \/ att[cseg] # {} \/ CuseNoRmid) goto cu6;
     \* no attachment: stale, IPC_RMID
cu5: rmid(cseg);
     cseg := 0;
     cr := TRUE;
cu6: if (cseg = 0 /\ cr) shmgetCreate(cseg);
     \* shmat()
cu7: if (cseg = 0 \/ ~alive[cseg]) {
         \* the daemon exits, systemd starts it again
         cuseSem := 0;
         cseg := 0;
         cr := FALSE;
         if (~Overlap) startLock := NoProc;
         goto cu1;
     } else {
         att[cseg] := att[cseg] \cup {"ck"};
         cuseSeg := cseg;
         cuseState := "run";
         cseg := 0;
         cr := FALSE;
         if (~Overlap) startLock := NoProc;
     };
     \* esdm_cuse_poll_checker(): a pass under esdm_cuse_ph_lock
ck1: while (TRUE) {
         seen := Content(cuseSeg);
         susp := ssusp[cuseSeg];
         \* the one-shot trigger cleared after the pass
ck2:     if (susp) ssusp[cuseSeg] := FALSE;
         susp := FALSE;
         \* esdm_cuse_shm_status_down(): the version, then sem_wait(); with
         \* ExitUnpublish another pass every second while no server publishes
ck3:     if (ExitUnpublish /\ ver[cuseSeg] # Ready) {
             goto ck1;
         } else {
             await ver[cuseSeg] = Ready;
         };
ck4:     await sval[cuseSem] > 0;
         sval[cuseSem] := sval[cuseSem] - 1;
     }
}

\* esdm_aux_timedwait_for_need_entropy() in a loop, as esdm-tool does
fair process (ax \in AuxProcs)
{
ax1: while (TRUE) {
         await ver[1] = Ready;
         if (sneed[1]) {
             \* returns 0: the ESDM needs entropy
             skip;
         } else {
ax2:         either {
                 \* sem_clockwait() returns 0
                 await sval[2] > 0;
                 sval[2] := sval[2] - 1;
                 if (AuxRecheck)
                     owe[self] := owe[self] \cup {"L"};
                 else if (~sneed[1] /\ ~needT)
                     viol := viol \cup {"AuxSpurious"};
             } or {
                 \* the timeout
                 goto ax1;
             };
             \* AuxRecheck: returns 0 only with the flag set, passing the
             \* wakeup on (sem_getvalue(), sem_post()); waits on without
ax3:         if (AuxRecheck /\ sneed[1] /\ sval[2] = 0) {
                 goto ax4;
             } else {
                 owe[self] := owe[self] \ {"L"};
                 goto ax1;
             };
ax4:         sval[2] := sval[2] + 1;
             owe[self] := owe[self] \ {"L"};
         };
     }
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES keyAt, alive, removed, att, ver, sop, sneed, ssusp, nextSeg, semAt, 
          sval, nextSem, srvState, srvSeg, srvSem, esdmOp, needT, handler, 
          dlock, nlock, req, startLock, cuseState, cuseSeg, cuseSem, seen, 
          owe, fresh, viol, pc, stack

(* define statement *)
Content(s) == <<sop[s], sneed[s]>>
OnOff(b) == IF b THEN "on" ELSE "off"
Changed == cuseSeg # 0 /\ (Content(cuseSeg) # seen \/ ssusp[cuseSeg])

AliveAfterRm(s) == alive[s] /\ att[s] # {}

VARIABLES un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, restarts, opc, nc, 
          sc, cseg, cr, susp

vars == << keyAt, alive, removed, att, ver, sop, sneed, ssusp, nextSeg, semAt, 
           sval, nextSem, srvState, srvSeg, srvSem, esdmOp, needT, handler, 
           dlock, nlock, req, startLock, cuseState, cuseSeg, cuseSem, seen, 
           owe, fresh, viol, pc, stack, un, uo, rq, en, oseg, nseg, curr, nw, 
           cn, sid, restarts, opc, nc, sc, cseg, cr, susp >>

ProcSet == {"srv"} \cup (DrngProcs) \cup (NeedW) \cup (SigProcs) \cup {"ck"} \cup (AuxProcs)

Init == (* Global variables *)
        /\ keyAt = (IF InitSegs = {} THEN 0 ELSE 1)
        /\ alive = [s \in Segs |-> s \in InitSegs]
        /\ removed = [s \in Segs |-> FALSE]
        /\ att = [s \in Segs |-> IF s = 1 /\ ~Life THEN {"srv", "ck"} \cup AuxProcs
                                 ELSE {}]
        /\ ver = [s \in Segs |-> IF s \in InitSegs THEN Ready ELSE 0]
        /\ sop = [s \in Segs |-> s = 1 /\ Life /\ Leftover]
        /\ sneed = [s \in Segs |-> FALSE]
        /\ ssusp = [s \in Segs |-> FALSE]
        /\ nextSeg = (IF InitSegs = {} THEN 1 ELSE 2)
        /\ semAt = [n \in Names |-> IF InitSegs = {} THEN 0 ELSE SemId(n)]
        /\ sval = [o \in Sems |-> 0]
        /\ nextSem = (IF InitSegs = {} THEN 1 ELSE Cardinality(Names) + 1)
        /\ srvState = IF Life THEN "down" ELSE "up"
        /\ srvSeg = IF Life THEN 0 ELSE 1
        /\ srvSem = [n \in Names |-> IF Life THEN 0 ELSE SemId(n)]
        /\ esdmOp = FALSE
        /\ needT = FALSE
        /\ handler = ~Life
        /\ dlock = NoProc
        /\ nlock = NoProc
        /\ req = [n \in Names |-> 0]
        /\ startLock = NoProc
        /\ cuseState = IF Life THEN "off" ELSE "run"
        /\ cuseSeg = IF Life THEN 0 ELSE 1
        /\ cuseSem = IF Life THEN 0 ELSE 1
        /\ seen = <<FALSE, FALSE>>
        /\ owe = [p \in Procs |-> {}]
        /\ fresh = TRUE
        /\ viol = {}
        (* Procedure up *)
        /\ un = [ self \in ProcSet |-> defaultInitValue]
        /\ uo = [ self \in ProcSet |-> 0]
        /\ rq = [ self \in ProcSet |-> 0]
        (* Procedure setOp *)
        /\ en = [ self \in ProcSet |-> defaultInitValue]
        /\ oseg = [ self \in ProcSet |-> 0]
        (* Procedure setNeed *)
        /\ nseg = [ self \in ProcSet |-> 0]
        /\ curr = [ self \in ProcSet |-> FALSE]
        /\ nw = [ self \in ProcSet |-> FALSE]
        (* Procedure createSem *)
        /\ cn = [ self \in ProcSet |-> defaultInitValue]
        (* Process srv *)
        /\ sid = 0
        /\ restarts = 0
        (* Process dr *)
        /\ opc = [self \in DrngProcs |-> 0]
        (* Process pw *)
        /\ nc = [self \in NeedW |-> 0]
        (* Process sg *)
        /\ sc = [self \in SigProcs |-> 0]
        (* Process ck *)
        /\ cseg = 0
        /\ cr = FALSE
        /\ susp = FALSE
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self = "srv" -> "sv0"
                                        [] self \in DrngProcs -> "dr1"
                                        [] self \in NeedW -> "wn1"
                                        [] self \in SigProcs -> "sg1"
                                        [] self = "ck" -> "ck0"
                                        [] self \in AuxProcs -> "ax1"]

up0(self) == /\ pc[self] = "up0"
             /\ IF srvSem[un[self]] = 0
                   THEN /\ owe' = [owe EXCEPT ![self] = owe[self] \ {un[self]}]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ uo' = [uo EXCEPT ![self] = Head(stack[self]).uo]
                        /\ rq' = [rq EXCEPT ![self] = Head(stack[self]).rq]
                        /\ un' = [un EXCEPT ![self] = Head(stack[self]).un]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ req' = req
                   ELSE /\ IF SemFix /\ req[un[self]] > 0
                              THEN /\ req' = [req EXCEPT ![un[self]] = req[un[self]] + 1]
                                   /\ owe' = [owe EXCEPT ![self] = owe[self] \ {un[self]}]
                                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                   /\ uo' = [uo EXCEPT ![self] = Head(stack[self]).uo]
                                   /\ rq' = [rq EXCEPT ![self] = Head(stack[self]).rq]
                                   /\ un' = [un EXCEPT ![self] = Head(stack[self]).un]
                                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                              ELSE /\ IF SemFix
                                         THEN /\ req' = [req EXCEPT ![un[self]] = 1]
                                         ELSE /\ TRUE
                                              /\ req' = req
                                   /\ uo' = [uo EXCEPT ![self] = srvSem[un[self]]]
                                   /\ pc' = [pc EXCEPT ![self] = "up1"]
                                   /\ UNCHANGED << owe, stack, un, rq >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, startLock, cuseState, cuseSeg, cuseSem, 
                             seen, fresh, viol, en, oseg, nseg, curr, nw, cn, 
                             sid, restarts, opc, nc, sc, cseg, cr, susp >>

up1(self) == /\ pc[self] = "up1"
             /\ rq' = [rq EXCEPT ![self] = req[un[self]]]
             /\ IF sval[uo[self]] > 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "up3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "up2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                             en, oseg, nseg, curr, nw, cn, sid, restarts, opc, 
                             nc, sc, cseg, cr, susp >>

up2(self) == /\ pc[self] = "up2"
             /\ sval' = [sval EXCEPT ![uo[self]] = sval[uo[self]] + 1]
             /\ pc' = [pc EXCEPT ![self] = "up3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, handler, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, owe, 
                             fresh, viol, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, cn, sid, restarts, opc, nc, sc, cseg, 
                             cr, susp >>

up3(self) == /\ pc[self] = "up3"
             /\ IF SemFix /\ req[un[self]] # rq[self]
                   THEN /\ pc' = [pc EXCEPT ![self] = "up1"]
                        /\ UNCHANGED << req, owe, stack, un, uo, rq >>
                   ELSE /\ IF SemFix
                              THEN /\ req' = [req EXCEPT ![un[self]] = 0]
                              ELSE /\ TRUE
                                   /\ req' = req
                        /\ owe' = [owe EXCEPT ![self] = owe[self] \ {un[self]}]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ uo' = [uo EXCEPT ![self] = Head(stack[self]).uo]
                        /\ rq' = [rq EXCEPT ![self] = Head(stack[self]).rq]
                        /\ un' = [un EXCEPT ![self] = Head(stack[self]).un]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, startLock, cuseState, cuseSeg, cuseSem, 
                             seen, fresh, viol, en, oseg, nseg, curr, nw, cn, 
                             sid, restarts, opc, nc, sc, cseg, cr, susp >>

up(self) == up0(self) \/ up1(self) \/ up2(self) \/ up3(self)

op1(self) == /\ pc[self] = "op1"
             /\ IF srvSeg = 0 \/ sop[srvSeg] = (en[self] = "on")
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ oseg' = [oseg EXCEPT ![self] = Head(stack[self]).oseg]
                        /\ en' = [en EXCEPT ![self] = Head(stack[self]).en]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ oseg' = [oseg EXCEPT ![self] = srvSeg]
                        /\ pc' = [pc EXCEPT ![self] = "op2"]
                        /\ UNCHANGED << stack, en >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, un, uo, rq, nseg, 
                             curr, nw, cn, sid, restarts, opc, nc, sc, cseg, 
                             cr, susp >>

op2(self) == /\ pc[self] = "op2"
             /\ sop' = [sop EXCEPT ![oseg[self]] = en[self] = "on"]
             /\ owe' = [owe EXCEPT ![self] = owe[self] \cup {"R"}]
             /\ /\ oseg' = [oseg EXCEPT ![self] = Head(stack[self]).oseg]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                         pc        |->  Head(stack[self]).pc,
                                                         uo        |->  uo[self],
                                                         rq        |->  rq[self],
                                                         un        |->  un[self] ] >>
                                                     \o Tail(stack[self])]
                /\ un' = [un EXCEPT ![self] = "R"]
             /\ uo' = [uo EXCEPT ![self] = 0]
             /\ rq' = [rq EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "up0"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sneed, ssusp, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, handler, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, 
                             fresh, viol, en, nseg, curr, nw, cn, sid, 
                             restarts, opc, nc, sc, cseg, cr, susp >>

setOp(self) == op1(self) \/ op2(self)

ne0(self) == /\ pc[self] = "ne0"
             /\ IF NeedLocked
                   THEN /\ nlock = NoProc
                        /\ nlock' = self
                   ELSE /\ TRUE
                        /\ nlock' = nlock
             /\ pc' = [pc EXCEPT ![self] = "ne1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             req, startLock, cuseState, cuseSeg, cuseSem, seen, 
                             owe, fresh, viol, stack, un, uo, rq, en, oseg, 
                             nseg, curr, nw, cn, sid, restarts, opc, nc, sc, 
                             cseg, cr, susp >>

ne1(self) == /\ pc[self] = "ne1"
             /\ IF srvSeg = 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "ne5"]
                        /\ UNCHANGED << nseg, curr >>
                   ELSE /\ nseg' = [nseg EXCEPT ![self] = srvSeg]
                        /\ curr' = [curr EXCEPT ![self] = sneed[srvSeg]]
                        /\ pc' = [pc EXCEPT ![self] = "ne2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                             rq, en, oseg, nw, cn, sid, restarts, opc, nc, sc, 
                             cseg, cr, susp >>

ne2(self) == /\ pc[self] = "ne2"
             /\ nw' = [nw EXCEPT ![self] = needT]
             /\ IF needT /\ Aux # {}
                   THEN /\ owe' = [owe EXCEPT ![self] = owe[self] \cup {"L"}]
                   ELSE /\ TRUE
                        /\ owe' = owe
             /\ pc' = [pc EXCEPT ![self] = "ne3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, fresh, viol, stack, un, uo, rq, en, 
                             oseg, nseg, curr, cn, sid, restarts, opc, nc, sc, 
                             cseg, cr, susp >>

ne3(self) == /\ pc[self] = "ne3"
             /\ IF curr[self] # nw[self]
                   THEN /\ sneed' = [sneed EXCEPT ![nseg[self]] = nw[self]]
                        /\ owe' = [owe EXCEPT ![self] = owe[self] \cup {"R"}]
                        /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                                    pc        |->  "ne4",
                                                                    uo        |->  uo[self],
                                                                    rq        |->  rq[self],
                                                                    un        |->  un[self] ] >>
                                                                \o stack[self]]
                           /\ un' = [un EXCEPT ![self] = "R"]
                        /\ uo' = [uo EXCEPT ![self] = 0]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "up0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ne4"]
                        /\ UNCHANGED << sneed, owe, stack, un, uo, rq >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, ssusp, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, handler, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, 
                             fresh, viol, en, oseg, nseg, curr, nw, cn, sid, 
                             restarts, opc, nc, sc, cseg, cr, susp >>

ne4(self) == /\ pc[self] = "ne4"
             /\ IF nw[self] /\ Aux # {}
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                                    pc        |->  "ne5",
                                                                    uo        |->  uo[self],
                                                                    rq        |->  rq[self],
                                                                    un        |->  un[self] ] >>
                                                                \o stack[self]]
                           /\ un' = [un EXCEPT ![self] = "L"]
                        /\ uo' = [uo EXCEPT ![self] = 0]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "up0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ne5"]
                        /\ UNCHANGED << stack, un, uo, rq >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, en, oseg, nseg, 
                             curr, nw, cn, sid, restarts, opc, nc, sc, cseg, 
                             cr, susp >>

ne5(self) == /\ pc[self] = "ne5"
             /\ IF NeedLocked
                   THEN /\ nlock' = NoProc
                   ELSE /\ TRUE
                        /\ nlock' = nlock
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ nseg' = [nseg EXCEPT ![self] = Head(stack[self]).nseg]
             /\ curr' = [curr EXCEPT ![self] = Head(stack[self]).curr]
             /\ nw' = [nw EXCEPT ![self] = Head(stack[self]).nw]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             req, startLock, cuseState, cuseSeg, cuseSem, seen, 
                             owe, fresh, viol, un, uo, rq, en, oseg, cn, sid, 
                             restarts, opc, nc, sc, cseg, cr, susp >>

setNeed(self) == ne0(self) \/ ne1(self) \/ ne2(self) \/ ne3(self)
                    \/ ne4(self) \/ ne5(self)

cm1(self) == /\ pc[self] = "cm1"
             /\ IF semAt[cn[self]] = 0
                   THEN /\ IF semAt[cn[self]] = 0
                              THEN /\ Assert(nextSem <= MaxSem, 
                                             "Failure of assertion at line 152, column 9 of macro called at line 242, column 10.")
                                   /\ srvSem' = [srvSem EXCEPT ![cn[self]] = nextSem]
                                   /\ semAt' = [semAt EXCEPT ![cn[self]] = nextSem]
                                   /\ nextSem' = nextSem + 1
                              ELSE /\ srvSem' = [srvSem EXCEPT ![cn[self]] = semAt[cn[self]]]
                                   /\ UNCHANGED << semAt, nextSem >>
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ cn' = [cn EXCEPT ![self] = Head(stack[self]).cn]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cm2"]
                        /\ UNCHANGED << semAt, nextSem, srvSem, stack, cn >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, sval, srvState, srvSeg, esdmOp, 
                             needT, handler, dlock, nlock, req, startLock, 
                             cuseState, cuseSeg, cuseSem, seen, owe, fresh, 
                             viol, un, uo, rq, en, oseg, nseg, curr, nw, sid, 
                             restarts, opc, nc, sc, cseg, cr, susp >>

cm2(self) == /\ pc[self] = "cm2"
             /\ IF semAt[cn[self]] = 0
                   THEN /\ Assert(nextSem <= MaxSem, 
                                  "Failure of assertion at line 152, column 9 of macro called at line 246, column 6.")
                        /\ srvSem' = [srvSem EXCEPT ![cn[self]] = nextSem]
                        /\ semAt' = [semAt EXCEPT ![cn[self]] = nextSem]
                        /\ nextSem' = nextSem + 1
                   ELSE /\ srvSem' = [srvSem EXCEPT ![cn[self]] = semAt[cn[self]]]
                        /\ UNCHANGED << semAt, nextSem >>
             /\ pc' = [pc EXCEPT ![self] = "cm3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, sval, srvState, srvSeg, esdmOp, 
                             needT, handler, dlock, nlock, req, startLock, 
                             cuseState, cuseSeg, cuseSem, seen, owe, fresh, 
                             viol, stack, un, uo, rq, en, oseg, nseg, curr, nw, 
                             cn, sid, restarts, opc, nc, sc, cseg, cr, susp >>

cm3(self) == /\ pc[self] = "cm3"
             /\ IF SemFix
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                                    pc        |->  Head(stack[self]).pc,
                                                                    uo        |->  uo[self],
                                                                    rq        |->  rq[self],
                                                                    un        |->  un[self] ] >>
                                                                \o Tail(stack[self])]
                           /\ un' = [un EXCEPT ![self] = cn[self]]
                        /\ uo' = [uo EXCEPT ![self] = 0]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "up0"]
                        /\ UNCHANGED << sval, cn >>
                   ELSE /\ sval' = [sval EXCEPT ![srvSem[cn[self]]] = sval[srvSem[cn[self]]] + 1]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ cn' = [cn EXCEPT ![self] = Head(stack[self]).cn]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << un, uo, rq >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, handler, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, owe, 
                             fresh, viol, en, oseg, nseg, curr, nw, sid, 
                             restarts, opc, nc, sc, cseg, cr, susp >>

createSem(self) == cm1(self) \/ cm2(self) \/ cm3(self)

sv0 == /\ pc["srv"] = "sv0"
       /\ IF ~Life
             THEN /\ pc' = [pc EXCEPT !["srv"] = "svUp"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "cs1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

cs1 == /\ pc["srv"] = "cs1"
       /\ IF ~Overlap
             THEN /\ startLock = NoProc
                  /\ startLock' = "srv"
             ELSE /\ TRUE
                  /\ UNCHANGED startLock
       /\ srvState' = "init"
       /\ sid' = keyAt
       /\ pc' = [pc EXCEPT !["srv"] = "cs2"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvSeg, srvSem, esdmOp, 
                       needT, handler, dlock, nlock, req, cuseState, cuseSeg, 
                       cuseSem, seen, owe, fresh, viol, stack, un, uo, rq, en, 
                       oseg, nseg, curr, nw, cn, restarts, opc, nc, sc, cseg, 
                       cr, susp >>

cs2 == /\ pc["srv"] = "cs2"
       /\ IF sid = 0
             THEN /\ IF keyAt = 0
                        THEN /\ Assert(nextSeg <= MaxSeg, 
                                       "Failure of assertion at line 139, column 9 of macro called at line 267, column 19.")
                             /\ sid' = nextSeg
                             /\ keyAt' = nextSeg
                             /\ alive' = [alive EXCEPT ![nextSeg] = TRUE]
                             /\ nextSeg' = nextSeg + 1
                        ELSE /\ sid' = keyAt
                             /\ UNCHANGED << keyAt, alive, nextSeg >>
             ELSE /\ TRUE
                  /\ UNCHANGED << keyAt, alive, nextSeg, sid >>
       /\ pc' = [pc EXCEPT !["srv"] = "cs3"]
       /\ UNCHANGED << removed, att, ver, sop, sneed, ssusp, semAt, sval, 
                       nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, cn, restarts, opc, nc, sc, 
                       cseg, cr, susp >>

cs3 == /\ pc["srv"] = "cs3"
       /\ IF ~alive[sid]
             THEN /\ sid' = 0
                  /\ IF ~Overlap
                        THEN /\ startLock' = NoProc
                        ELSE /\ TRUE
                             /\ UNCHANGED startLock
                  /\ pc' = [pc EXCEPT !["srv"] = "cs1"]
                  /\ UNCHANGED << att, ver, srvSeg, fresh >>
             ELSE /\ att' = [att EXCEPT ![sid] = att[sid] \cup {"srv"}]
                  /\ srvSeg' = sid
                  /\ ver' = [ver EXCEPT ![sid] = 0]
                  /\ fresh' = FALSE
                  /\ sid' = 0
                  /\ IF ~Overlap
                        THEN /\ startLock' = NoProc
                        ELSE /\ TRUE
                             /\ UNCHANGED startLock
                  /\ pc' = [pc EXCEPT !["srv"] = "cs4"]
       /\ UNCHANGED << keyAt, alive, removed, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, cuseState, cuseSeg, cuseSem, 
                       seen, owe, viol, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, cn, restarts, opc, nc, sc, cseg, cr, susp >>

cs4 == /\ pc["srv"] = "cs4"
       /\ /\ cn' = [cn EXCEPT !["srv"] = "R"]
          /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "createSem",
                                                    pc        |->  "cs5",
                                                    cn        |->  cn["srv"] ] >>
                                                \o stack["srv"]]
       /\ pc' = [pc EXCEPT !["srv"] = "cm1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, un, 
                       uo, rq, en, oseg, nseg, curr, nw, sid, restarts, opc, 
                       nc, sc, cseg, cr, susp >>

cs5 == /\ pc["srv"] = "cs5"
       /\ IF Aux # {}
             THEN /\ /\ cn' = [cn EXCEPT !["srv"] = "L"]
                     /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "createSem",
                                                               pc        |->  "in1",
                                                               cn        |->  cn["srv"] ] >>
                                                           \o stack["srv"]]
                  /\ pc' = [pc EXCEPT !["srv"] = "cm1"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "in1"]
                  /\ UNCHANGED << stack, cn >>
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, un, 
                       uo, rq, en, oseg, nseg, curr, nw, sid, restarts, opc, 
                       nc, sc, cseg, cr, susp >>

in1 == /\ pc["srv"] = "in1"
       /\ IF ~PublishLast
             THEN /\ ver' = [ver EXCEPT ![srvSeg] = Ready]
             ELSE /\ TRUE
                  /\ ver' = ver
       /\ pc' = [pc EXCEPT !["srv"] = "in2"]
       /\ UNCHANGED << keyAt, alive, removed, att, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, cn, sid, restarts, opc, 
                       nc, sc, cseg, cr, susp >>

in2 == /\ pc["srv"] = "in2"
       /\ IF InitLocked
             THEN /\ dlock = NoProc
                  /\ dlock' = "srv"
             ELSE /\ TRUE
                  /\ dlock' = dlock
       /\ pc' = [pc EXCEPT !["srv"] = "in3"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

in3 == /\ pc["srv"] = "in3"
       /\ /\ en' = [en EXCEPT !["srv"] = OnOff(esdmOp)]
          /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "setOp",
                                                    pc        |->  "in4",
                                                    oseg      |->  oseg["srv"],
                                                    en        |->  en["srv"] ] >>
                                                \o stack["srv"]]
       /\ oseg' = [oseg EXCEPT !["srv"] = 0]
       /\ pc' = [pc EXCEPT !["srv"] = "op1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, un, 
                       uo, rq, nseg, curr, nw, cn, sid, restarts, opc, nc, sc, 
                       cseg, cr, susp >>

in4 == /\ pc["srv"] = "in4"
       /\ IF InitLocked
             THEN /\ dlock' = NoProc
             ELSE /\ TRUE
                  /\ dlock' = dlock
       /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "setNeed",
                                                 pc        |->  "in5",
                                                 nseg      |->  nseg["srv"],
                                                 curr      |->  curr["srv"],
                                                 nw        |->  nw["srv"] ] >>
                                             \o stack["srv"]]
       /\ nseg' = [nseg EXCEPT !["srv"] = 0]
       /\ curr' = [curr EXCEPT !["srv"] = FALSE]
       /\ nw' = [nw EXCEPT !["srv"] = FALSE]
       /\ pc' = [pc EXCEPT !["srv"] = "ne0"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, un, 
                       uo, rq, en, oseg, cn, sid, restarts, opc, nc, sc, cseg, 
                       cr, susp >>

in5 == /\ pc["srv"] = "in5"
       /\ fresh' = TRUE
       /\ handler' = TRUE
       /\ pc' = [pc EXCEPT !["srv"] = "in6"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, viol, stack, un, uo, rq, 
                       en, oseg, nseg, curr, nw, cn, sid, restarts, opc, nc, 
                       sc, cseg, cr, susp >>

in6 == /\ pc["srv"] = "in6"
       /\ ssusp' = [ssusp EXCEPT ![srvSeg] = FALSE]
       /\ IF PublishLast
             THEN /\ ver' = [ver EXCEPT ![srvSeg] = Ready]
             ELSE /\ TRUE
                  /\ ver' = ver
       /\ srvState' = "up"
       /\ pc' = [pc EXCEPT !["srv"] = "svUp"]
       /\ UNCHANGED << keyAt, alive, removed, att, sop, sneed, nextSeg, semAt, 
                       sval, nextSem, srvSeg, srvSem, esdmOp, needT, handler, 
                       dlock, nlock, req, startLock, cuseState, cuseSeg, 
                       cuseSem, seen, owe, fresh, viol, stack, un, uo, rq, en, 
                       oseg, nseg, curr, nw, cn, sid, restarts, opc, nc, sc, 
                       cseg, cr, susp >>

svUp == /\ pc["srv"] = "svUp"
        /\ restarts < Restarts
        /\ srvState' = "exit"
        /\ pc' = [pc EXCEPT !["srv"] = "sx1"]
        /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                        nextSeg, semAt, sval, nextSem, srvSeg, srvSem, esdmOp, 
                        needT, handler, dlock, nlock, req, startLock, 
                        cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                        stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                        restarts, opc, nc, sc, cseg, cr, susp >>

sx1 == /\ pc["srv"] = "sx1"
       /\ (\A d \in DrngProcs : pc[d] = "dr1")
          /\ (\A w \in NeedW : pc[w] = "wn1")
       /\ pc' = [pc EXCEPT !["srv"] = "sx1a"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

sx1a == /\ pc["srv"] = "sx1a"
        /\ IF ExitUnpublish
              THEN /\ ver' = [ver EXCEPT ![srvSeg] = 0]
              ELSE /\ TRUE
                   /\ ver' = ver
        /\ pc' = [pc EXCEPT !["srv"] = "sx2"]
        /\ UNCHANGED << keyAt, alive, removed, att, sop, sneed, ssusp, nextSeg, 
                        semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                        needT, handler, dlock, nlock, req, startLock, 
                        cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                        stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                        restarts, opc, nc, sc, cseg, cr, susp >>

sx2 == /\ pc["srv"] = "sx2"
       /\ ssusp' = [ssusp EXCEPT ![srvSeg] = TRUE]
       /\ owe' = [owe EXCEPT !["srv"] = owe["srv"] \cup {"R"}]
       /\ /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "up",
                                                    pc        |->  "sx3",
                                                    uo        |->  uo["srv"],
                                                    rq        |->  rq["srv"],
                                                    un        |->  un["srv"] ] >>
                                                \o stack["srv"]]
          /\ un' = [un EXCEPT !["srv"] = "R"]
       /\ uo' = [uo EXCEPT !["srv"] = 0]
       /\ rq' = [rq EXCEPT !["srv"] = 0]
       /\ pc' = [pc EXCEPT !["srv"] = "up0"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, fresh, viol, en, oseg, nseg, 
                       curr, nw, cn, sid, restarts, opc, nc, sc, cseg, cr, 
                       susp >>

sx3 == /\ pc["srv"] = "sx3"
       /\ IF Aux # {}
             THEN /\ /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "up",
                                                               pc        |->  "sx4",
                                                               uo        |->  uo["srv"],
                                                               rq        |->  rq["srv"],
                                                               un        |->  un["srv"] ] >>
                                                           \o stack["srv"]]
                     /\ un' = [un EXCEPT !["srv"] = "L"]
                  /\ uo' = [uo EXCEPT !["srv"] = 0]
                  /\ rq' = [rq EXCEPT !["srv"] = 0]
                  /\ pc' = [pc EXCEPT !["srv"] = "up0"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "sx4"]
                  /\ UNCHANGED << stack, un, uo, rq >>
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, en, 
                       oseg, nseg, curr, nw, cn, sid, restarts, opc, nc, sc, 
                       cseg, cr, susp >>

sx4 == /\ pc["srv"] = "sx4"
       /\ LET a == att[srvSeg] \ {"srv"} IN
            /\ att' = [att EXCEPT ![srvSeg] = a]
            /\ alive' = [alive EXCEPT ![srvSeg] = alive[srvSeg] /\ ~(removed[srvSeg] /\ a = {})]
       /\ srvSeg' = 0
       /\ srvSem' = [n \in Names |-> 0]
       /\ IF KeepIpc
             THEN /\ pc' = [pc EXCEPT !["srv"] = "sx9"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "cl1"]
       /\ UNCHANGED << keyAt, removed, ver, sop, sneed, ssusp, nextSeg, semAt, 
                       sval, nextSem, srvState, esdmOp, needT, handler, dlock, 
                       nlock, req, startLock, cuseState, cuseSeg, cuseSem, 
                       seen, owe, fresh, viol, stack, un, uo, rq, en, oseg, 
                       nseg, curr, nw, cn, sid, restarts, opc, nc, sc, cseg, 
                       cr, susp >>

cl1 == /\ pc["srv"] = "cl1"
       /\ sid' = keyAt
       /\ IF sid' # 0 /\ att[sid'] # {}
             THEN /\ pc' = [pc EXCEPT !["srv"] = "sx9"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "cl2"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

cl2 == /\ pc["srv"] = "cl2"
       /\ IF sid # 0
             THEN /\ alive' = [alive EXCEPT ![sid] = AliveAfterRm(sid)]
                  /\ removed' = [removed EXCEPT ![sid] = TRUE]
                  /\ IF keyAt = sid
                        THEN /\ keyAt' = 0
                        ELSE /\ TRUE
                             /\ keyAt' = keyAt
             ELSE /\ TRUE
                  /\ UNCHANGED << keyAt, alive, removed >>
       /\ pc' = [pc EXCEPT !["srv"] = "cl3"]
       /\ UNCHANGED << att, ver, sop, sneed, ssusp, nextSeg, semAt, sval, 
                       nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, cn, sid, restarts, opc, 
                       nc, sc, cseg, cr, susp >>

cl3 == /\ pc["srv"] = "cl3"
       /\ semAt' = [n \in Names |-> 0]
       /\ pc' = [pc EXCEPT !["srv"] = "sx9"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

sx9 == /\ pc["srv"] = "sx9"
       /\ restarts' = restarts + 1
       /\ srvState' = "down"
       /\ req' = [n \in Names |-> 0]
       /\ esdmOp' = FALSE
       /\ handler' = FALSE
       /\ sid' = 0
       /\ pc' = [pc EXCEPT !["srv"] = "cs1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvSeg, srvSem, needT, 
                       dlock, nlock, startLock, cuseState, cuseSeg, cuseSem, 
                       seen, owe, fresh, viol, stack, un, uo, rq, en, oseg, 
                       nseg, curr, nw, cn, opc, nc, sc, cseg, cr, susp >>

srv == sv0 \/ cs1 \/ cs2 \/ cs3 \/ cs4 \/ cs5 \/ in1 \/ in2 \/ in3 \/ in4
          \/ in5 \/ in6 \/ svUp \/ sx1 \/ sx1a \/ sx2 \/ sx3 \/ sx4 \/ cl1
          \/ cl2 \/ cl3 \/ sx9

dr1(self) == /\ pc[self] = "dr1"
             /\ opc[self] < OpChanges /\ dlock = NoProc
                /\ (srvState = "up"
                    \/ (InitConcurrent /\ srvState = "init" /\ srvSeg # 0))
             /\ dlock' = self
             /\ esdmOp' = ~esdmOp
             /\ opc' = [opc EXCEPT ![self] = opc[self] + 1]
             /\ pc' = [pc EXCEPT ![self] = "dr2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, needT, handler, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, owe, 
                             fresh, viol, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, cn, sid, restarts, nc, sc, cseg, cr, 
                             susp >>

dr2(self) == /\ pc[self] = "dr2"
             /\ /\ en' = [en EXCEPT ![self] = OnOff(esdmOp)]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "setOp",
                                                         pc        |->  "dr3",
                                                         oseg      |->  oseg[self],
                                                         en        |->  en[self] ] >>
                                                     \o stack[self]]
             /\ oseg' = [oseg EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "op1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, un, uo, rq, nseg, 
                             curr, nw, cn, sid, restarts, opc, nc, sc, cseg, 
                             cr, susp >>

dr3(self) == /\ pc[self] = "dr3"
             /\ dlock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "dr1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, nlock, 
                             req, startLock, cuseState, cuseSeg, cuseSem, seen, 
                             owe, fresh, viol, stack, un, uo, rq, en, oseg, 
                             nseg, curr, nw, cn, sid, restarts, opc, nc, sc, 
                             cseg, cr, susp >>

dr(self) == dr1(self) \/ dr2(self) \/ dr3(self)

wn1(self) == /\ pc[self] = "wn1"
             /\ nc[self] < NeedChanges /\ srvState = "up"
             /\ nc' = [nc EXCEPT ![self] = nc[self] + 1]
             /\ needT' = ~needT
             /\ pc' = [pc EXCEPT ![self] = "wn2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, handler, dlock, nlock, 
                             req, startLock, cuseState, cuseSeg, cuseSem, seen, 
                             owe, fresh, viol, stack, un, uo, rq, en, oseg, 
                             nseg, curr, nw, cn, sid, restarts, opc, sc, cseg, 
                             cr, susp >>

wn2(self) == /\ pc[self] = "wn2"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "setNeed",
                                                      pc        |->  "wn1",
                                                      nseg      |->  nseg[self],
                                                      curr      |->  curr[self],
                                                      nw        |->  nw[self] ] >>
                                                  \o stack[self]]
             /\ nseg' = [nseg EXCEPT ![self] = 0]
             /\ curr' = [curr EXCEPT ![self] = FALSE]
             /\ nw' = [nw EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "ne0"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, un, uo, rq, en, 
                             oseg, cn, sid, restarts, opc, nc, sc, cseg, cr, 
                             susp >>

pw(self) == wn1(self) \/ wn2(self)

sg1(self) == /\ pc[self] = "sg1"
             /\ IF sc[self] < Suspends
                   THEN /\ srvState # "down" /\ (handler \/ EarlySignal)
                        /\ sc' = [sc EXCEPT ![self] = sc[self] + 1]
                        /\ IF ~handler /\ IgnoreEarly
                              THEN /\ TRUE
                                   /\ UNCHANGED << ssusp, sval, req, viol >>
                              ELSE /\ IF ~handler
                                         THEN /\ viol' = (viol \cup {"SuspendKills"})
                                              /\ UNCHANGED << ssusp, sval, req >>
                                         ELSE /\ IF srvSeg # 0
                                                    THEN /\ ssusp' = [ssusp EXCEPT ![srvSeg] = TRUE]
                                                         /\ sval' = [o \in Sems |->
                                                                        IF /\ \E n \in Names : /\ srvSem[n] = o
                                                                                               /\ ~(SemFix /\ req[n] > 0)
                                                                           /\ sval[o] = 0
                                                                        THEN 1 ELSE sval[o]]
                                                         /\ req' = [n \in Names |-> IF SemFix /\ req[n] > 0 THEN req[n] + 1
                                                                                    ELSE req[n]]
                                                    ELSE /\ TRUE
                                                         /\ UNCHANGED << ssusp, 
                                                                         sval, 
                                                                         req >>
                                              /\ viol' = viol
                        /\ pc' = [pc EXCEPT ![self] = "sg1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << ssusp, sval, req, viol, sc >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             nextSeg, semAt, nextSem, srvState, srvSeg, srvSem, 
                             esdmOp, needT, handler, dlock, nlock, startLock, 
                             cuseState, cuseSeg, cuseSem, seen, owe, fresh, 
                             stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, 
                             sid, restarts, opc, nc, cseg, cr, susp >>

sg(self) == sg1(self)

ck0 == /\ pc["ck"] = "ck0"
       /\ IF ~Life
             THEN /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
             ELSE /\ pc' = [pc EXCEPT !["ck"] = "cu1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

cu1 == /\ pc["ck"] = "cu1"
       /\ IF ~Overlap
             THEN /\ startLock = NoProc
                  /\ startLock' = "ck"
             ELSE /\ TRUE
                  /\ UNCHANGED startLock
       /\ IF semAt["R"] = 0
             THEN /\ IF semAt["R"] = 0
                        THEN /\ Assert(nextSem <= MaxSem, 
                                       "Failure of assertion at line 152, column 9 of macro called at line 404, column 10.")
                             /\ cuseSem' = nextSem
                             /\ semAt' = [semAt EXCEPT !["R"] = nextSem]
                             /\ nextSem' = nextSem + 1
                        ELSE /\ cuseSem' = semAt["R"]
                             /\ UNCHANGED << semAt, nextSem >>
                  /\ pc' = [pc EXCEPT !["ck"] = "cu3"]
             ELSE /\ pc' = [pc EXCEPT !["ck"] = "cu2"]
                  /\ UNCHANGED << semAt, nextSem, cuseSem >>
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, sval, srvState, srvSeg, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, cuseState, cuseSeg, seen, 
                       owe, fresh, viol, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, cn, sid, restarts, opc, nc, sc, cseg, cr, 
                       susp >>

cu2 == /\ pc["ck"] = "cu2"
       /\ IF semAt["R"] = 0
             THEN /\ Assert(nextSem <= MaxSem, 
                            "Failure of assertion at line 152, column 9 of macro called at line 407, column 6.")
                  /\ cuseSem' = nextSem
                  /\ semAt' = [semAt EXCEPT !["R"] = nextSem]
                  /\ nextSem' = nextSem + 1
             ELSE /\ cuseSem' = semAt["R"]
                  /\ UNCHANGED << semAt, nextSem >>
       /\ pc' = [pc EXCEPT !["ck"] = "cu3"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, sval, srvState, srvSeg, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, seen, owe, fresh, viol, stack, un, uo, rq, en, 
                       oseg, nseg, curr, nw, cn, sid, restarts, opc, nc, sc, 
                       cseg, cr, susp >>

cu3 == /\ pc["ck"] = "cu3"
       /\ cseg' = keyAt
       /\ cr' = (keyAt = 0)
       /\ pc' = [pc EXCEPT !["ck"] = "cu4"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, susp >>

cu4 == /\ pc["ck"] = "cu4"
       /\ IF cseg = 0 \/ att[cseg] # {} \/ CuseNoRmid
             THEN /\ pc' = [pc EXCEPT !["ck"] = "cu6"]
             ELSE /\ pc' = [pc EXCEPT !["ck"] = "cu5"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

cu5 == /\ pc["ck"] = "cu5"
       /\ alive' = [alive EXCEPT ![cseg] = AliveAfterRm(cseg)]
       /\ removed' = [removed EXCEPT ![cseg] = TRUE]
       /\ IF keyAt = cseg
             THEN /\ keyAt' = 0
             ELSE /\ TRUE
                  /\ keyAt' = keyAt
       /\ cseg' = 0
       /\ cr' = TRUE
       /\ pc' = [pc EXCEPT !["ck"] = "cu6"]
       /\ UNCHANGED << att, ver, sop, sneed, ssusp, nextSeg, semAt, sval, 
                       nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, cn, sid, restarts, opc, 
                       nc, sc, susp >>

cu6 == /\ pc["ck"] = "cu6"
       /\ IF cseg = 0 /\ cr
             THEN /\ IF keyAt = 0
                        THEN /\ Assert(nextSeg <= MaxSeg, 
                                       "Failure of assertion at line 139, column 9 of macro called at line 416, column 26.")
                             /\ cseg' = nextSeg
                             /\ keyAt' = nextSeg
                             /\ alive' = [alive EXCEPT ![nextSeg] = TRUE]
                             /\ nextSeg' = nextSeg + 1
                        ELSE /\ cseg' = keyAt
                             /\ UNCHANGED << keyAt, alive, nextSeg >>
             ELSE /\ TRUE
                  /\ UNCHANGED << keyAt, alive, nextSeg, cseg >>
       /\ pc' = [pc EXCEPT !["ck"] = "cu7"]
       /\ UNCHANGED << removed, att, ver, sop, sneed, ssusp, semAt, sval, 
                       nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                       handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, cn, sid, restarts, opc, 
                       nc, sc, cr, susp >>

cu7 == /\ pc["ck"] = "cu7"
       /\ IF cseg = 0 \/ ~alive[cseg]
             THEN /\ cuseSem' = 0
                  /\ cseg' = 0
                  /\ cr' = FALSE
                  /\ IF ~Overlap
                        THEN /\ startLock' = NoProc
                        ELSE /\ TRUE
                             /\ UNCHANGED startLock
                  /\ pc' = [pc EXCEPT !["ck"] = "cu1"]
                  /\ UNCHANGED << att, cuseState, cuseSeg >>
             ELSE /\ att' = [att EXCEPT ![cseg] = att[cseg] \cup {"ck"}]
                  /\ cuseSeg' = cseg
                  /\ cuseState' = "run"
                  /\ cseg' = 0
                  /\ cr' = FALSE
                  /\ IF ~Overlap
                        THEN /\ startLock' = NoProc
                        ELSE /\ TRUE
                             /\ UNCHANGED startLock
                  /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
                  /\ UNCHANGED cuseSem
       /\ UNCHANGED << keyAt, alive, removed, ver, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, handler, dlock, nlock, req, seen, owe, fresh, 
                       viol, stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, 
                       sid, restarts, opc, nc, sc, susp >>

ck1 == /\ pc["ck"] = "ck1"
       /\ seen' = Content(cuseSeg)
       /\ susp' = ssusp[cuseSeg]
       /\ pc' = [pc EXCEPT !["ck"] = "ck2"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, owe, fresh, viol, stack, 
                       un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, restarts, 
                       opc, nc, sc, cseg, cr >>

ck2 == /\ pc["ck"] = "ck2"
       /\ IF susp
             THEN /\ ssusp' = [ssusp EXCEPT ![cuseSeg] = FALSE]
             ELSE /\ TRUE
                  /\ ssusp' = ssusp
       /\ susp' = FALSE
       /\ pc' = [pc EXCEPT !["ck"] = "ck3"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, handler, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, cn, sid, restarts, opc, 
                       nc, sc, cseg, cr >>

ck3 == /\ pc["ck"] = "ck3"
       /\ IF ExitUnpublish /\ ver[cuseSeg] # Ready
             THEN /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
             ELSE /\ ver[cuseSeg] = Ready
                  /\ pc' = [pc EXCEPT !["ck"] = "ck4"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

ck4 == /\ pc["ck"] = "ck4"
       /\ sval[cuseSem] > 0
       /\ sval' = [sval EXCEPT ![cuseSem] = sval[cuseSem] - 1]
       /\ pc' = [pc EXCEPT !["ck"] = "ck1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, handler, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seen, owe, fresh, viol, 
                       stack, un, uo, rq, en, oseg, nseg, curr, nw, cn, sid, 
                       restarts, opc, nc, sc, cseg, cr, susp >>

ck == ck0 \/ cu1 \/ cu2 \/ cu3 \/ cu4 \/ cu5 \/ cu6 \/ cu7 \/ ck1 \/ ck2
         \/ ck3 \/ ck4

ax1(self) == /\ pc[self] = "ax1"
             /\ ver[1] = Ready
             /\ IF sneed[1]
                   THEN /\ TRUE
                        /\ pc' = [pc EXCEPT ![self] = "ax1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ax2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, owe, fresh, viol, stack, un, uo, 
                             rq, en, oseg, nseg, curr, nw, cn, sid, restarts, 
                             opc, nc, sc, cseg, cr, susp >>

ax2(self) == /\ pc[self] = "ax2"
             /\ \/ /\ sval[2] > 0
                   /\ sval' = [sval EXCEPT ![2] = sval[2] - 1]
                   /\ IF AuxRecheck
                         THEN /\ owe' = [owe EXCEPT ![self] = owe[self] \cup {"L"}]
                              /\ viol' = viol
                         ELSE /\ IF ~sneed[1] /\ ~needT
                                    THEN /\ viol' = (viol \cup {"AuxSpurious"})
                                    ELSE /\ TRUE
                                         /\ viol' = viol
                              /\ owe' = owe
                   /\ pc' = [pc EXCEPT ![self] = "ax3"]
                \/ /\ pc' = [pc EXCEPT ![self] = "ax1"]
                   /\ UNCHANGED <<sval, owe, viol>>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, handler, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, 
                             fresh, stack, un, uo, rq, en, oseg, nseg, curr, 
                             nw, cn, sid, restarts, opc, nc, sc, cseg, cr, 
                             susp >>

ax3(self) == /\ pc[self] = "ax3"
             /\ IF AuxRecheck /\ sneed[1] /\ sval[2] = 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "ax4"]
                        /\ owe' = owe
                   ELSE /\ owe' = [owe EXCEPT ![self] = owe[self] \ {"L"}]
                        /\ pc' = [pc EXCEPT ![self] = "ax1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, handler, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seen, fresh, viol, stack, un, uo, rq, en, 
                             oseg, nseg, curr, nw, cn, sid, restarts, opc, nc, 
                             sc, cseg, cr, susp >>

ax4(self) == /\ pc[self] = "ax4"
             /\ sval' = [sval EXCEPT ![2] = sval[2] + 1]
             /\ owe' = [owe EXCEPT ![self] = owe[self] \ {"L"}]
             /\ pc' = [pc EXCEPT ![self] = "ax1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, handler, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seen, 
                             fresh, viol, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, cn, sid, restarts, opc, nc, sc, cseg, 
                             cr, susp >>

ax(self) == ax1(self) \/ ax2(self) \/ ax3(self) \/ ax4(self)

Next == srv \/ ck
           \/ (\E self \in ProcSet:  \/ up(self) \/ setOp(self) \/ setNeed(self)
                                     \/ createSem(self))
           \/ (\E self \in DrngProcs: dr(self))
           \/ (\E self \in NeedW: pw(self))
           \/ (\E self \in SigProcs: sg(self))
           \/ (\E self \in AuxProcs: ax(self))

Spec == /\ Init /\ [][Next]_vars
        /\ /\ WF_vars(srv)
           /\ WF_vars(createSem("srv"))
           /\ WF_vars(setOp("srv"))
           /\ WF_vars(setNeed("srv"))
           /\ WF_vars(up("srv"))
        /\ \A self \in DrngProcs : WF_vars(dr(self)) /\ WF_vars(setOp(self)) /\ WF_vars(up(self))
        /\ \A self \in NeedW : WF_vars(pw(self)) /\ WF_vars(setNeed(self)) /\ WF_vars(up(self))
        /\ \A self \in SigProcs : WF_vars(sg(self))
        /\ WF_vars(ck)
        /\ \A self \in AuxProcs : WF_vars(ax(self))

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ keyAt \in 0..MaxSeg
    /\ srvSeg \in 0..MaxSeg
    /\ cuseSeg \in 0..MaxSeg
    /\ sval \in [Sems -> Nat]

\* The semaphores toggle between 0 and 1, as _esdm_shm_status_up() means
\* them to.
SemBinary == \A o \in Sems : sval[o] <= 1

\* Once the threads publishing a state are idle, the segment shows it.
OpFresh ==
    (srvState = "up" /\ \A d \in DrngProcs : pc[d] = "dr1")
        => sop[srvSeg] = esdmOp
NeedFresh ==
    (srvState = "up" /\ \A w \in NeedW : pc[w] = "wn1")
        => sneed[srvSeg] = needT

\* A segment showing the ready version shows this server's state: "publish
\* the version last" (esdm_shm_status_init()).
StatusFresh ==
    (srvSeg # 0 /\ ver[srvSeg] = Ready /\ ~fresh)
        => Content(srvSeg) = <<esdmOp, needT>>

\* The poll checker waits on its semaphore only if it saw the status, or a
\* writer has stored a change and still has to post.
NoLostWakeup ==
    (cuseState = "run" /\ pc["ck"] = "ck4" /\ sval[cuseSem] = 0 /\ Changed)
        => (\E p \in Procs : "R" \in owe[p]) \/ req["R"] > 0

\* The CUSE daemon and a running server use the same segment and semaphore.
Connected ==
    (srvState = "up" /\ cuseState = "run")
        => cuseSeg = srvSeg /\ cuseSem = srvSem["R"]

\* An aux client sleeps on the level semaphore only while the ESDM does not
\* need entropy, or a writer still has to post it.
AuxNoLostWakeup ==
    \A a \in AuxProcs :
        (pc[a] = "ax2" /\ sval[2] = 0 /\ sneed[1])
            => \E p \in Procs : "L" \in owe[p]

\* An aux client is told to deliver entropy only while the ESDM needs it.
AuxSpurious == "AuxSpurious" \notin viol

\* A suspend signal does not end the server.
SuspendKills == "SuspendKills" \notin viol

-----------------------------------------------------------------------------
(* Liveness *)

\* Once the server and its threads are done changing the status, the
\* CUSE daemon's checker sees it.
Synced ==
    /\ srvState = "up"
    /\ cuseState = "run"
    /\ cuseSeg = srvSeg
    /\ seen = Content(srvSeg)
EventuallySynced == <>[]Synced
=============================================================================
