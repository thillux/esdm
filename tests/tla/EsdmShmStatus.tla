---------------------------- MODULE EsdmShmStatus ----------------------------
(***************************************************************************)
(* The status the esdm-server publishes in shared memory for other         *)
(* processes: esdm/esdm_shm_status.c on the server side, its readers in    *)
(* frontends/cuse/cuse_device.c (the poll checker of a CUSE daemon) and    *)
(* frontends/aux-client/esdm_aux_need_entropy.c. One System V segment      *)
(* under a well-known ftok() key holds version, operational, need_entropy  *)
(* and suspend_gen; POSIX named semaphores, one per CUSE daemon and the    *)
(* level-triggered need_entropy one, tell the readers to look again.       *)
(* One step is one atomic variable access or one system call; the labels   *)
(* name the C functions they come from.                                    *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - Cuse names the CUSE daemons by their semaphores: "R" is               *)
(*   esdm-cuse-random, "U" esdm-cuse-urandom. They share the segment.      *)
(*   Segments and semaphores have identities: IPC_RMID takes a segment off *)
(*   the key, it lives on while attached; sem_unlink() takes a semaphore   *)
(*   off its name, holders keep it. Every process has the same uid, the    *)
(*   ownership checks are left out, and so are the info/infolen/           *)
(*   unpriv_threads fields.                                                *)
(* - The server's threads: the one holding the initial DRNG's lock         *)
(*   (esdm_init_ops(), esdm_unset_fully_seeded()) flips the operational    *)
(*   state and publishes it; threads changing the auxiliary pool flip      *)
(*   esdm_need_entropy() and call esdm_shm_status_set_need_entropy(); the  *)
(*   thread serving RpcSetWriteWakeupThresh moves the threshold, the other *)
(*   side of esdm_need_entropy() (esdm_set_write_wakeup_bits()). The       *)
(*   suspend notification comes two ways. The SIGUSR1 handler is one       *)
(*   atomic step: that is exact for the thread it interrupts and leaves    *)
(*   out the steps of the other threads during the handler. The thread of  *)
(*   esdm_es_events.c (suspend and shutdown events of the kernel module)   *)
(*   calls esdm_shm_status_suspend() with its store and each of its posts  *)
(*   as separate steps; as nothing in it blocks, it also covers a handler  *)
(*   the other threads run alongside. All threads are quiescent while      *)
(*   esdm_shm_status_init() runs (the server starts no thread before) and  *)
(*   are joined before the exit.                                           *)
(* - A server restart is a new process: the ESDM is not operational,       *)
(*   SIGUSR1 has its default action until main() ignores it, and           *)
(*   esdm-server-signal-helper signals the process the PID file names. The *)
(*   segment and semaphores stay (--keep_ipc) or                           *)
(*   esdm_shm_status_cleanup_ipc removes them. A failed shmat() makes the  *)
(*   server exit and start again.                                          *)
(* - The CUSE daemon's poll checker reads the status in each pass as       *)
(*   esdm_cuse_get_pollmask() does, as if a poller were always registered, *)
(*   one field per step (EsdmCuse.tla models the list). The poller of a    *)
(*   pass waits since the end of the pass that woke the one before: pend   *)
(*   holds a suspend notification it is owed. The checker's wait for the   *)
(*   version is another pass (ExitUnpublish) or an await.                  *)
(* - An aux client makes AuxCalls calls of                                 *)
(*   esdm_aux_timedwait_for_need_entropy(); with AuxTimeout its timeout    *)
(*   may expire at any time.                                               *)
(* - Every environment process is bounded. The only state without a        *)
(*   successor that is no deadlock is Quiescent: the server is up, every   *)
(*   budget is used, every checker waits having seen the status, every aux *)
(*   client is done or waits without a need. The process fin stutters      *)
(*   there, so that TLC's deadlock check reports every other such state.   *)
(* - Not modelled: the uid eviction, the EINVAL resize path, shutdown of   *)
(*   the readers, esdm_reinit() but for InitConcurrent.                    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Life,           \* server lifecycle: it starts, exits and restarts
    Leftover,       \* segment and semaphores of an earlier server that was
                    \* operational, needed entropy and died
    Restarts,       \* server restarts
    KeepIpc,        \* --keep_ipc (the stock unit): no IPC cleanup at the exit
    Overlap,        \* a CUSE daemon's start overlaps the server's
    Cuse,           \* the CUSE daemons: {"R"} or {"R", "U"}
    NeedW,          \* threads changing the auxiliary pool
    NeedChanges,    \* changes per such thread
    OpChanges,      \* operational state changes
    ThreshChanges,  \* changes of the write wakeup threshold that flip the need
    Suspends,       \* SIGUSR1 suspend signals
    ThreadSuspends, \* suspend notifications from the thread of esdm_es_events
    EarlySignal,    \* a signal may come before the handler is installed
    Aux,            \* aux clients waiting for need entropy
    AuxCalls,       \* calls per aux client
    AuxTimeout,     \* the calls of the aux clients may time out
    InitConcurrent, \* the DRNG thread runs during esdm_shm_status_init(), as
                    \* in esdm_reinit() (library API, not called by the server)
    PublishLast,    \* fix: version published after operational, need_entropy
    PostPublish,    \* fix: the CUSE semaphores posted after the version
    NeedLocked,     \* fix: esdm_shm_status_set_need_entropy() serialized
    InitLocked,     \* fix: the initial DRNG's lock around the init's snapshot
    CuseNoRmid,     \* fix: the CUSE daemon never removes a segment
    SemFix,         \* fix: combined posts, re-synchronizing post only on 0
    AuxRecheck,     \* fix: an aux client checks the flag after waking and
                    \* passes the wakeup on while the need lasts
    IgnoreEarly,    \* fix: SIGUSR1 ignored until the handler is installed
    ExitUnpublish,  \* fix: the exit withdraws the version; the CUSE checker
                    \* passes every second while no server publishes
    SuspendGen,     \* fix: a suspend generation only the server writes; else
                    \* the one-shot trigger the checkers and the init clear
    ThreshPublish,  \* fix: a threshold change publishes the need
    MaxSeg,         \* segment identities
    MaxSem          \* semaphore identities

ASSUME "R" \in Cuse /\ Cuse \subseteq {"R", "U"}

Ready == 3                      \* ESDM_SHM_STATUS_VERSION
NoProc == "none"
Names == Cuse \cup (IF Aux = {} THEN {} ELSE {"L"})
SemId(n) == CASE n = "R" -> 1 [] n = "U" -> 2 [] n = "L" -> Cardinality(Cuse) + 1
LSem == SemId("L")
Segs == 1..MaxSeg
Sems == 1..MaxSem
DrngProcs == IF OpChanges > 0 THEN {"drng"} ELSE {}
ThreshProcs == IF ThreshChanges > 0 THEN {"thr"} ELSE {}
SigProcs == IF Suspends > 0 THEN {"sig"} ELSE {}
EvProcs == IF ThreadSuspends > 0 THEN {"ev"} ELSE {}
AuxProcs == Aux
Procs == {"srv"} \cup Cuse \cup DrngProcs \cup NeedW \cup ThreshProcs
         \cup SigProcs \cup EvProcs \cup AuxProcs
InitSegs == IF Life /\ ~Leftover THEN {} ELSE {1}

(* --algorithm EsdmShmStatus {
variables
    \* System V segments: the one the ftok() key names (0: none), the live
    \* ones, those taken off the key, attachments and contents; ssusp is
    \* suspend_gen, or 0 and 1 for the one-shot trigger (~SuspendGen)
    keyAt = IF InitSegs = {} THEN 0 ELSE 1,
    alive = [s \in Segs |-> s \in InitSegs],
    removed = [s \in Segs |-> FALSE],
    att = [s \in Segs |-> IF s = 1 /\ ~Life THEN {"srv"} \cup Cuse \cup AuxProcs
                          ELSE {}],
    ver = [s \in Segs |-> IF s \in InitSegs THEN Ready ELSE 0],
    sop = [s \in Segs |-> s = 1 /\ Life /\ Leftover],
    sneed = [s \in Segs |-> s = 1 /\ Life /\ Leftover],
    ssusp = [s \in Segs |-> 0],
    nextSeg = IF InitSegs = {} THEN 1 ELSE 2,
    \* POSIX semaphores: the one each name names (0: none) and the values
    semAt = [n \in Names |-> IF InitSegs = {} THEN 0 ELSE SemId(n)],
    sval = [o \in Sems |-> 0],
    nextSem = IF InitSegs = {} THEN 1 ELSE Cardinality(Names) + 1,
    \* the server: esdm_shm_status, esdm_semid_*, the ESDM state, the
    \* disposition of SIGUSR1 and whether the PID file names the process
    srvState = IF Life THEN "down" ELSE "up",
    srvSeg = IF Life THEN 0 ELSE 1,
    srvSem = [n \in Names |-> IF Life THEN 0 ELSE SemId(n)],
    esdmOp = FALSE,         \* esdm_state.esdm_operational
    needT = FALSE,          \* esdm_need_entropy()
    sigDisp = IF Life THEN "default" ELSE "handler",
    pidfile = ~Life,
    dlock = NoProc,         \* the initial DRNG's lock
    nlock = NoProc,         \* fix NeedLocked
    req = [n \in Names |-> 0], \* fix SemFix: requests of the combined posts
    startLock = NoProc,     \* systemd orders the starts (~Overlap)
    \* the CUSE daemons (esdm_cuse_shm_status, esdm_cuse_semid,
    \* esdm_cuse_suspend_seen) and the aux clients, attached from the start
    \* without Life
    cuseState = [d \in Cuse |-> IF Life THEN "off" ELSE "run"],
    cuseSeg = [d \in Cuse |-> IF Life THEN 0 ELSE 1],
    cuseSem = [d \in Cuse |-> IF Life THEN 0 ELSE SemId(d)],
    seenGen = [d \in Cuse |-> 0],
    \* the budgets of the environment
    restarts = 0,
    opc = 0,
    nc = [w \in NeedW |-> 0],
    tc = 0,
    sc = 0,
    ec = 0,
    calls = [a \in AuxProcs |-> 0],
    \* ghosts: what a checker last read (version ready, operational,
    \* need_entropy), the suspend notification its poller is owed, the posts
    \* a writer owes after its store, whether the need was published during
    \* an aux client's call, a server ended by SIGUSR1, the semaphore names
    \* and who removed what
    seen = [d \in Cuse |-> <<FALSE, FALSE, FALSE>>],
    pend = [d \in Cuse |-> FALSE],
    owe = [p \in Procs |-> {}],
    needSeen = [a \in AuxProcs |-> FALSE],
    killed = FALSE,
    nameOf = [o \in Sems |-> IF InitSegs # {} /\ (\E n \in Names : SemId(n) = o)
                             THEN CHOOSE n \in Names : SemId(n) = o
                             ELSE "none"],
    rmBy = [s \in Segs |-> "none"],
    semRm = "none";

define {
    Content(s) == <<sop[s], sneed[s]>>
    \* what the poll mask of a CUSE daemon follows: without the ready
    \* version the kernel's device, whatever the other fields say
    View(s) == IF ver[s] = Ready THEN <<TRUE, sop[s], sneed[s]>>
               ELSE <<FALSE, FALSE, FALSE>>
    OnOff(b) == IF b THEN "on" ELSE "off"
    \* the segment after IPC_RMID: gone if nobody is attached
    AliveAfterRm(s) == alive[s] /\ att[s] # {}
    \* esdm_cuse_suspend_pending(), or the one-shot trigger
    SuspVisible(d) == IF SuspendGen THEN ssusp[cuseSeg[d]] # seenGen[d]
                      ELSE ssusp[cuseSeg[d]] = 1
    \* a daemon whose checker waits having seen everything
    CuseIdle(d) ==
        /\ cuseState[d] = "run"
        /\ pc[d] = "ck4"
        /\ sval[cuseSem[d]] = 0
        /\ cuseSeg[d] = srvSeg
        /\ seen[d] = View(cuseSeg[d])
        /\ ~pend[d]
    \* the final state: nothing is left to do and nothing is owed
    Quiescent ==
        /\ pc["srv"] = "svUp" /\ restarts = Restarts
        /\ \A d \in DrngProcs : pc[d] = "dr1"
        /\ opc = OpChanges
        /\ \A w \in NeedW : pc[w] = "wn1" /\ nc[w] = NeedChanges
        /\ \A t \in ThreshProcs : pc[t] = "tw1"
        /\ tc = ThreshChanges
        /\ sc = Suspends
        /\ \A e \in EvProcs : pc[e] = "ev1"
        /\ ec = ThreadSuspends
        /\ \A d \in Cuse : CuseIdle(d)
        /\ \A a \in AuxProcs : \/ pc[a] = "Done"
                               \/ pc[a] = "ax2" /\ ~sneed[1]
}

\* IPC_RMID of segment s
macro rmid(s, who) {
    alive[s] := AliveAfterRm(s);
    removed[s] := TRUE;
    rmBy[s] := who;
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
        nameOf[nextSem] := n;
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

\* esdm_shm_status_up(): the semaphores of the CUSE daemons
procedure upCuse()
{
uc1: if ("U" \in Cuse) {
         call up("R");
     } else {
         call up("R");
         return;
     };
uc2: call up("U");
     return;
}

\* esdm_shm_wake_all()
procedure wakeAll()
{
wa1: call upCuse();
wa2: if (Aux # {}) {
         call up("L");
         return;
     } else {
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
     owe[self] := owe[self] \cup Cuse;
     call upCuse();
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
         needSeen := [a \in AuxProcs |-> needSeen[a] \/ nw];
         owe[self] := owe[self] \cup Cuse;
         call upCuse();
     };
     \* the level-triggered semaphore
ne4: if (nw /\ Aux # {}) call up("L");
ne5: if (NeedLocked) nlock := NoProc;
     return;
}

\* esdm_shm_status_set_suspend(): the pointer, the store, the posts
procedure setSuspend()
    variables sseg = 0;
{
ss1: if (srvSeg = 0) {
         return;
     } else {
         sseg := srvSeg;
     };
ss2: ssusp[sseg] := IF SuspendGen THEN ssusp[sseg] + 1 ELSE 1;
     pend := [d \in Cuse |->
                 pend[d] \/ (cuseState[d] = "run" /\ cuseSeg[d] = sseg)];
     owe[self] := owe[self] \cup Names;
     call wakeAll();
     return;
}

\* esdm_shm_status_create_sem()
procedure createSem(cn)
{
cm1: if (semAt[cn] = 0) {
         \* sem_open(O_CREAT | O_EXCL): nobody waits on a new semaphore
         semOpen(cn, srvSem[cn]);
         owe[self] := owe[self] \ {cn};
         return;
     };
     \* EEXIST: sem_open(O_CREAT), then re-synchronize
cm2: semOpen(cn, srvSem[cn]);
cm3: if (SemFix) {
         call up(cn);
         return;
     } else {
         sval[srvSem[cn]] := sval[srvSem[cn]] + 1;
         owe[self] := owe[self] \ {cn};
         return;
     };
}

fair process (srv = "srv")
    variables sid = 0;
{
sv0: if (~Life) goto svUp;
     \* main(): install_term() ignores SIGUSR1, then create_pid_file()
st1: if (IgnoreEarly) sigDisp := "ignore";
st2: pidfile := TRUE;
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
         srvState := "down";
         sigDisp := "default";
         pidfile := FALSE;
         goto st1;
     } else {
         att[sid] := att[sid] \cup {"srv"};
         srvSeg := sid;
         \* a version withdrawn from under a waiting checker: the
         \* re-synchronizing posts of the semaphores announce it
         if (ver[sid] = Ready) owe["srv"] := owe["srv"] \cup Cuse;
         ver[sid] := 0;
         sid := 0;
         if (~Overlap) startLock := NoProc;
     };
     \* esdm_shm_status_init()
cs4: call createSem("R");
cs5: if ("U" \in Cuse) call createSem("U");
cs6: if (Aux # {}) call createSem("L");
in1: if (~PublishLast) {
         ver[srvSeg] := Ready;
         if (PostPublish) owe["srv"] := owe["srv"] \cup Cuse;
     };
     \* esdm_shm_status_set_operational(esdm_state_operational())
in2: if (InitLocked) {
         await dlock = NoProc;
         dlock := "srv";
     };
in3: call setOp(OnOff(esdmOp));
in4: if (InitLocked) dlock := NoProc;
     call setNeed();
     \* esdm_shm_status_install_signal_suspend()
in5: sigDisp := "handler";
     \* the one-shot trigger was cleared here
in6: if (~SuspendGen) ssusp[srvSeg] := 0;
     \* the version, then esdm_shm_status_up()
in7: if (PublishLast) {
         ver[srvSeg] := Ready;
         if (PostPublish) owe["srv"] := owe["srv"] \cup Cuse;
     };
     if (PostPublish) call upCuse();
in8: srvState := "up";
svUp: await restarts < Restarts;
     srvState := "exit";
     \* esdm_fini() joins the threads first
sx1: await /\ \A d \in DrngProcs : pc[d] = "dr1"
           /\ \A w \in NeedW : pc[w] = "wn1"
           /\ \A t \in ThreshProcs : pc[t] = "tw1"
           /\ \A e \in EvProcs : pc[e] = "ev1";
     \* esdm_shm_status_exit_common(): the version withdrawn, then
     \* esdm_shm_status_set_suspend()
sx2: if (ExitUnpublish) {
         if (ver[srvSeg] = Ready) owe["srv"] := owe["srv"] \cup Cuse;
         ver[srvSeg] := 0;
     };
sx3: call setSuspend();
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
cl2: if (sid # 0) rmid(sid, "cleanup");
cl3: if (\E n \in Names : semAt[n] # 0) semRm := "cleanup";
     semAt := [n \in Names |-> 0];
     \* the process ends, systemd starts it again
sx9: restarts := restarts + 1;
     srvState := "down";
     req := [n \in Names |-> 0];
     esdmOp := FALSE;
     sigDisp := "default";
     pidfile := FALSE;
     owe["srv"] := {};
     sid := 0;
     goto st1;
}

\* the thread holding the initial DRNG's lock: esdm_init_ops() and
\* esdm_unset_fully_seeded() change the state, then publish it
fair process (dr \in DrngProcs)
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
{
wn1: while (TRUE) {
         await nc[self] < NeedChanges /\ srvState = "up";
         nc[self] := nc[self] + 1;
         needT := ~needT;
wn2:     call setNeed();
     }
}

\* esdm_set_write_wakeup_bits(): the threshold moves across the level of the
\* pool; with ThreshPublish it calls esdm_shm_status_set_need_entropy()
fair process (tw \in ThreshProcs)
{
tw1: while (TRUE) {
         await tc < ThreshChanges /\ srvState = "up";
         tc := tc + 1;
         needT := ~needT;
tw2:     if (ThreshPublish) call setNeed();
     }
}

\* esdm_shm_status_signal_suspend(), sent by esdm-server-signal-helper to
\* the process the PID file names
fair process (sg \in SigProcs)
{
sg1: while (sc < Suspends) {
         await pidfile /\ (sigDisp = "handler" \/ EarlySignal);
         sc := sc + 1;
         if (sigDisp = "default") {
             \* SIGUSR1's default action ends the server
             killed := TRUE;
         } else if (sigDisp = "handler" /\ srvSeg # 0) {
             \* with SemFix, an owner in its loop posts for the handler
             ssusp[srvSeg] := IF SuspendGen THEN ssusp[srvSeg] + 1 ELSE 1;
             pend := [d \in Cuse |->
                         pend[d] \/ (cuseState[d] = "run"
                                     /\ cuseSeg[d] = srvSeg)];
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

\* esdm_es_events_handle(): esdm_shm_status_suspend() from a thread
fair process (ev \in EvProcs)
{
ev1: while (TRUE) {
         await ec < ThreadSuspends /\ srvState = "up";
         ec := ec + 1;
         call setSuspend();
     }
}

\* a CUSE daemon
fair process (ck \in Cuse)
    variables cseg = 0, cr = FALSE, cg = 0, wk = FALSE;
{
ck0: if (~Life) goto ck1;
     \* esdm_cuse_init_done(): esdm_cuse_shm_status_create_sem()
cu1: if (~Overlap) {
         await startLock = NoProc;
         startLock := self;
     };
     if (semAt[self] = 0) {
         semOpen(self, cuseSem[self]);
         goto cu3;
     };
cu2: semOpen(self, cuseSem[self]);
     \* esdm_cuse_shm_status_create_shm(): shmget(), IPC_STAT
cu3: cseg := keyAt;
     cr := keyAt = 0;
cu4: if (cseg = 0 \/ att[cseg] # {} \/ CuseNoRmid) goto cu6;
     \* no attachment: stale, IPC_RMID
cu5: rmid(cseg, "cuse");
     cseg := 0;
     cr := TRUE;
cu6: if (cseg = 0 /\ cr) shmgetCreate(cseg);
     \* shmat()
cu7: if (cseg = 0 \/ ~alive[cseg]) {
         \* the daemon exits, systemd starts it again
         cuseSem[self] := 0;
         cseg := 0;
         cr := FALSE;
         if (~Overlap) startLock := NoProc;
         goto cu1;
     } else {
         att[cseg] := att[cseg] \cup {self};
         cuseSeg[self] := cseg;
         cseg := 0;
         cr := FALSE;
         if (~Overlap) startLock := NoProc;
     };
     \* the suspend generation so far concerns no poller; the checker starts
cu8: if (SuspendGen) seenGen[self] := ssusp[cuseSeg[self]];
     cuseState[self] := "run";
     \* esdm_cuse_poll_checker(): a pass under esdm_cuse_ph_lock, the
     \* suspend generation (or trigger) first
ck1: while (TRUE) {
         cg := ssusp[cuseSeg[self]];
         \* esdm_cuse_get_pollmask(): version, operational, need_entropy,
         \* the suspend generation against the one seen
ck1a:    if (ver[cuseSeg[self]] = Ready) {
             seen[self] := <<TRUE, seen[self][2], seen[self][3]>>;
         } else {
             seen[self] := <<FALSE, FALSE, FALSE>>;
             goto ck1d;
         };
ck1b:    seen[self] := <<TRUE, sop[cuseSeg[self]], seen[self][3]>>;
ck1c:    seen[self] := <<TRUE, seen[self][2], sneed[cuseSeg[self]]>>;
ck1d:    wk := SuspVisible(self);
         \* the end of the pass: the generation loaded first is the one seen
         \* (the trigger cleared if it was loaded set); a poller woken by a
         \* suspend is followed by one that waits from here on
ck2:     if (wk) pend[self] := FALSE;
         wk := FALSE;
         if (~SuspendGen) {
             if (cg = 1) ssusp[cuseSeg[self]] := 0;
             cg := 0;
         } else {
             \* a store of the daemon's own: one step with the load of the
             \* version in esdm_cuse_shm_status_down()
             seenGen[self] := cg;
             cg := 0;
             if (~ExitUnpublish) {
                 goto ck3;
             } else if (ver[cuseSeg[self]] # Ready) {
                 goto ck1;
             } else {
                 goto ck4;
             };
         };
         \* esdm_cuse_shm_status_down(): the version, then sem_wait(); with
         \* ExitUnpublish another pass every second while no server publishes
ck3:     if (ExitUnpublish /\ ver[cuseSeg[self]] # Ready) {
             goto ck1;
         } else {
             await ver[cuseSeg[self]] = Ready;
         };
ck4:     await sval[cuseSem[self]] > 0;
         sval[cuseSem[self]] := sval[cuseSem[self]] - 1;
     }
}

\* esdm_aux_timedwait_for_need_entropy(), AuxCalls times
fair process (ax \in AuxProcs)
    variables av = 0;
{
ax0: while (calls[self] < AuxCalls) {
         needSeen[self] := sneed[1];
         \* the version, then the flag
ax1:     await ver[1] = Ready;
         if (sneed[1]) goto axR;
ax2:     either {
             \* sem_clockwait() returns 0
             await sval[LSem] > 0;
             sval[LSem] := sval[LSem] - 1;
             if (AuxRecheck) owe[self] := owe[self] \cup {"L"};
         } or {
             \* the timeout: returns -1
             await AuxTimeout;
             calls[self] := calls[self] + 1;
             goto ax0;
         };
         \* AuxRecheck: returns 0 only with the flag set, passing the wakeup
         \* on (sem_getvalue(), sem_post()); waits on without
ax3:     if (~AuxRecheck) {
             goto axR;
         } else if (~sneed[1]) {
             owe[self] := owe[self] \ {"L"};
             goto ax1;
         };
ax4:     av := sval[LSem];
ax5:     if (av = 0) sval[LSem] := sval[LSem] + 1;
         owe[self] := owe[self] \ {"L"};
         av := 0;
         \* returns 0: the ESDM needs entropy
axR:     calls[self] := calls[self] + 1;
     }
}

\* the final state, see Quiescent
process (fin = "fin")
{
fn1: while (TRUE) {
         await Quiescent;
         skip;
     }
}

} *)
\* BEGIN TRANSLATION
CONSTANT defaultInitValue
VARIABLES keyAt, alive, removed, att, ver, sop, sneed, ssusp, nextSeg, semAt, 
          sval, nextSem, srvState, srvSeg, srvSem, esdmOp, needT, sigDisp, 
          pidfile, dlock, nlock, req, startLock, cuseState, cuseSeg, cuseSem, 
          seenGen, restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
          needSeen, killed, nameOf, rmBy, semRm, pc, stack

(* define statement *)
Content(s) == <<sop[s], sneed[s]>>


View(s) == IF ver[s] = Ready THEN <<TRUE, sop[s], sneed[s]>>
           ELSE <<FALSE, FALSE, FALSE>>
OnOff(b) == IF b THEN "on" ELSE "off"

AliveAfterRm(s) == alive[s] /\ att[s] # {}

SuspVisible(d) == IF SuspendGen THEN ssusp[cuseSeg[d]] # seenGen[d]
                  ELSE ssusp[cuseSeg[d]] = 1

CuseIdle(d) ==
    /\ cuseState[d] = "run"
    /\ pc[d] = "ck4"
    /\ sval[cuseSem[d]] = 0
    /\ cuseSeg[d] = srvSeg
    /\ seen[d] = View(cuseSeg[d])
    /\ ~pend[d]

Quiescent ==
    /\ pc["srv"] = "svUp" /\ restarts = Restarts
    /\ \A d \in DrngProcs : pc[d] = "dr1"
    /\ opc = OpChanges
    /\ \A w \in NeedW : pc[w] = "wn1" /\ nc[w] = NeedChanges
    /\ \A t \in ThreshProcs : pc[t] = "tw1"
    /\ tc = ThreshChanges
    /\ sc = Suspends
    /\ \A e \in EvProcs : pc[e] = "ev1"
    /\ ec = ThreadSuspends
    /\ \A d \in Cuse : CuseIdle(d)
    /\ \A a \in AuxProcs : \/ pc[a] = "Done"
                           \/ pc[a] = "ax2" /\ ~sneed[1]

VARIABLES un, uo, rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, cg, 
          wk, av

vars == << keyAt, alive, removed, att, ver, sop, sneed, ssusp, nextSeg, semAt, 
           sval, nextSem, srvState, srvSeg, srvSem, esdmOp, needT, sigDisp, 
           pidfile, dlock, nlock, req, startLock, cuseState, cuseSeg, cuseSem, 
           seenGen, restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
           needSeen, killed, nameOf, rmBy, semRm, pc, stack, un, uo, rq, en, 
           oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ProcSet == {"srv"} \cup (DrngProcs) \cup (NeedW) \cup (ThreshProcs) \cup (SigProcs) \cup (EvProcs) \cup (Cuse) \cup (AuxProcs) \cup {"fin"}

Init == (* Global variables *)
        /\ keyAt = (IF InitSegs = {} THEN 0 ELSE 1)
        /\ alive = [s \in Segs |-> s \in InitSegs]
        /\ removed = [s \in Segs |-> FALSE]
        /\ att = [s \in Segs |-> IF s = 1 /\ ~Life THEN {"srv"} \cup Cuse \cup AuxProcs
                                 ELSE {}]
        /\ ver = [s \in Segs |-> IF s \in InitSegs THEN Ready ELSE 0]
        /\ sop = [s \in Segs |-> s = 1 /\ Life /\ Leftover]
        /\ sneed = [s \in Segs |-> s = 1 /\ Life /\ Leftover]
        /\ ssusp = [s \in Segs |-> 0]
        /\ nextSeg = (IF InitSegs = {} THEN 1 ELSE 2)
        /\ semAt = [n \in Names |-> IF InitSegs = {} THEN 0 ELSE SemId(n)]
        /\ sval = [o \in Sems |-> 0]
        /\ nextSem = (IF InitSegs = {} THEN 1 ELSE Cardinality(Names) + 1)
        /\ srvState = IF Life THEN "down" ELSE "up"
        /\ srvSeg = IF Life THEN 0 ELSE 1
        /\ srvSem = [n \in Names |-> IF Life THEN 0 ELSE SemId(n)]
        /\ esdmOp = FALSE
        /\ needT = FALSE
        /\ sigDisp = IF Life THEN "default" ELSE "handler"
        /\ pidfile = ~Life
        /\ dlock = NoProc
        /\ nlock = NoProc
        /\ req = [n \in Names |-> 0]
        /\ startLock = NoProc
        /\ cuseState = [d \in Cuse |-> IF Life THEN "off" ELSE "run"]
        /\ cuseSeg = [d \in Cuse |-> IF Life THEN 0 ELSE 1]
        /\ cuseSem = [d \in Cuse |-> IF Life THEN 0 ELSE SemId(d)]
        /\ seenGen = [d \in Cuse |-> 0]
        /\ restarts = 0
        /\ opc = 0
        /\ nc = [w \in NeedW |-> 0]
        /\ tc = 0
        /\ sc = 0
        /\ ec = 0
        /\ calls = [a \in AuxProcs |-> 0]
        /\ seen = [d \in Cuse |-> <<FALSE, FALSE, FALSE>>]
        /\ pend = [d \in Cuse |-> FALSE]
        /\ owe = [p \in Procs |-> {}]
        /\ needSeen = [a \in AuxProcs |-> FALSE]
        /\ killed = FALSE
        /\ nameOf = [o \in Sems |-> IF InitSegs # {} /\ (\E n \in Names : SemId(n) = o)
                                    THEN CHOOSE n \in Names : SemId(n) = o
                                    ELSE "none"]
        /\ rmBy = [s \in Segs |-> "none"]
        /\ semRm = "none"
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
        (* Procedure setSuspend *)
        /\ sseg = [ self \in ProcSet |-> 0]
        (* Procedure createSem *)
        /\ cn = [ self \in ProcSet |-> defaultInitValue]
        (* Process srv *)
        /\ sid = 0
        (* Process ck *)
        /\ cseg = [self \in Cuse |-> 0]
        /\ cr = [self \in Cuse |-> FALSE]
        /\ cg = [self \in Cuse |-> 0]
        /\ wk = [self \in Cuse |-> FALSE]
        (* Process ax *)
        /\ av = [self \in AuxProcs |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self = "srv" -> "sv0"
                                        [] self \in DrngProcs -> "dr1"
                                        [] self \in NeedW -> "wn1"
                                        [] self \in ThreshProcs -> "tw1"
                                        [] self \in SigProcs -> "sg1"
                                        [] self \in EvProcs -> "ev1"
                                        [] self \in Cuse -> "ck0"
                                        [] self \in AuxProcs -> "ax0"
                                        [] self = "fin" -> "fn1"]

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, en, oseg, nseg, curr, nw, sseg, cn, sid, 
                             cseg, cr, cg, wk, av >>

up1(self) == /\ pc[self] = "up1"
             /\ rq' = [rq EXCEPT ![self] = req[un[self]]]
             /\ IF sval[uo[self]] > 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "up3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "up2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, en, oseg, nseg, curr, 
                             nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

up2(self) == /\ pc[self] = "up2"
             /\ sval' = [sval EXCEPT ![uo[self]] = sval[uo[self]] + 1]
             /\ pc' = [pc EXCEPT ![self] = "up3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, en, oseg, nseg, curr, nw, sseg, cn, sid, 
                             cseg, cr, cg, wk, av >>

up(self) == up0(self) \/ up1(self) \/ up2(self) \/ up3(self)

uc1(self) == /\ pc[self] = "uc1"
             /\ IF "U" \in Cuse
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                                    pc        |->  "uc2",
                                                                    uo        |->  uo[self],
                                                                    rq        |->  rq[self],
                                                                    un        |->  un[self] ] >>
                                                                \o stack[self]]
                           /\ un' = [un EXCEPT ![self] = "R"]
                        /\ uo' = [uo EXCEPT ![self] = 0]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "up0"]
                   ELSE /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                                    pc        |->  Head(stack[self]).pc,
                                                                    uo        |->  uo[self],
                                                                    rq        |->  rq[self],
                                                                    un        |->  un[self] ] >>
                                                                \o Tail(stack[self])]
                           /\ un' = [un EXCEPT ![self] = "R"]
                        /\ uo' = [uo EXCEPT ![self] = 0]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "up0"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, en, oseg, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

uc2(self) == /\ pc[self] = "uc2"
             /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                         pc        |->  Head(stack[self]).pc,
                                                         uo        |->  uo[self],
                                                         rq        |->  rq[self],
                                                         un        |->  un[self] ] >>
                                                     \o Tail(stack[self])]
                /\ un' = [un EXCEPT ![self] = "U"]
             /\ uo' = [uo EXCEPT ![self] = 0]
             /\ rq' = [rq EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "up0"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, en, oseg, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

upCuse(self) == uc1(self) \/ uc2(self)

wa1(self) == /\ pc[self] = "wa1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "upCuse",
                                                      pc        |->  "wa2" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "uc1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, en, oseg, nseg, curr, nw, 
                             sseg, cn, sid, cseg, cr, cg, wk, av >>

wa2(self) == /\ pc[self] = "wa2"
             /\ IF Aux # {}
                   THEN /\ /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "up",
                                                                    pc        |->  Head(stack[self]).pc,
                                                                    uo        |->  uo[self],
                                                                    rq        |->  rq[self],
                                                                    un        |->  un[self] ] >>
                                                                \o Tail(stack[self])]
                           /\ un' = [un EXCEPT ![self] = "L"]
                        /\ uo' = [uo EXCEPT ![self] = 0]
                        /\ rq' = [rq EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "up0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << un, uo, rq >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, en, oseg, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

wakeAll(self) == wa1(self) \/ wa2(self)

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

op2(self) == /\ pc[self] = "op2"
             /\ sop' = [sop EXCEPT ![oseg[self]] = en[self] = "on"]
             /\ owe' = [owe EXCEPT ![self] = owe[self] \cup Cuse]
             /\ /\ oseg' = [oseg EXCEPT ![self] = Head(stack[self]).oseg]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "upCuse",
                                                         pc        |->  Head(stack[self]).pc ] >>
                                                     \o Tail(stack[self])]
             /\ pc' = [pc EXCEPT ![self] = "uc1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sneed, ssusp, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, un, uo, rq, en, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ne1(self) == /\ pc[self] = "ne1"
             /\ IF srvSeg = 0
                   THEN /\ pc' = [pc EXCEPT ![self] = "ne5"]
                        /\ UNCHANGED << nseg, curr >>
                   ELSE /\ nseg' = [nseg EXCEPT ![self] = srvSeg]
                        /\ curr' = [curr EXCEPT ![self] = sneed[srvSeg]]
                        /\ pc' = [pc EXCEPT ![self] = "ne2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nw, 
                             sseg, cn, sid, cseg, cr, cg, wk, av >>

ne2(self) == /\ pc[self] = "ne2"
             /\ nw' = [nw EXCEPT ![self] = needT]
             /\ IF needT /\ Aux # {}
                   THEN /\ owe' = [owe EXCEPT ![self] = owe[self] \cup {"L"}]
                   ELSE /\ TRUE
                        /\ owe' = owe
             /\ pc' = [pc EXCEPT ![self] = "ne3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                             sseg, cn, sid, cseg, cr, cg, wk, av >>

ne3(self) == /\ pc[self] = "ne3"
             /\ IF curr[self] # nw[self]
                   THEN /\ sneed' = [sneed EXCEPT ![nseg[self]] = nw[self]]
                        /\ needSeen' = [a \in AuxProcs |-> needSeen[a] \/ nw[self]]
                        /\ owe' = [owe EXCEPT ![self] = owe[self] \cup Cuse]
                        /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "upCuse",
                                                                 pc        |->  "ne4" ] >>
                                                             \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "uc1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ne4"]
                        /\ UNCHANGED << sneed, owe, needSeen, stack >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, ssusp, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, killed, nameOf, rmBy, semRm, 
                             un, uo, rq, en, oseg, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, en, oseg, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, en, oseg, sseg, cn, sid, 
                             cseg, cr, cg, wk, av >>

setNeed(self) == ne0(self) \/ ne1(self) \/ ne2(self) \/ ne3(self)
                    \/ ne4(self) \/ ne5(self)

ss1(self) == /\ pc[self] = "ss1"
             /\ IF srvSeg = 0
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ sseg' = [sseg EXCEPT ![self] = Head(stack[self]).sseg]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ sseg' = [sseg EXCEPT ![self] = srvSeg]
                        /\ pc' = [pc EXCEPT ![self] = "ss2"]
                        /\ stack' = stack
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, en, oseg, nseg, curr, nw, 
                             cn, sid, cseg, cr, cg, wk, av >>

ss2(self) == /\ pc[self] = "ss2"
             /\ ssusp' = [ssusp EXCEPT ![sseg[self]] = IF SuspendGen THEN ssusp[sseg[self]] + 1 ELSE 1]
             /\ pend' = [d \in Cuse |->
                            pend[d] \/ (cuseState[d] = "run" /\ cuseSeg[d] = sseg[self])]
             /\ owe' = [owe EXCEPT ![self] = owe[self] \cup Names]
             /\ /\ sseg' = [sseg EXCEPT ![self] = Head(stack[self]).sseg]
                /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "wakeAll",
                                                         pc        |->  Head(stack[self]).pc ] >>
                                                     \o Tail(stack[self])]
             /\ pc' = [pc EXCEPT ![self] = "wa1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, needSeen, killed, nameOf, rmBy, 
                             semRm, un, uo, rq, en, oseg, nseg, curr, nw, cn, 
                             sid, cseg, cr, cg, wk, av >>

setSuspend(self) == ss1(self) \/ ss2(self)

cm1(self) == /\ pc[self] = "cm1"
             /\ IF semAt[cn[self]] = 0
                   THEN /\ IF semAt[cn[self]] = 0
                              THEN /\ Assert(nextSem <= MaxSem, 
                                             "Failure of assertion at line 239, column 9 of macro called at line 373, column 10.")
                                   /\ srvSem' = [srvSem EXCEPT ![cn[self]] = nextSem]
                                   /\ semAt' = [semAt EXCEPT ![cn[self]] = nextSem]
                                   /\ nameOf' = [nameOf EXCEPT ![nextSem] = cn[self]]
                                   /\ nextSem' = nextSem + 1
                              ELSE /\ srvSem' = [srvSem EXCEPT ![cn[self]] = semAt[cn[self]]]
                                   /\ UNCHANGED << semAt, nextSem, nameOf >>
                        /\ owe' = [owe EXCEPT ![self] = owe[self] \ {cn[self]}]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ cn' = [cn EXCEPT ![self] = Head(stack[self]).cn]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cm2"]
                        /\ UNCHANGED << semAt, nextSem, srvSem, owe, nameOf, 
                                        stack, cn >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, sval, srvState, srvSeg, esdmOp, 
                             needT, sigDisp, pidfile, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                             restarts, opc, nc, tc, sc, ec, calls, seen, pend, 
                             needSeen, killed, rmBy, semRm, un, uo, rq, en, 
                             oseg, nseg, curr, nw, sseg, sid, cseg, cr, cg, wk, 
                             av >>

cm2(self) == /\ pc[self] = "cm2"
             /\ IF semAt[cn[self]] = 0
                   THEN /\ Assert(nextSem <= MaxSem, 
                                  "Failure of assertion at line 239, column 9 of macro called at line 378, column 6.")
                        /\ srvSem' = [srvSem EXCEPT ![cn[self]] = nextSem]
                        /\ semAt' = [semAt EXCEPT ![cn[self]] = nextSem]
                        /\ nameOf' = [nameOf EXCEPT ![nextSem] = cn[self]]
                        /\ nextSem' = nextSem + 1
                   ELSE /\ srvSem' = [srvSem EXCEPT ![cn[self]] = semAt[cn[self]]]
                        /\ UNCHANGED << semAt, nextSem, nameOf >>
             /\ pc' = [pc EXCEPT ![self] = "cm3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, sval, srvState, srvSeg, esdmOp, 
                             needT, sigDisp, pidfile, dlock, nlock, req, 
                             startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                             restarts, opc, nc, tc, sc, ec, calls, seen, pend, 
                             owe, needSeen, killed, rmBy, semRm, stack, un, uo, 
                             rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, 
                             cr, cg, wk, av >>

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
                        /\ UNCHANGED << sval, owe, cn >>
                   ELSE /\ sval' = [sval EXCEPT ![srvSem[cn[self]]] = sval[srvSem[cn[self]]] + 1]
                        /\ owe' = [owe EXCEPT ![self] = owe[self] \ {cn[self]}]
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ cn' = [cn EXCEPT ![self] = Head(stack[self]).cn]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << un, uo, rq >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, en, oseg, nseg, curr, nw, sseg, sid, cseg, 
                             cr, cg, wk, av >>

createSem(self) == cm1(self) \/ cm2(self) \/ cm3(self)

sv0 == /\ pc["srv"] = "sv0"
       /\ IF ~Life
             THEN /\ pc' = [pc EXCEPT !["srv"] = "svUp"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "st1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, 
                       cg, wk, av >>

st1 == /\ pc["srv"] = "st1"
       /\ IF IgnoreEarly
             THEN /\ sigDisp' = "ignore"
             ELSE /\ TRUE
                  /\ UNCHANGED sigDisp
       /\ pc' = [pc EXCEPT !["srv"] = "st2"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

st2 == /\ pc["srv"] = "st2"
       /\ pidfile' = TRUE
       /\ pc' = [pc EXCEPT !["srv"] = "cs1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

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
                       needT, sigDisp, pidfile, dlock, nlock, req, cuseState, 
                       cuseSeg, cuseSem, seenGen, restarts, opc, nc, tc, sc, 
                       ec, calls, seen, pend, owe, needSeen, killed, nameOf, 
                       rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                       nw, sseg, cn, cseg, cr, cg, wk, av >>

cs2 == /\ pc["srv"] = "cs2"
       /\ IF sid = 0
             THEN /\ IF keyAt = 0
                        THEN /\ Assert(nextSeg <= MaxSeg, 
                                       "Failure of assertion at line 226, column 9 of macro called at line 403, column 19.")
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
                       sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, cseg, cr, cg, wk, av >>

cs3 == /\ pc["srv"] = "cs3"
       /\ IF ~alive[sid]
             THEN /\ sid' = 0
                  /\ IF ~Overlap
                        THEN /\ startLock' = NoProc
                        ELSE /\ TRUE
                             /\ UNCHANGED startLock
                  /\ srvState' = "down"
                  /\ sigDisp' = "default"
                  /\ pidfile' = FALSE
                  /\ pc' = [pc EXCEPT !["srv"] = "st1"]
                  /\ UNCHANGED << att, ver, srvSeg, owe >>
             ELSE /\ att' = [att EXCEPT ![sid] = att[sid] \cup {"srv"}]
                  /\ srvSeg' = sid
                  /\ IF ver[sid] = Ready
                        THEN /\ owe' = [owe EXCEPT !["srv"] = owe["srv"] \cup Cuse]
                        ELSE /\ TRUE
                             /\ owe' = owe
                  /\ ver' = [ver EXCEPT ![sid] = 0]
                  /\ sid' = 0
                  /\ IF ~Overlap
                        THEN /\ startLock' = NoProc
                        ELSE /\ TRUE
                             /\ UNCHANGED startLock
                  /\ pc' = [pc EXCEPT !["srv"] = "cs4"]
                  /\ UNCHANGED << srvState, sigDisp, pidfile >>
       /\ UNCHANGED << keyAt, alive, removed, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvSem, esdmOp, needT, dlock, 
                       nlock, req, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, 
                       needSeen, killed, nameOf, rmBy, semRm, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, sseg, cn, cseg, cr, cg, 
                       wk, av >>

cs4 == /\ pc["srv"] = "cs4"
       /\ /\ cn' = [cn EXCEPT !["srv"] = "R"]
          /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "createSem",
                                                    pc        |->  "cs5",
                                                    cn        |->  cn["srv"] ] >>
                                                \o stack["srv"]]
       /\ pc' = [pc EXCEPT !["srv"] = "cm1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, un, uo, rq, en, 
                       oseg, nseg, curr, nw, sseg, sid, cseg, cr, cg, wk, av >>

cs5 == /\ pc["srv"] = "cs5"
       /\ IF "U" \in Cuse
             THEN /\ /\ cn' = [cn EXCEPT !["srv"] = "U"]
                     /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "createSem",
                                                               pc        |->  "cs6",
                                                               cn        |->  cn["srv"] ] >>
                                                           \o stack["srv"]]
                  /\ pc' = [pc EXCEPT !["srv"] = "cm1"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "cs6"]
                  /\ UNCHANGED << stack, cn >>
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, un, uo, rq, en, 
                       oseg, nseg, curr, nw, sseg, sid, cseg, cr, cg, wk, av >>

cs6 == /\ pc["srv"] = "cs6"
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
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, un, uo, rq, en, 
                       oseg, nseg, curr, nw, sseg, sid, cseg, cr, cg, wk, av >>

in1 == /\ pc["srv"] = "in1"
       /\ IF ~PublishLast
             THEN /\ ver' = [ver EXCEPT ![srvSeg] = Ready]
                  /\ IF PostPublish
                        THEN /\ owe' = [owe EXCEPT !["srv"] = owe["srv"] \cup Cuse]
                        ELSE /\ TRUE
                             /\ owe' = owe
             ELSE /\ TRUE
                  /\ UNCHANGED << ver, owe >>
       /\ pc' = [pc EXCEPT !["srv"] = "in2"]
       /\ UNCHANGED << keyAt, alive, removed, att, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, needSeen, killed, nameOf, 
                       rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                       nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

in2 == /\ pc["srv"] = "in2"
       /\ IF InitLocked
             THEN /\ dlock = NoProc
                  /\ dlock' = "srv"
             ELSE /\ TRUE
                  /\ dlock' = dlock
       /\ pc' = [pc EXCEPT !["srv"] = "in3"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

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
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, un, uo, rq, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

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
                       esdmOp, needT, sigDisp, pidfile, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, un, uo, rq, en, oseg, sseg, cn, 
                       sid, cseg, cr, cg, wk, av >>

in5 == /\ pc["srv"] = "in5"
       /\ sigDisp' = "handler"
       /\ pc' = [pc EXCEPT !["srv"] = "in6"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

in6 == /\ pc["srv"] = "in6"
       /\ IF ~SuspendGen
             THEN /\ ssusp' = [ssusp EXCEPT ![srvSeg] = 0]
             ELSE /\ TRUE
                  /\ ssusp' = ssusp
       /\ pc' = [pc EXCEPT !["srv"] = "in7"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

in7 == /\ pc["srv"] = "in7"
       /\ IF PublishLast
             THEN /\ ver' = [ver EXCEPT ![srvSeg] = Ready]
                  /\ IF PostPublish
                        THEN /\ owe' = [owe EXCEPT !["srv"] = owe["srv"] \cup Cuse]
                        ELSE /\ TRUE
                             /\ owe' = owe
             ELSE /\ TRUE
                  /\ UNCHANGED << ver, owe >>
       /\ IF PostPublish
             THEN /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "upCuse",
                                                            pc        |->  "in8" ] >>
                                                        \o stack["srv"]]
                  /\ pc' = [pc EXCEPT !["srv"] = "uc1"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "in8"]
                  /\ stack' = stack
       /\ UNCHANGED << keyAt, alive, removed, att, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, needSeen, killed, nameOf, 
                       rmBy, semRm, un, uo, rq, en, oseg, nseg, curr, nw, sseg, 
                       cn, sid, cseg, cr, cg, wk, av >>

in8 == /\ pc["srv"] = "in8"
       /\ srvState' = "up"
       /\ pc' = [pc EXCEPT !["srv"] = "svUp"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvSeg, srvSem, esdmOp, 
                       needT, sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                       curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

svUp == /\ pc["srv"] = "svUp"
        /\ restarts < Restarts
        /\ srvState' = "exit"
        /\ pc' = [pc EXCEPT !["srv"] = "sx1"]
        /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                        nextSeg, semAt, sval, nextSem, srvSeg, srvSem, esdmOp, 
                        needT, sigDisp, pidfile, dlock, nlock, req, startLock, 
                        cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, 
                        nc, tc, sc, ec, calls, seen, pend, owe, needSeen, 
                        killed, nameOf, rmBy, semRm, stack, un, uo, rq, en, 
                        oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, cg, wk, 
                        av >>

sx1 == /\ pc["srv"] = "sx1"
       /\ /\ \A d \in DrngProcs : pc[d] = "dr1"
          /\ \A w \in NeedW : pc[w] = "wn1"
          /\ \A t \in ThreshProcs : pc[t] = "tw1"
          /\ \A e \in EvProcs : pc[e] = "ev1"
       /\ pc' = [pc EXCEPT !["srv"] = "sx2"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, 
                       cg, wk, av >>

sx2 == /\ pc["srv"] = "sx2"
       /\ IF ExitUnpublish
             THEN /\ IF ver[srvSeg] = Ready
                        THEN /\ owe' = [owe EXCEPT !["srv"] = owe["srv"] \cup Cuse]
                        ELSE /\ TRUE
                             /\ owe' = owe
                  /\ ver' = [ver EXCEPT ![srvSeg] = 0]
             ELSE /\ TRUE
                  /\ UNCHANGED << ver, owe >>
       /\ pc' = [pc EXCEPT !["srv"] = "sx3"]
       /\ UNCHANGED << keyAt, alive, removed, att, sop, sneed, ssusp, nextSeg, 
                       semAt, sval, nextSem, srvState, srvSeg, srvSem, esdmOp, 
                       needT, sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, needSeen, killed, nameOf, 
                       rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                       nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

sx3 == /\ pc["srv"] = "sx3"
       /\ stack' = [stack EXCEPT !["srv"] = << [ procedure |->  "setSuspend",
                                                 pc        |->  "sx4",
                                                 sseg      |->  sseg["srv"] ] >>
                                             \o stack["srv"]]
       /\ sseg' = [sseg EXCEPT !["srv"] = 0]
       /\ pc' = [pc EXCEPT !["srv"] = "ss1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, un, uo, rq, en, 
                       oseg, nseg, curr, nw, cn, sid, cseg, cr, cg, wk, av >>

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
                       sval, nextSem, srvState, esdmOp, needT, sigDisp, 
                       pidfile, dlock, nlock, req, startLock, cuseState, 
                       cuseSeg, cuseSem, seenGen, restarts, opc, nc, tc, sc, 
                       ec, calls, seen, pend, owe, needSeen, killed, nameOf, 
                       rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                       nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

cl1 == /\ pc["srv"] = "cl1"
       /\ sid' = keyAt
       /\ IF sid' # 0 /\ att[sid'] # {}
             THEN /\ pc' = [pc EXCEPT !["srv"] = "sx9"]
             ELSE /\ pc' = [pc EXCEPT !["srv"] = "cl2"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, sseg, cn, cseg, cr, cg, 
                       wk, av >>

cl2 == /\ pc["srv"] = "cl2"
       /\ IF sid # 0
             THEN /\ alive' = [alive EXCEPT ![sid] = AliveAfterRm(sid)]
                  /\ removed' = [removed EXCEPT ![sid] = TRUE]
                  /\ rmBy' = [rmBy EXCEPT ![sid] = "cleanup"]
                  /\ IF keyAt = sid
                        THEN /\ keyAt' = 0
                        ELSE /\ TRUE
                             /\ keyAt' = keyAt
             ELSE /\ TRUE
                  /\ UNCHANGED << keyAt, alive, removed, rmBy >>
       /\ pc' = [pc EXCEPT !["srv"] = "cl3"]
       /\ UNCHANGED << att, ver, sop, sneed, ssusp, nextSeg, semAt, sval, 
                       nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                       sigDisp, pidfile, dlock, nlock, req, startLock, 
                       cuseState, cuseSeg, cuseSem, seenGen, restarts, opc, nc, 
                       tc, sc, ec, calls, seen, pend, owe, needSeen, killed, 
                       nameOf, semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                       nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

cl3 == /\ pc["srv"] = "cl3"
       /\ IF \E n \in Names : semAt[n] # 0
             THEN /\ semRm' = "cleanup"
             ELSE /\ TRUE
                  /\ semRm' = semRm
       /\ semAt' = [n \in Names |-> 0]
       /\ pc' = [pc EXCEPT !["srv"] = "sx9"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, stack, un, uo, rq, en, 
                       oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, cg, wk, 
                       av >>

sx9 == /\ pc["srv"] = "sx9"
       /\ restarts' = restarts + 1
       /\ srvState' = "down"
       /\ req' = [n \in Names |-> 0]
       /\ esdmOp' = FALSE
       /\ sigDisp' = "default"
       /\ pidfile' = FALSE
       /\ owe' = [owe EXCEPT !["srv"] = {}]
       /\ sid' = 0
       /\ pc' = [pc EXCEPT !["srv"] = "st1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvSeg, srvSem, needT, 
                       dlock, nlock, startLock, cuseState, cuseSeg, cuseSem, 
                       seenGen, opc, nc, tc, sc, ec, calls, seen, pend, 
                       needSeen, killed, nameOf, rmBy, semRm, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, sseg, cn, cseg, cr, cg, 
                       wk, av >>

srv == sv0 \/ st1 \/ st2 \/ cs1 \/ cs2 \/ cs3 \/ cs4 \/ cs5 \/ cs6 \/ in1
          \/ in2 \/ in3 \/ in4 \/ in5 \/ in6 \/ in7 \/ in8 \/ svUp \/ sx1
          \/ sx2 \/ sx3 \/ sx4 \/ cl1 \/ cl2 \/ cl3 \/ sx9

dr1(self) == /\ pc[self] = "dr1"
             /\ opc < OpChanges /\ dlock = NoProc
                /\ (srvState = "up"
                    \/ (InitConcurrent /\ srvState = "init" /\ srvSeg # 0))
             /\ dlock' = self
             /\ esdmOp' = ~esdmOp
             /\ opc' = opc + 1
             /\ pc' = [pc EXCEPT ![self] = "dr2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, needT, sigDisp, pidfile, nlock, 
                             req, startLock, cuseState, cuseSeg, cuseSem, 
                             seenGen, restarts, nc, tc, sc, ec, calls, seen, 
                             pend, owe, needSeen, killed, nameOf, rmBy, semRm, 
                             stack, un, uo, rq, en, oseg, nseg, curr, nw, sseg, 
                             cn, sid, cseg, cr, cg, wk, av >>

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

dr3(self) == /\ pc[self] = "dr3"
             /\ dlock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "dr1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

dr(self) == dr1(self) \/ dr2(self) \/ dr3(self)

wn1(self) == /\ pc[self] = "wn1"
             /\ nc[self] < NeedChanges /\ srvState = "up"
             /\ nc' = [nc EXCEPT ![self] = nc[self] + 1]
             /\ needT' = ~needT
             /\ pc' = [pc EXCEPT ![self] = "wn2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

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
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, en, oseg, sseg, cn, sid, 
                             cseg, cr, cg, wk, av >>

pw(self) == wn1(self) \/ wn2(self)

tw1(self) == /\ pc[self] = "tw1"
             /\ tc < ThreshChanges /\ srvState = "up"
             /\ tc' = tc + 1
             /\ needT' = ~needT
             /\ pc' = [pc EXCEPT ![self] = "tw2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

tw2(self) == /\ pc[self] = "tw2"
             /\ IF ThreshPublish
                   THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "setNeed",
                                                                 pc        |->  "tw1",
                                                                 nseg      |->  nseg[self],
                                                                 curr      |->  curr[self],
                                                                 nw        |->  nw[self] ] >>
                                                             \o stack[self]]
                        /\ nseg' = [nseg EXCEPT ![self] = 0]
                        /\ curr' = [curr EXCEPT ![self] = FALSE]
                        /\ nw' = [nw EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "ne0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "tw1"]
                        /\ UNCHANGED << stack, nseg, curr, nw >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, en, oseg, sseg, cn, sid, 
                             cseg, cr, cg, wk, av >>

tw(self) == tw1(self) \/ tw2(self)

sg1(self) == /\ pc[self] = "sg1"
             /\ IF sc < Suspends
                   THEN /\ pidfile /\ (sigDisp = "handler" \/ EarlySignal)
                        /\ sc' = sc + 1
                        /\ IF sigDisp = "default"
                              THEN /\ killed' = TRUE
                                   /\ UNCHANGED << ssusp, sval, req, pend >>
                              ELSE /\ IF sigDisp = "handler" /\ srvSeg # 0
                                         THEN /\ ssusp' = [ssusp EXCEPT ![srvSeg] = IF SuspendGen THEN ssusp[srvSeg] + 1 ELSE 1]
                                              /\ pend' = [d \in Cuse |->
                                                             pend[d] \/ (cuseState[d] = "run"
                                                                         /\ cuseSeg[d] = srvSeg)]
                                              /\ sval' = [o \in Sems |->
                                                             IF /\ \E n \in Names : /\ srvSem[n] = o
                                                                                    /\ ~(SemFix /\ req[n] > 0)
                                                                /\ sval[o] = 0
                                                             THEN 1 ELSE sval[o]]
                                              /\ req' = [n \in Names |-> IF SemFix /\ req[n] > 0 THEN req[n] + 1
                                                                         ELSE req[n]]
                                         ELSE /\ TRUE
                                              /\ UNCHANGED << ssusp, sval, req, 
                                                              pend >>
                                   /\ UNCHANGED killed
                        /\ pc' = [pc EXCEPT ![self] = "sg1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << ssusp, sval, req, sc, pend, killed >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             nextSeg, semAt, nextSem, srvState, srvSeg, srvSem, 
                             esdmOp, needT, sigDisp, pidfile, dlock, nlock, 
                             startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                             restarts, opc, nc, tc, ec, calls, seen, owe, 
                             needSeen, nameOf, rmBy, semRm, stack, un, uo, rq, 
                             en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, 
                             cg, wk, av >>

sg(self) == sg1(self)

ev1(self) == /\ pc[self] = "ev1"
             /\ ec < ThreadSuspends /\ srvState = "up"
             /\ ec' = ec + 1
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "setSuspend",
                                                      pc        |->  "ev1",
                                                      sseg      |->  sseg[self] ] >>
                                                  \o stack[self]]
             /\ sseg' = [sseg EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "ss1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, un, uo, rq, en, oseg, nseg, curr, nw, 
                             cn, sid, cseg, cr, cg, wk, av >>

ev(self) == ev1(self)

ck0(self) == /\ pc[self] = "ck0"
             /\ IF ~Life
                   THEN /\ pc' = [pc EXCEPT ![self] = "ck1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cu1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

cu1(self) == /\ pc[self] = "cu1"
             /\ IF ~Overlap
                   THEN /\ startLock = NoProc
                        /\ startLock' = self
                   ELSE /\ TRUE
                        /\ UNCHANGED startLock
             /\ IF semAt[self] = 0
                   THEN /\ IF semAt[self] = 0
                              THEN /\ Assert(nextSem <= MaxSem, 
                                             "Failure of assertion at line 239, column 9 of macro called at line 579, column 10.")
                                   /\ cuseSem' = [cuseSem EXCEPT ![self] = nextSem]
                                   /\ semAt' = [semAt EXCEPT ![self] = nextSem]
                                   /\ nameOf' = [nameOf EXCEPT ![nextSem] = self]
                                   /\ nextSem' = nextSem + 1
                              ELSE /\ cuseSem' = [cuseSem EXCEPT ![self] = semAt[self]]
                                   /\ UNCHANGED << semAt, nextSem, nameOf >>
                        /\ pc' = [pc EXCEPT ![self] = "cu3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cu2"]
                        /\ UNCHANGED << semAt, nextSem, cuseSem, nameOf >>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, sval, srvState, srvSeg, srvSem, 
                             esdmOp, needT, sigDisp, pidfile, dlock, nlock, 
                             req, cuseState, cuseSeg, seenGen, restarts, opc, 
                             nc, tc, sc, ec, calls, seen, pend, owe, needSeen, 
                             killed, rmBy, semRm, stack, un, uo, rq, en, oseg, 
                             nseg, curr, nw, sseg, cn, sid, cseg, cr, cg, wk, 
                             av >>

cu2(self) == /\ pc[self] = "cu2"
             /\ IF semAt[self] = 0
                   THEN /\ Assert(nextSem <= MaxSem, 
                                  "Failure of assertion at line 239, column 9 of macro called at line 582, column 6.")
                        /\ cuseSem' = [cuseSem EXCEPT ![self] = nextSem]
                        /\ semAt' = [semAt EXCEPT ![self] = nextSem]
                        /\ nameOf' = [nameOf EXCEPT ![nextSem] = self]
                        /\ nextSem' = nextSem + 1
                   ELSE /\ cuseSem' = [cuseSem EXCEPT ![self] = semAt[self]]
                        /\ UNCHANGED << semAt, nextSem, nameOf >>
             /\ pc' = [pc EXCEPT ![self] = "cu3"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, sval, srvState, srvSeg, srvSem, 
                             esdmOp, needT, sigDisp, pidfile, dlock, nlock, 
                             req, startLock, cuseState, cuseSeg, seenGen, 
                             restarts, opc, nc, tc, sc, ec, calls, seen, pend, 
                             owe, needSeen, killed, rmBy, semRm, stack, un, uo, 
                             rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, 
                             cr, cg, wk, av >>

cu3(self) == /\ pc[self] = "cu3"
             /\ cseg' = [cseg EXCEPT ![self] = keyAt]
             /\ cr' = [cr EXCEPT ![self] = keyAt = 0]
             /\ pc' = [pc EXCEPT ![self] = "cu4"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cg, wk, av >>

cu4(self) == /\ pc[self] = "cu4"
             /\ IF cseg[self] = 0 \/ att[cseg[self]] # {} \/ CuseNoRmid
                   THEN /\ pc' = [pc EXCEPT ![self] = "cu6"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cu5"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

cu5(self) == /\ pc[self] = "cu5"
             /\ alive' = [alive EXCEPT ![cseg[self]] = AliveAfterRm(cseg[self])]
             /\ removed' = [removed EXCEPT ![cseg[self]] = TRUE]
             /\ rmBy' = [rmBy EXCEPT ![cseg[self]] = "cuse"]
             /\ IF keyAt = cseg[self]
                   THEN /\ keyAt' = 0
                   ELSE /\ TRUE
                        /\ keyAt' = keyAt
             /\ cseg' = [cseg EXCEPT ![self] = 0]
             /\ cr' = [cr EXCEPT ![self] = TRUE]
             /\ pc' = [pc EXCEPT ![self] = "cu6"]
             /\ UNCHANGED << att, ver, sop, sneed, ssusp, nextSeg, semAt, sval, 
                             nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                             sigDisp, pidfile, dlock, nlock, req, startLock, 
                             cuseState, cuseSeg, cuseSem, seenGen, restarts, 
                             opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                             needSeen, killed, nameOf, semRm, stack, un, uo, 
                             rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cg, 
                             wk, av >>

cu6(self) == /\ pc[self] = "cu6"
             /\ IF cseg[self] = 0 /\ cr[self]
                   THEN /\ IF keyAt = 0
                              THEN /\ Assert(nextSeg <= MaxSeg, 
                                             "Failure of assertion at line 226, column 9 of macro called at line 591, column 26.")
                                   /\ cseg' = [cseg EXCEPT ![self] = nextSeg]
                                   /\ keyAt' = nextSeg
                                   /\ alive' = [alive EXCEPT ![nextSeg] = TRUE]
                                   /\ nextSeg' = nextSeg + 1
                              ELSE /\ cseg' = [cseg EXCEPT ![self] = keyAt]
                                   /\ UNCHANGED << keyAt, alive, nextSeg >>
                   ELSE /\ TRUE
                        /\ UNCHANGED << keyAt, alive, nextSeg, cseg >>
             /\ pc' = [pc EXCEPT ![self] = "cu7"]
             /\ UNCHANGED << removed, att, ver, sop, sneed, ssusp, semAt, sval, 
                             nextSem, srvState, srvSeg, srvSem, esdmOp, needT, 
                             sigDisp, pidfile, dlock, nlock, req, startLock, 
                             cuseState, cuseSeg, cuseSem, seenGen, restarts, 
                             opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                             needSeen, killed, nameOf, rmBy, semRm, stack, un, 
                             uo, rq, en, oseg, nseg, curr, nw, sseg, cn, sid, 
                             cr, cg, wk, av >>

cu7(self) == /\ pc[self] = "cu7"
             /\ IF cseg[self] = 0 \/ ~alive[cseg[self]]
                   THEN /\ cuseSem' = [cuseSem EXCEPT ![self] = 0]
                        /\ cseg' = [cseg EXCEPT ![self] = 0]
                        /\ cr' = [cr EXCEPT ![self] = FALSE]
                        /\ IF ~Overlap
                              THEN /\ startLock' = NoProc
                              ELSE /\ TRUE
                                   /\ UNCHANGED startLock
                        /\ pc' = [pc EXCEPT ![self] = "cu1"]
                        /\ UNCHANGED << att, cuseSeg >>
                   ELSE /\ att' = [att EXCEPT ![cseg[self]] = att[cseg[self]] \cup {self}]
                        /\ cuseSeg' = [cuseSeg EXCEPT ![self] = cseg[self]]
                        /\ cseg' = [cseg EXCEPT ![self] = 0]
                        /\ cr' = [cr EXCEPT ![self] = FALSE]
                        /\ IF ~Overlap
                              THEN /\ startLock' = NoProc
                              ELSE /\ TRUE
                                   /\ UNCHANGED startLock
                        /\ pc' = [pc EXCEPT ![self] = "cu8"]
                        /\ UNCHANGED cuseSem
             /\ UNCHANGED << keyAt, alive, removed, ver, sop, sneed, ssusp, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, cuseState, seenGen, restarts, opc, nc, 
                             tc, sc, ec, calls, seen, pend, owe, needSeen, 
                             killed, nameOf, rmBy, semRm, stack, un, uo, rq, 
                             en, oseg, nseg, curr, nw, sseg, cn, sid, cg, wk, 
                             av >>

cu8(self) == /\ pc[self] = "cu8"
             /\ IF SuspendGen
                   THEN /\ seenGen' = [seenGen EXCEPT ![self] = ssusp[cuseSeg[self]]]
                   ELSE /\ TRUE
                        /\ UNCHANGED seenGen
             /\ cuseState' = [cuseState EXCEPT ![self] = "run"]
             /\ pc' = [pc EXCEPT ![self] = "ck1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseSeg, cuseSem, 
                             restarts, opc, nc, tc, sc, ec, calls, seen, pend, 
                             owe, needSeen, killed, nameOf, rmBy, semRm, stack, 
                             un, uo, rq, en, oseg, nseg, curr, nw, sseg, cn, 
                             sid, cseg, cr, cg, wk, av >>

ck1(self) == /\ pc[self] = "ck1"
             /\ cg' = [cg EXCEPT ![self] = ssusp[cuseSeg[self]]]
             /\ pc' = [pc EXCEPT ![self] = "ck1a"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, wk, av >>

ck1a(self) == /\ pc[self] = "ck1a"
              /\ IF ver[cuseSeg[self]] = Ready
                    THEN /\ seen' = [seen EXCEPT ![self] = <<TRUE, seen[self][2], seen[self][3]>>]
                         /\ pc' = [pc EXCEPT ![self] = "ck1b"]
                    ELSE /\ seen' = [seen EXCEPT ![self] = <<FALSE, FALSE, FALSE>>]
                         /\ pc' = [pc EXCEPT ![self] = "ck1d"]
              /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                              ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                              srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                              dlock, nlock, req, startLock, cuseState, cuseSeg, 
                              cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                              calls, pend, owe, needSeen, killed, nameOf, rmBy, 
                              semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                              nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ck1b(self) == /\ pc[self] = "ck1b"
              /\ seen' = [seen EXCEPT ![self] = <<TRUE, sop[cuseSeg[self]], seen[self][3]>>]
              /\ pc' = [pc EXCEPT ![self] = "ck1c"]
              /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                              ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                              srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                              dlock, nlock, req, startLock, cuseState, cuseSeg, 
                              cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                              calls, pend, owe, needSeen, killed, nameOf, rmBy, 
                              semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                              nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ck1c(self) == /\ pc[self] = "ck1c"
              /\ seen' = [seen EXCEPT ![self] = <<TRUE, seen[self][2], sneed[cuseSeg[self]]>>]
              /\ pc' = [pc EXCEPT ![self] = "ck1d"]
              /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                              ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                              srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                              dlock, nlock, req, startLock, cuseState, cuseSeg, 
                              cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                              calls, pend, owe, needSeen, killed, nameOf, rmBy, 
                              semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                              nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ck1d(self) == /\ pc[self] = "ck1d"
              /\ wk' = [wk EXCEPT ![self] = SuspVisible(self)]
              /\ pc' = [pc EXCEPT ![self] = "ck2"]
              /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                              ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                              srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                              dlock, nlock, req, startLock, cuseState, cuseSeg, 
                              cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                              calls, seen, pend, owe, needSeen, killed, nameOf, 
                              rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                              curr, nw, sseg, cn, sid, cseg, cr, cg, av >>

ck2(self) == /\ pc[self] = "ck2"
             /\ IF wk[self]
                   THEN /\ pend' = [pend EXCEPT ![self] = FALSE]
                   ELSE /\ TRUE
                        /\ pend' = pend
             /\ wk' = [wk EXCEPT ![self] = FALSE]
             /\ IF ~SuspendGen
                   THEN /\ IF cg[self] = 1
                              THEN /\ ssusp' = [ssusp EXCEPT ![cuseSeg[self]] = 0]
                              ELSE /\ TRUE
                                   /\ ssusp' = ssusp
                        /\ cg' = [cg EXCEPT ![self] = 0]
                        /\ pc' = [pc EXCEPT ![self] = "ck3"]
                        /\ UNCHANGED seenGen
                   ELSE /\ seenGen' = [seenGen EXCEPT ![self] = cg[self]]
                        /\ cg' = [cg EXCEPT ![self] = 0]
                        /\ IF ~ExitUnpublish
                              THEN /\ pc' = [pc EXCEPT ![self] = "ck3"]
                              ELSE /\ IF ver[cuseSeg[self]] # Ready
                                         THEN /\ pc' = [pc EXCEPT ![self] = "ck1"]
                                         ELSE /\ pc' = [pc EXCEPT ![self] = "ck4"]
                        /\ ssusp' = ssusp
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             nextSeg, semAt, sval, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, restarts, opc, nc, tc, sc, ec, calls, 
                             seen, owe, needSeen, killed, nameOf, rmBy, semRm, 
                             stack, un, uo, rq, en, oseg, nseg, curr, nw, sseg, 
                             cn, sid, cseg, cr, av >>

ck3(self) == /\ pc[self] = "ck3"
             /\ IF ExitUnpublish /\ ver[cuseSeg[self]] # Ready
                   THEN /\ pc' = [pc EXCEPT ![self] = "ck1"]
                   ELSE /\ ver[cuseSeg[self]] = Ready
                        /\ pc' = [pc EXCEPT ![self] = "ck4"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ck4(self) == /\ pc[self] = "ck4"
             /\ sval[cuseSem[self]] > 0
             /\ sval' = [sval EXCEPT ![cuseSem[self]] = sval[cuseSem[self]] - 1]
             /\ pc' = [pc EXCEPT ![self] = "ck1"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ck(self) == ck0(self) \/ cu1(self) \/ cu2(self) \/ cu3(self) \/ cu4(self)
               \/ cu5(self) \/ cu6(self) \/ cu7(self) \/ cu8(self)
               \/ ck1(self) \/ ck1a(self) \/ ck1b(self) \/ ck1c(self)
               \/ ck1d(self) \/ ck2(self) \/ ck3(self) \/ ck4(self)

ax0(self) == /\ pc[self] = "ax0"
             /\ IF calls[self] < AuxCalls
                   THEN /\ needSeen' = [needSeen EXCEPT ![self] = sneed[1]]
                        /\ pc' = [pc EXCEPT ![self] = "ax1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED needSeen
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, killed, nameOf, rmBy, 
                             semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                             nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ax1(self) == /\ pc[self] = "ax1"
             /\ ver[1] = Ready
             /\ IF sneed[1]
                   THEN /\ pc' = [pc EXCEPT ![self] = "axR"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ax2"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ax2(self) == /\ pc[self] = "ax2"
             /\ \/ /\ sval[LSem] > 0
                   /\ sval' = [sval EXCEPT ![LSem] = sval[LSem] - 1]
                   /\ IF AuxRecheck
                         THEN /\ owe' = [owe EXCEPT ![self] = owe[self] \cup {"L"}]
                         ELSE /\ TRUE
                              /\ owe' = owe
                   /\ pc' = [pc EXCEPT ![self] = "ax3"]
                   /\ calls' = calls
                \/ /\ AuxTimeout
                   /\ calls' = [calls EXCEPT ![self] = calls[self] + 1]
                   /\ pc' = [pc EXCEPT ![self] = "ax0"]
                   /\ UNCHANGED <<sval, owe>>
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             seen, pend, needSeen, killed, nameOf, rmBy, semRm, 
                             stack, un, uo, rq, en, oseg, nseg, curr, nw, sseg, 
                             cn, sid, cseg, cr, cg, wk, av >>

ax3(self) == /\ pc[self] = "ax3"
             /\ IF ~AuxRecheck
                   THEN /\ pc' = [pc EXCEPT ![self] = "axR"]
                        /\ owe' = owe
                   ELSE /\ IF ~sneed[1]
                              THEN /\ owe' = [owe EXCEPT ![self] = owe[self] \ {"L"}]
                                   /\ pc' = [pc EXCEPT ![self] = "ax1"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "ax4"]
                                   /\ owe' = owe
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                             nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ax4(self) == /\ pc[self] = "ax4"
             /\ av' = [av EXCEPT ![self] = sval[LSem]]
             /\ pc' = [pc EXCEPT ![self] = "ax5"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, owe, needSeen, killed, nameOf, 
                             rmBy, semRm, stack, un, uo, rq, en, oseg, nseg, 
                             curr, nw, sseg, cn, sid, cseg, cr, cg, wk >>

ax5(self) == /\ pc[self] = "ax5"
             /\ IF av[self] = 0
                   THEN /\ sval' = [sval EXCEPT ![LSem] = sval[LSem] + 1]
                   ELSE /\ TRUE
                        /\ sval' = sval
             /\ owe' = [owe EXCEPT ![self] = owe[self] \ {"L"}]
             /\ av' = [av EXCEPT ![self] = 0]
             /\ pc' = [pc EXCEPT ![self] = "axR"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, nextSem, srvState, srvSeg, 
                             srvSem, esdmOp, needT, sigDisp, pidfile, dlock, 
                             nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             calls, seen, pend, needSeen, killed, nameOf, rmBy, 
                             semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                             nw, sseg, cn, sid, cseg, cr, cg, wk >>

axR(self) == /\ pc[self] = "axR"
             /\ calls' = [calls EXCEPT ![self] = calls[self] + 1]
             /\ pc' = [pc EXCEPT ![self] = "ax0"]
             /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, 
                             ssusp, nextSeg, semAt, sval, nextSem, srvState, 
                             srvSeg, srvSem, esdmOp, needT, sigDisp, pidfile, 
                             dlock, nlock, req, startLock, cuseState, cuseSeg, 
                             cuseSem, seenGen, restarts, opc, nc, tc, sc, ec, 
                             seen, pend, owe, needSeen, killed, nameOf, rmBy, 
                             semRm, stack, un, uo, rq, en, oseg, nseg, curr, 
                             nw, sseg, cn, sid, cseg, cr, cg, wk, av >>

ax(self) == ax0(self) \/ ax1(self) \/ ax2(self) \/ ax3(self) \/ ax4(self)
               \/ ax5(self) \/ axR(self)

fn1 == /\ pc["fin"] = "fn1"
       /\ Quiescent
       /\ TRUE
       /\ pc' = [pc EXCEPT !["fin"] = "fn1"]
       /\ UNCHANGED << keyAt, alive, removed, att, ver, sop, sneed, ssusp, 
                       nextSeg, semAt, sval, nextSem, srvState, srvSeg, srvSem, 
                       esdmOp, needT, sigDisp, pidfile, dlock, nlock, req, 
                       startLock, cuseState, cuseSeg, cuseSem, seenGen, 
                       restarts, opc, nc, tc, sc, ec, calls, seen, pend, owe, 
                       needSeen, killed, nameOf, rmBy, semRm, stack, un, uo, 
                       rq, en, oseg, nseg, curr, nw, sseg, cn, sid, cseg, cr, 
                       cg, wk, av >>

fin == fn1

Next == srv \/ fin
           \/ (\E self \in ProcSet:  \/ up(self) \/ upCuse(self) \/ wakeAll(self)
                                     \/ setOp(self) \/ setNeed(self)
                                     \/ setSuspend(self) \/ createSem(self))
           \/ (\E self \in DrngProcs: dr(self))
           \/ (\E self \in NeedW: pw(self))
           \/ (\E self \in ThreshProcs: tw(self))
           \/ (\E self \in SigProcs: sg(self))
           \/ (\E self \in EvProcs: ev(self))
           \/ (\E self \in Cuse: ck(self))
           \/ (\E self \in AuxProcs: ax(self))

Spec == /\ Init /\ [][Next]_vars
        /\ /\ WF_vars(srv)
           /\ WF_vars(createSem("srv"))
           /\ WF_vars(setOp("srv"))
           /\ WF_vars(setNeed("srv"))
           /\ WF_vars(upCuse("srv"))
           /\ WF_vars(setSuspend("srv"))
           /\ WF_vars(up("srv"))
           /\ WF_vars(wakeAll("srv"))
        /\ \A self \in DrngProcs : /\ WF_vars(dr(self))
                                   /\ WF_vars(setOp(self))
                                   /\ WF_vars(up(self))
                                   /\ WF_vars(upCuse(self))
        /\ \A self \in NeedW : /\ WF_vars(pw(self))
                               /\ WF_vars(setNeed(self))
                               /\ WF_vars(up(self))
                               /\ WF_vars(upCuse(self))
        /\ \A self \in ThreshProcs : /\ WF_vars(tw(self))
                                     /\ WF_vars(setNeed(self))
                                     /\ WF_vars(up(self))
                                     /\ WF_vars(upCuse(self))
        /\ \A self \in SigProcs : WF_vars(sg(self))
        /\ \A self \in EvProcs : /\ WF_vars(ev(self))
                                 /\ WF_vars(setSuspend(self))
                                 /\ WF_vars(up(self))
                                 /\ WF_vars(upCuse(self))
                                 /\ WF_vars(wakeAll(self))
        /\ \A self \in Cuse : WF_vars(ck(self))
        /\ \A self \in AuxProcs : WF_vars(ax(self))

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ keyAt \in 0..MaxSeg
    /\ srvSeg \in 0..MaxSeg
    /\ cuseSeg \in [Cuse -> 0..MaxSeg]
    /\ cuseSem \in [Cuse -> 0..MaxSem]
    /\ ver \in [Segs -> {0, Ready}]
    /\ ssusp \in [Segs -> Nat]
    /\ sval \in [Sems -> Nat]
    /\ seen \in [Cuse -> BOOLEAN \X BOOLEAN \X BOOLEAN]
    /\ sigDisp \in {"default", "ignore", "handler"}
    /\ srvState \in {"down", "init", "up", "exit"}
    /\ \A p \in Procs : owe[p] \subseteq Names

\* The semaphores of the CUSE daemons toggle between 0 and 1, as
\* _esdm_shm_status_up() means them to: only the server posts them.
SemBinary == \A o \in Sems : nameOf[o] \in Cuse => sval[o] <= 1

\* The level-triggered semaphore does not: an aux client passing the wakeup
\* on posts it too, and its sem_getvalue() and sem_post() are not combined
\* with the server's. A woken client checks the flag, so a value above 1
\* costs wakeups and no more.
LevelSemBinary == \A o \in Sems : nameOf[o] = "L" => sval[o] <= 1

\* Once the threads publishing a state are idle, the segment shows it.
OpFresh ==
    (srvState = "up" /\ \A d \in DrngProcs : pc[d] = "dr1")
        => sop[srvSeg] = esdmOp
NeedIdle == /\ \A w \in NeedW : pc[w] = "wn1"
            /\ \A t \in ThreshProcs : pc[t] = "tw1"
NeedFresh == (srvState = "up" /\ NeedIdle) => sneed[srvSeg] = needT

\* A segment showing the ready version shows this server's state once its
\* threads are idle, whoever wrote the segment before: the initialization
\* refreshes every field before the version (esdm_shm_status_init()).
StatusFresh ==
    (/\ srvSeg # 0
     /\ ver[srvSeg] = Ready
     /\ \A d \in DrngProcs : pc[d] = "dr1"
     /\ NeedIdle)
        => Content(srvSeg) = <<esdmOp, needT>>

\* A poll checker waits on its semaphore only if it saw what its poll mask
\* follows, or a writer has stored a change and still has to post: the
\* version, the operational state and the need for entropy, the suspend
\* notification.
Owed(n) == (\E p \in Procs : n \in owe[p]) \/ req[n] > 0
Blocked(d) ==
    /\ cuseState[d] = "run"
    /\ pc[d] = "ck4"
    /\ sval[cuseSem[d]] = 0
    /\ ~Owed(d)
NoLostVersion ==
    \A d \in Cuse : Blocked(d) => seen[d][1] = (ver[cuseSeg[d]] = Ready)
NoLostStatus ==
    \A d \in Cuse :
        (Blocked(d) /\ seen[d][1] /\ ver[cuseSeg[d]] = Ready)
            => seen[d] = View(cuseSeg[d])
NoLostSuspend ==
    \A d \in Cuse : Blocked(d) => ~pend[d] /\ ~SuspVisible(d)
NoLostWakeup == NoLostVersion /\ NoLostStatus /\ NoLostSuspend

\* A writer that is idle owes no post: every store is followed by its posts.
NoOwedIdle ==
    /\ pc["srv"] = "svUp" => owe["srv"] = {}
    /\ \A d \in DrngProcs : pc[d] = "dr1" => owe[d] = {}
    /\ \A w \in NeedW : pc[w] = "wn1" => owe[w] = {}
    /\ \A t \in ThreshProcs : pc[t] = "tw1" => owe[t] = {}
    /\ \A e \in EvProcs : pc[e] = "ev1" => owe[e] = {}
    /\ \A a \in AuxProcs :
           pc[a] \in {"ax0", "ax1", "ax2", "axR", "Done"} => owe[a] = {}

\* A CUSE daemon and a running server use the same segment and semaphore.
Connected ==
    \A d \in Cuse :
        (srvState = "up" /\ cuseState[d] = "run")
            => cuseSeg[d] = srvSeg /\ cuseSem[d] = srvSem[d]

\* An aux client sleeps on the level semaphore only while the ESDM does not
\* need entropy, or a writer still has to post it.
AuxNoLostWakeup ==
    \A a \in AuxProcs :
        (pc[a] = "ax2" /\ sval[LSem] = 0 /\ sneed[1])
            => \E p \in Procs : "L" \in owe[p]

\* An aux client is told to deliver entropy only if the segment showed the
\* need during its call.
AuxSpurious == \A a \in AuxProcs : pc[a] = "axR" => needSeen[a]

\* A suspend signal does not end the server.
SuspendKills == ~killed

-----------------------------------------------------------------------------
(* Liveness, under weak fairness of every process *)

\* The system reaches the final state and stays: the server is up, every
\* change is published, every checker has seen it and waits, every aux
\* client is done or waits without a need.
Settles == <>[]Quiescent

\* Once the server and its threads are done changing the status, the
\* checkers have seen it.
Synced ==
    /\ srvState = "up"
    /\ \A d \in Cuse : /\ cuseState[d] = "run"
                       /\ cuseSeg[d] = srvSeg
                       /\ seen[d] = View(srvSeg)
                       /\ ~pend[d]
EventuallySynced == <>[]Synced

\* A suspend notification reaches the poller of every CUSE daemon.
SuspendReaches == \A d \in Cuse : pend[d] ~> ~pend[d]

\* While the need lasts, a waiting aux client returns.
AuxWoken ==
    \A a \in AuxProcs :
        (pc[a] = "ax2" /\ sneed[1]) ~> (pc[a] = "axR" \/ ~sneed[1])
=============================================================================
