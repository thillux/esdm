----------------------------- MODULE EsdmSelftest -----------------------------
(***************************************************************************)
(* The self test gate on the output of the ESDM: esdm/esdm_selftest.c,     *)
(* the verdict it records and the periodic self test worker, and the       *)
(* callers that depend on it in esdm/esdm_drng_mgr.c and esdm/esdm_lib.c,  *)
(* at the granularity of their locks and atomics. One step is one atomic   *)
(* variable access or one statement of a critical section where the        *)
(* verdict is read in it; the labels name the C functions they come from.  *)
(*                                                                         *)
(* The verdict is an atomic that esdm_selftest_record() writes without     *)
(* any lock. Every reader therefore checks it in one step and acts on it   *)
(* in a later one: the check of a chunk, its generation, the check after   *)
(* it and its handing out are four steps of esdm_drng_get(), the entry     *)
(* check of a seeding, its collection, the check before the injection and  *)
(* the injection four steps of esdm_drng_seed_es(). What the properties    *)
(* state is what such a reader can deliver: nothing produced after the     *)
(* failure was recorded is handed out; a failure recorded after a check    *)
(* does not stop what that check let through.                              *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - The crypto implementations either work or are broken; the             *)
(*   environment may break them once at any time. A self test of a broken  *)
(*   implementation fails, of a working one passes.                        *)
(* - One DRNG lock stands for the lock of the DRNG a request, a seeding    *)
(*   and esdm_selftest_crypto() take; esdm_node_cleanup_lock is a          *)
(*   reader-preferring lock: readers wait for a writer holding it only.    *)
(* - esdm_drng_get() is reduced to its gates and its chunks, each one      *)
(*   generate under the DRNG lock; esdm_get_seed() to its gates and the    *)
(*   collection it hands out. The generation of a chunk and a collection   *)
(*   are one step each: the moment they end.                               *)
(* - A seeding is esdm_drng_seed(): the DRNG lock held across the          *)
(*   collection and the injection. esdm_drng_reseed_seed_locked() collects *)
(*   before it takes the lock; its checks are in the same order.           *)
(* - The ESDM becomes operational with esdm_init() (SeedAtInit), or with   *)
(*   the first injection once the environment delivered entropy; it does   *)
(*   not leave that state. A blocking request (Blocking) is                *)
(*   esdm_get_random_bytes_full(): esdm_drng_sleep_while_nonoperational()  *)
(*   and then esdm_drng_get(). thread_wait_event() polls its condition     *)
(*   every 100 ms and needs no wakeup: it is one step enabled by the       *)
(*   condition. esdm_drng_sleep_while_not_all_nodes_seeded() has the same  *)
(*   shape and is not modelled apart.                                      *)
(* - The worker's timed waits are one wait until the next pass is due or   *)
(*   it is asked to leave; the environment makes the pass due after the    *)
(*   interval. The worker has one thread slot (its special thread group):  *)
(*   thread_start() waits while the slot is busy, or fails where           *)
(*   ThreadFail says so; without Threads, thread_available() is false.     *)
(* - Of the entropy source self tests only the one of the auxiliary pool   *)
(*   is modelled: whether its XOF context is there, which esdm_aux_init()  *)
(*   replaces in esdm_reinit().                                            *)
(* - Not modelled: the seeding state beyond operational, the request and   *)
(*   reseed logic of EsdmReseed, the release of the DRNG state in          *)
(*   esdm_fini() and the check for it in esdm_drng_get(), the reseed       *)
(*   worker's own stop request, the shared memory status and the log       *)
(*   messages.                                                             *)
(* - Every thread but the worker and the environment is bounded, and the   *)
(*   environment acts a bounded number of times unless a worker is on      *)
(*   duty: the interval passes once per self test pass, the                *)
(*   implementations break once. Entropy for a full seed arrives once, at  *)
(*   some time (a process of its own, so that fairness makes it arrive).   *)
(*   When every bounded thread returned and no worker is on duty, the      *)
(*   environment idles: the only state without a successor that is not a   *)
(*   deadlock. Every process is weakly fair.                               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Req,          \* threads requesting random bits, esdm_drng_get()
    Chunks,       \* chunks of a request
    MaxReq,       \* requests per thread
    Blocking,     \* the requests wait for the ESDM to become operational:
                  \* esdm_get_random_bytes_full()
    SeedCallers,  \* threads calling esdm_get_seed()
    OnDemand,     \* threads running esdm_selftest_run() (the RPC self test)
    InitMonitor,  \* esdm_init_monitor() starts the periodic self tests
    SeedAtInit,   \* esdm_init() finds the entropy to seed with; otherwise
                  \* the first injection after entropy arrived does
    Reseeder,     \* the reseed worker seeds MaxReseeds times
    MaxReseeds,
    Reinit,       \* esdm_reinit() runs once
    Fini,         \* esdm_fini() runs once
    CanBreak,     \* the crypto implementations may break
    Threads,      \* thread_available(): the process has a thread pool
    ThreadFail,   \* thread_start() may fail
    \* the fixes, FALSE for the code before them:
    GateEachChunk, \* the verdict is checked under the DRNG lock before every
                   \* chunk, and before esdm_get_seed() hands out
    RecheckChunk, \* ... and again after the chunk is generated: one
                  \* generated meanwhile is wiped
    GateSeeding,  \* a recorded failure stops the seedings and the reseed
                  \* worker
    WaitGate,     \* ... and ends the wait for the ESDM to become operational
    EsLocked      \* esdm_aux_selftest() reads under the pool lock

NoProc == "none"
InitProcs == {"init"}
ReseedProcs == IF Reseeder THEN {"reseed"} ELSE {}
ReinitProcs == IF Reinit THEN {"reinit"} ELSE {}
FiniProcs == IF Fini THEN {"fini"} ELSE {}
\* the threads that finish
Finite == InitProcs \cup Req \cup SeedCallers \cup OnDemand \cup ReseedProcs
          \cup ReinitProcs \cup FiniProcs
AllProcs == Finite \cup {"pw", "ent", "env"}

(* --algorithm EsdmSelftest {
variables
    result = "undone",      \* esdm_selftest_result
    esResult = "undone",    \* esdm_es_selftest_result
    active = FALSE,         \* esdm_selftest_worker_active
    slot = FALSE,           \* the worker's thread slot is in use
    terminate = FALSE,      \* esdm_selftest_worker_terminate
    mgrTerminate = FALSE,   \* esdm_drng_mgr_terminate
    due = TRUE,             \* esdm_selftest_due(), no pass recorded yet
    avail = FALSE,          \* esdm_get_available()
    operational = FALSE,    \* esdm_state_operational()
    entropy = SeedAtInit,   \* the entropy sources deliver a full seed
    initFailed = FALSE,     \* esdm_init() failed
    broken = FALSE,
    drngLock = NoProc,      \* drng->lock
    readers = {},           \* esdm_node_cleanup_lock held for reading
    writer = NoProc,        \* ... and for writing
    xof = TRUE,             \* esdm_pools[0].xdrbg.xof is there
    poolLock = NoProc,      \* esdm_pools[0].lock
    \* ghosts: a failing self test was recorded; esdm_fini() joined the
    \* threads; the worker in the slot started after it was asked to leave;
    \* properties violated
    failRec = FALSE,
    joined = FALSE,
    lateWorker = FALSE,
    viol = {};

\* esdm_selftest_crypto()
procedure crypto()
    variables tret = FALSE;
{
     \* esdm_drng_node_instance(): esdm_drng_get_instances()
cr0: await writer = NoProc;
     readers := readers \cup {self};
     \* hash_selftest() and esdm_xdrbg_selftest(), unlocked
cr1: if (broken) {
         tret := TRUE;
         goto cr3;
     };
     \* drng_selftest() under drng->lock
cr2: await drngLock = NoProc;
     tret := broken;
     \* esdm_drng_put_instances(), then esdm_selftest_record(), under no
     \* lock: a failure by atomic_exchange(), a pass by
     \* atomic_compare_exchange_strong() from undone
cr3: readers := readers \ {self};
     if (tret) {
         result := "failed";
         failRec := TRUE;
     } else if (result = "undone") {
         result := "passed";
     };
     return;
}

\* esdm_selftest_es() with the auxiliary pool's esdm_aux_selftest()
procedure es()
    variables esFail = FALSE;
{
es1: if (EsLocked) await poolLock = NoProc;
     esFail := ~xof;
     \* atomic_store() of the verdict; no source breaks in this model
es2: esResult := IF esFail THEN "failed" ELSE "passed";
     if (esFail) viol := viol \cup {"EsSpurious"};
     return;
}

\* esdm_selftest_run(); the entropy source self tests only where
\* esdm_reinit() can make one fail
procedure run()
{
ru1: call crypto();
ru2: if (Reinit) call es();
     \* esdm_selftest_last_pass stamped: the next pass is due later
ru3: due := FALSE;
     return;
}

\* esdm_selftest_periodic_start(). esdm_selftest_stop() also reads
\* esdm_drng_mgr_terminate, which esdm_fini() sets after terminate and never
\* withdraws: terminate decides.
procedure start()
{
ps1: if (terminate \/ active \/ ~Threads) return;
     \* atomic_exchange()
ps3: if (active) {
         return;
     } else {
         active := TRUE;
     };
     \* thread_start(): waits for the slot, or fails
ps4: either {
         await ~slot;
         slot := TRUE;
         return;
     } or {
         await ThreadFail;
     };
ps5: active := FALSE;
     return;
}

\* A seeding, esdm_drng_seed() with esdm_drng_seed_es(), of the initial
\* DRNG. failLock and failColl are ghosts: a failure was recorded when the
\* lock was taken, when the collection ended.
procedure seed()
    variables failLock = FALSE, failColl = FALSE;
{
     \* __esdm_drng_seed_work(): nothing to seed before esdm_init()
sd0: if (~avail) return;
sd1: await drngLock = NoProc;
     drngLock := self;
     failLock := (result = "failed");
     \* the check at the entry of esdm_drng_seed_es()
sd2: if (GateSeeding /\ result = "failed") goto sd6;
     \* esdm_get_seed_buffers(): the entropy sources drained and conditioned
     \* with the hash
sd3: if (failLock) viol := viol \cup {"Collect"};
     failColl := (result = "failed");
     \* the check before the injection
sd4: if (GateSeeding /\ result = "failed") goto sd6;
     \* esdm_drng_inject(), and esdm_init_ops() where the seed is a full one
sd5: viol := viol \cup (IF failColl THEN {"Inject"} ELSE {})
                  \cup (IF result = "failed" THEN {"InjectLate"} ELSE {});
     if (entropy) operational := TRUE;
sd6: drngLock := NoProc;
     return;
}

\* esdm_init(), then esdm_init_monitor()
fair process (ini \in InitProcs)
{
     \* esdm_drng_mgr_initialize()
in1: call crypto();
in2: if (result # "passed") {
         initFailed := TRUE;
         goto Done;
     } else {
         \* esdm_es_mgr_initialize() seeds the DRNGs where there is entropy
         avail := TRUE;
         operational := SeedAtInit;
     };
     \* the initial self test pass
in3: call run();
in4: if (InitMonitor) call start();
}

\* A request: esdm_get_random_bytes_full() where Blocking, with
\* esdm_drng_get_sleep() and esdm_drng_get(). late and failLk are ghosts: the
\* chunk was generated without a passed verdict; the verdict as it was one
\* step before the check that follows.
fair process (r \in Req)
    variables nr = 0, c = 0, ret = "none", late = FALSE, failLk = FALSE;
{
rq0: while (nr < MaxReq) {
         nr := nr + 1;
         failLk := (Blocking /\ result = "failed");
wt0:     if (Blocking) {
             \* esdm_drng_sleep_while_nonoperational(): nothing seeds after
             \* a failure, nothing to wait for
wt1:         if (WaitGate /\ result = "failed") goto rq0;
             \* esdm_force_fully_seeded()
wt2:         await writer = NoProc;
             readers := readers \cup {self};
             if (failLk) viol := viol \cup {"Wait"};
wt3:         call seed();
wt4:         readers := readers \ {self};
wt5:         if (~operational) {
                 \* thread_wait_event(): polled, no wakeup needed
wt6:             await operational \/ mgrTerminate
                       \/ (WaitGate /\ result = "failed");
                 failLk := (result = "failed");
wt7:             if (WaitGate /\ result = "failed") goto rq0;
             };
         };
         \* esdm_drng_get_instances()
rq1:     await writer = NoProc;
         readers := readers \cup {self};
         ret := "none";
         if (failLk) viol := viol \cup {"Wait"};
         failLk := (result = "failed");
         \* the gates at the entry of esdm_drng_get()
rq2:     if (~operational) {
             ret := IF Blocking THEN "notsupp" ELSE "none";
             goto rq5;
         };
rq3:     if (result # "passed") {
             goto rq5;
         } else {
             if (failLk) viol := viol \cup {"Entry"};
             c := Chunks;
             call start();
         };
rq4:     while (c > 0) {
             \* a chunk: drng->lock
             await drngLock = NoProc;
             drngLock := self;
             failLk := (result # "passed");
             \* the check under the lock
rq4a:        if (GateEachChunk /\ result # "passed") {
                 c := 0;
                 drngLock := NoProc;
                 goto rq5;
             };
             \* drng_generate()
rq4b:        if (failLk) viol := viol \cup {"Generate"};
             late := (result # "passed");
             \* the check after it: the chunk is wiped; the lock released
rq4c:        drngLock := NoProc;
             if (RecheckChunk /\ result # "passed") {
                 c := 0;
                 goto rq5;
             };
             \* the chunk is part of what the request returns
rq4d:        viol := viol \cup (IF late THEN {"Output"} ELSE {})
                          \cup (IF result # "passed" THEN {"OutputLate"}
                                ELSE {});
             c := c - 1;
         };
         \* esdm_drng_put_instances()
rq5:     readers := readers \ {self};
         \* esdm_get_random_bytes_full(): the ESDM stopped since the wait -
         \* wait again, unless it terminates or a self test failed
rq6:     if (ret = "notsupp" /\ ~mgrTerminate /\ result = "passed") {
             ret := "none";
             failLk := FALSE;
             goto wt1;
         };
     };
}

\* esdm_get_seed(); gLate is a ghost: called after a recorded failure, then
\* collected without a passed verdict
fair process (g \in SeedCallers)
    variables gLate = FALSE;
{
gs0: gLate := (result = "failed");
gs1: if (result # "passed") goto Done;
     \* the collection, esdm_get_seed_buffers()
gs2: if (gLate) viol := viol \cup {"Entry"};
     gLate := (result # "passed");
     \* the check after it: the seed is wiped
gs3: if (GateEachChunk /\ result # "passed") goto Done;
     \* the seed is handed out
gs4: viol := viol \cup (IF gLate THEN {"Output"} ELSE {})
                  \cup (IF result # "passed" THEN {"OutputLate"} ELSE {});
}

\* the privileged RPC self test, esdm_rpc_selftest()
fair process (o \in OnDemand)
{
od1: call run();
}

\* the reseed worker, started by esdm_init_monitor() and woken when entropy
\* arrived or a self test failed. failPrev is a ghost: a failure was
\* recorded when the previous seeding ended.
fair process (rs \in ReseedProcs)
    variables ns = 0, failPrev = FALSE;
{
rs0: await pc["init"] = "Done" /\ (initFailed \/ entropy \/ result = "failed");
     failPrev := (result = "failed");
     if (initFailed) goto Done;
     \* esdm_drng_reseed_stop(): a recorded failure, not one undone, ends it
rs1: while (ns < MaxReseeds /\ ~(GateSeeding /\ result = "failed")) {
         ns := ns + 1;
rs2:     if (failPrev) viol := viol \cup {"Worker"};
         call seed();
rs3:     failPrev := (result = "failed");
     };
}

\* esdm_reinit(), once esdm_init() returned
fair process (ri \in ReinitProcs)
{
     \* esdm_drng_mgr_reinitialize()
ri0: await pc["init"] = "Done";
     if (initFailed) {
         goto Done;
     } else {
         call crypto();
     };
     \* esdm_es_mgr_reinitialize(): esdm_aux_init() replaces the XOF context
     \* under the pool lock, esdm_xdrbg_zero_free() then esdm_xdrbg_alloc()
ri1: await poolLock = NoProc;
     poolLock := self;
     xof := FALSE;
ri2: xof := TRUE;
     poolLock := NoProc;
ri3: call run();
}

\* esdm_fini(), once esdm_init() returned
fair process (fi \in FiniProcs)
{
     \* esdm_selftest_periodic_stop()
fi0: await pc["init"] = "Done";
     terminate := TRUE;
     \* esdm_es_mgr_finalize(): thread_wait_all() joins the worker
fi1: await ~slot;
     joined := TRUE;
     \* esdm_drng_mgr_finalize()
fi2: mgrTerminate := TRUE;
     \* esdm_node_fini(): the DRNGs released under their locks
fi3: await readers = {} /\ writer = NoProc;
     writer := self;
fi4: await drngLock = NoProc;
     writer := NoProc;
}

\* esdm_periodic_selftest_worker() in the thread slot
fair process (pw = "pw")
{
pw0: while (TRUE) {
         await slot;
         lateWorker := terminate;
pw1:     while (~terminate) {
             await due \/ terminate;
             if (terminate) {
                 goto pw4;
             } else {
                 if (lateWorker) viol := viol \cup {"LateRun"};
                 call run();
             };
             \* a failure is not recovered from: the worker leaves
pw3:         if (result # "passed") goto pw4;
         };
pw4:     active := FALSE;
pw5:     slot := FALSE;
     };
}

\* the entropy sources come to deliver a full seed, at some time
fair process (ea = "ent")
{
ea0: await ~entropy;
     entropy := TRUE;
}

\* the interval passing and the implementations breaking; idle when every
\* bounded thread returned and no worker is on duty
fair process (en = "env")
{
en0: while (TRUE) {
         either {
             await ~due;
             due := TRUE;
         } or {
             await CanBreak /\ ~broken;
             broken := TRUE;
         } or {
             await /\ \A p \in Finite : pc[p] = "Done"
                   /\ pc["pw"] = "pw0" /\ ~slot;
             skip;
         };
     };
}

} *)
\* BEGIN TRANSLATION
VARIABLES result, esResult, active, slot, terminate, mgrTerminate, due, avail, 
          operational, entropy, initFailed, broken, drngLock, readers, writer, 
          xof, poolLock, failRec, joined, lateWorker, viol, pc, stack, tret, 
          esFail, failLock, failColl, nr, c, ret, late, failLk, gLate, ns, 
          failPrev

vars == << result, esResult, active, slot, terminate, mgrTerminate, due, 
           avail, operational, entropy, initFailed, broken, drngLock, readers, 
           writer, xof, poolLock, failRec, joined, lateWorker, viol, pc, 
           stack, tret, esFail, failLock, failColl, nr, c, ret, late, failLk, 
           gLate, ns, failPrev >>

ProcSet == (InitProcs) \cup (Req) \cup (SeedCallers) \cup (OnDemand) \cup (ReseedProcs) \cup (ReinitProcs) \cup (FiniProcs) \cup {"pw"} \cup {"ent"} \cup {"env"}

Init == (* Global variables *)
        /\ result = "undone"
        /\ esResult = "undone"
        /\ active = FALSE
        /\ slot = FALSE
        /\ terminate = FALSE
        /\ mgrTerminate = FALSE
        /\ due = TRUE
        /\ avail = FALSE
        /\ operational = FALSE
        /\ entropy = SeedAtInit
        /\ initFailed = FALSE
        /\ broken = FALSE
        /\ drngLock = NoProc
        /\ readers = {}
        /\ writer = NoProc
        /\ xof = TRUE
        /\ poolLock = NoProc
        /\ failRec = FALSE
        /\ joined = FALSE
        /\ lateWorker = FALSE
        /\ viol = {}
        (* Procedure crypto *)
        /\ tret = [ self \in ProcSet |-> FALSE]
        (* Procedure es *)
        /\ esFail = [ self \in ProcSet |-> FALSE]
        (* Procedure seed *)
        /\ failLock = [ self \in ProcSet |-> FALSE]
        /\ failColl = [ self \in ProcSet |-> FALSE]
        (* Process r *)
        /\ nr = [self \in Req |-> 0]
        /\ c = [self \in Req |-> 0]
        /\ ret = [self \in Req |-> "none"]
        /\ late = [self \in Req |-> FALSE]
        /\ failLk = [self \in Req |-> FALSE]
        (* Process g *)
        /\ gLate = [self \in SeedCallers |-> FALSE]
        (* Process rs *)
        /\ ns = [self \in ReseedProcs |-> 0]
        /\ failPrev = [self \in ReseedProcs |-> FALSE]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in InitProcs -> "in1"
                                        [] self \in Req -> "rq0"
                                        [] self \in SeedCallers -> "gs0"
                                        [] self \in OnDemand -> "od1"
                                        [] self \in ReseedProcs -> "rs0"
                                        [] self \in ReinitProcs -> "ri0"
                                        [] self \in FiniProcs -> "fi0"
                                        [] self = "pw" -> "pw0"
                                        [] self = "ent" -> "ea0"
                                        [] self = "env" -> "en0"]

cr0(self) == /\ pc[self] = "cr0"
             /\ writer = NoProc
             /\ readers' = (readers \cup {self})
             /\ pc' = [pc EXCEPT ![self] = "cr1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, writer, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

cr1(self) == /\ pc[self] = "cr1"
             /\ IF broken
                   THEN /\ tret' = [tret EXCEPT ![self] = TRUE]
                        /\ pc' = [pc EXCEPT ![self] = "cr3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cr2"]
                        /\ tret' = tret
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

cr2(self) == /\ pc[self] = "cr2"
             /\ drngLock = NoProc
             /\ tret' = [tret EXCEPT ![self] = broken]
             /\ pc' = [pc EXCEPT ![self] = "cr3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

cr3(self) == /\ pc[self] = "cr3"
             /\ readers' = readers \ {self}
             /\ IF tret[self]
                   THEN /\ result' = "failed"
                        /\ failRec' = TRUE
                   ELSE /\ IF result = "undone"
                              THEN /\ result' = "passed"
                              ELSE /\ TRUE
                                   /\ UNCHANGED result
                        /\ UNCHANGED failRec
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ tret' = [tret EXCEPT ![self] = Head(stack[self]).tret]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << esResult, active, slot, terminate, mgrTerminate, 
                             due, avail, operational, entropy, initFailed, 
                             broken, drngLock, writer, xof, poolLock, joined, 
                             lateWorker, viol, esFail, failLock, failColl, nr, 
                             c, ret, late, failLk, gLate, ns, failPrev >>

crypto(self) == cr0(self) \/ cr1(self) \/ cr2(self) \/ cr3(self)

es1(self) == /\ pc[self] = "es1"
             /\ IF EsLocked
                   THEN /\ poolLock = NoProc
                   ELSE /\ TRUE
             /\ esFail' = [esFail EXCEPT ![self] = ~xof]
             /\ pc' = [pc EXCEPT ![self] = "es2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

es2(self) == /\ pc[self] = "es2"
             /\ esResult' = IF esFail[self] THEN "failed" ELSE "passed"
             /\ IF esFail[self]
                   THEN /\ viol' = (viol \cup {"EsSpurious"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ esFail' = [esFail EXCEPT ![self] = Head(stack[self]).esFail]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, active, slot, terminate, mgrTerminate, 
                             due, avail, operational, entropy, initFailed, 
                             broken, drngLock, readers, writer, xof, poolLock, 
                             failRec, joined, lateWorker, tret, failLock, 
                             failColl, nr, c, ret, late, failLk, gLate, ns, 
                             failPrev >>

es(self) == es1(self) \/ es2(self)

ru1(self) == /\ pc[self] = "ru1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "crypto",
                                                      pc        |->  "ru2",
                                                      tret      |->  tret[self] ] >>
                                                  \o stack[self]]
             /\ tret' = [tret EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "cr0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             esFail, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

ru2(self) == /\ pc[self] = "ru2"
             /\ IF Reinit
                   THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "es",
                                                                 pc        |->  "ru3",
                                                                 esFail    |->  esFail[self] ] >>
                                                             \o stack[self]]
                        /\ esFail' = [esFail EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "es1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ru3"]
                        /\ UNCHANGED << stack, esFail >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

ru3(self) == /\ pc[self] = "ru3"
             /\ due' = FALSE
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

run(self) == ru1(self) \/ ru2(self) \/ ru3(self)

ps1(self) == /\ pc[self] = "ps1"
             /\ IF terminate \/ active \/ ~Threads
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ps3"]
                        /\ stack' = stack
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

ps3(self) == /\ pc[self] = "ps3"
             /\ IF active
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED active
                   ELSE /\ active' = TRUE
                        /\ pc' = [pc EXCEPT ![self] = "ps4"]
                        /\ stack' = stack
             /\ UNCHANGED << result, esResult, slot, terminate, mgrTerminate, 
                             due, avail, operational, entropy, initFailed, 
                             broken, drngLock, readers, writer, xof, poolLock, 
                             failRec, joined, lateWorker, viol, tret, esFail, 
                             failLock, failColl, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

ps4(self) == /\ pc[self] = "ps4"
             /\ \/ /\ ~slot
                   /\ slot' = TRUE
                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                \/ /\ ThreadFail
                   /\ pc' = [pc EXCEPT ![self] = "ps5"]
                   /\ UNCHANGED <<slot, stack>>
             /\ UNCHANGED << result, esResult, active, terminate, mgrTerminate, 
                             due, avail, operational, entropy, initFailed, 
                             broken, drngLock, readers, writer, xof, poolLock, 
                             failRec, joined, lateWorker, viol, tret, esFail, 
                             failLock, failColl, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

ps5(self) == /\ pc[self] = "ps5"
             /\ active' = FALSE
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, esResult, slot, terminate, mgrTerminate, 
                             due, avail, operational, entropy, initFailed, 
                             broken, drngLock, readers, writer, xof, poolLock, 
                             failRec, joined, lateWorker, viol, tret, esFail, 
                             failLock, failColl, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

start(self) == ps1(self) \/ ps3(self) \/ ps4(self) \/ ps5(self)

sd0(self) == /\ pc[self] = "sd0"
             /\ IF ~avail
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ failLock' = [failLock EXCEPT ![self] = Head(stack[self]).failLock]
                        /\ failColl' = [failColl EXCEPT ![self] = Head(stack[self]).failColl]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "sd1"]
                        /\ UNCHANGED << stack, failLock, failColl >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, nr, c, ret, late, failLk, gLate, ns, 
                             failPrev >>

sd1(self) == /\ pc[self] = "sd1"
             /\ drngLock = NoProc
             /\ drngLock' = self
             /\ failLock' = [failLock EXCEPT ![self] = (result = "failed")]
             /\ pc' = [pc EXCEPT ![self] = "sd2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, readers, writer, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

sd2(self) == /\ pc[self] = "sd2"
             /\ IF GateSeeding /\ result = "failed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "sd6"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "sd3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

sd3(self) == /\ pc[self] = "sd3"
             /\ IF failLock[self]
                   THEN /\ viol' = (viol \cup {"Collect"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ failColl' = [failColl EXCEPT ![self] = (result = "failed")]
             /\ pc' = [pc EXCEPT ![self] = "sd4"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, stack, 
                             tret, esFail, failLock, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

sd4(self) == /\ pc[self] = "sd4"
             /\ IF GateSeeding /\ result = "failed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "sd6"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "sd5"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

sd5(self) == /\ pc[self] = "sd5"
             /\ viol' = (viol \cup (IF failColl[self] THEN {"Inject"} ELSE {})
                              \cup (IF result = "failed" THEN {"InjectLate"} ELSE {}))
             /\ IF entropy
                   THEN /\ operational' = TRUE
                   ELSE /\ TRUE
                        /\ UNCHANGED operational
             /\ pc' = [pc EXCEPT ![self] = "sd6"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, entropy, initFailed, 
                             broken, drngLock, readers, writer, xof, poolLock, 
                             failRec, joined, lateWorker, stack, tret, esFail, 
                             failLock, failColl, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

sd6(self) == /\ pc[self] = "sd6"
             /\ drngLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ failLock' = [failLock EXCEPT ![self] = Head(stack[self]).failLock]
             /\ failColl' = [failColl EXCEPT ![self] = Head(stack[self]).failColl]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, readers, writer, xof, 
                             poolLock, failRec, joined, lateWorker, viol, tret, 
                             esFail, nr, c, ret, late, failLk, gLate, ns, 
                             failPrev >>

seed(self) == sd0(self) \/ sd1(self) \/ sd2(self) \/ sd3(self) \/ sd4(self)
                 \/ sd5(self) \/ sd6(self)

in1(self) == /\ pc[self] = "in1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "crypto",
                                                      pc        |->  "in2",
                                                      tret      |->  tret[self] ] >>
                                                  \o stack[self]]
             /\ tret' = [tret EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "cr0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             esFail, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

in2(self) == /\ pc[self] = "in2"
             /\ IF result # "passed"
                   THEN /\ initFailed' = TRUE
                        /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << avail, operational >>
                   ELSE /\ avail' = TRUE
                        /\ operational' = SeedAtInit
                        /\ pc' = [pc EXCEPT ![self] = "in3"]
                        /\ UNCHANGED initFailed
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, entropy, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, joined, 
                             lateWorker, viol, stack, tret, esFail, failLock, 
                             failColl, nr, c, ret, late, failLk, gLate, ns, 
                             failPrev >>

in3(self) == /\ pc[self] = "in3"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "run",
                                                      pc        |->  "in4" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "ru1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

in4(self) == /\ pc[self] = "in4"
             /\ IF InitMonitor
                   THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "start",
                                                                 pc        |->  "Done" ] >>
                                                             \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ps1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ stack' = stack
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

ini(self) == in1(self) \/ in2(self) \/ in3(self) \/ in4(self)

rq0(self) == /\ pc[self] = "rq0"
             /\ IF nr[self] < MaxReq
                   THEN /\ nr' = [nr EXCEPT ![self] = nr[self] + 1]
                        /\ failLk' = [failLk EXCEPT ![self] = (Blocking /\ result = "failed")]
                        /\ pc' = [pc EXCEPT ![self] = "wt0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << nr, failLk >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, c, ret, 
                             late, gLate, ns, failPrev >>

wt0(self) == /\ pc[self] = "wt0"
             /\ IF Blocking
                   THEN /\ pc' = [pc EXCEPT ![self] = "wt1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

wt1(self) == /\ pc[self] = "wt1"
             /\ IF WaitGate /\ result = "failed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "rq0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "wt2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

wt2(self) == /\ pc[self] = "wt2"
             /\ writer = NoProc
             /\ readers' = (readers \cup {self})
             /\ IF failLk[self]
                   THEN /\ viol' = (viol \cup {"Wait"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = "wt3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, writer, xof, 
                             poolLock, failRec, joined, lateWorker, stack, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

wt3(self) == /\ pc[self] = "wt3"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seed",
                                                      pc        |->  "wt4",
                                                      failLock  |->  failLock[self],
                                                      failColl  |->  failColl[self] ] >>
                                                  \o stack[self]]
             /\ failLock' = [failLock EXCEPT ![self] = FALSE]
             /\ failColl' = [failColl EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "sd0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, nr, c, ret, late, failLk, gLate, ns, 
                             failPrev >>

wt4(self) == /\ pc[self] = "wt4"
             /\ readers' = readers \ {self}
             /\ pc' = [pc EXCEPT ![self] = "wt5"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, writer, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

wt5(self) == /\ pc[self] = "wt5"
             /\ IF ~operational
                   THEN /\ pc' = [pc EXCEPT ![self] = "wt6"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

wt6(self) == /\ pc[self] = "wt6"
             /\ operational \/ mgrTerminate
                \/ (WaitGate /\ result = "failed")
             /\ failLk' = [failLk EXCEPT ![self] = (result = "failed")]
             /\ pc' = [pc EXCEPT ![self] = "wt7"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, gLate, ns, failPrev >>

wt7(self) == /\ pc[self] = "wt7"
             /\ IF WaitGate /\ result = "failed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "rq0"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

rq1(self) == /\ pc[self] = "rq1"
             /\ writer = NoProc
             /\ readers' = (readers \cup {self})
             /\ ret' = [ret EXCEPT ![self] = "none"]
             /\ IF failLk[self]
                   THEN /\ viol' = (viol \cup {"Wait"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ failLk' = [failLk EXCEPT ![self] = (result = "failed")]
             /\ pc' = [pc EXCEPT ![self] = "rq2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, writer, xof, 
                             poolLock, failRec, joined, lateWorker, stack, 
                             tret, esFail, failLock, failColl, nr, c, late, 
                             gLate, ns, failPrev >>

rq2(self) == /\ pc[self] = "rq2"
             /\ IF ~operational
                   THEN /\ ret' = [ret EXCEPT ![self] = IF Blocking THEN "notsupp" ELSE "none"]
                        /\ pc' = [pc EXCEPT ![self] = "rq5"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq3"]
                        /\ ret' = ret
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             late, failLk, gLate, ns, failPrev >>

rq3(self) == /\ pc[self] = "rq3"
             /\ IF result # "passed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "rq5"]
                        /\ UNCHANGED << viol, stack, c >>
                   ELSE /\ IF failLk[self]
                              THEN /\ viol' = (viol \cup {"Entry"})
                              ELSE /\ TRUE
                                   /\ viol' = viol
                        /\ c' = [c EXCEPT ![self] = Chunks]
                        /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "start",
                                                                 pc        |->  "rq4" ] >>
                                                             \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ps1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, tret, 
                             esFail, failLock, failColl, nr, ret, late, failLk, 
                             gLate, ns, failPrev >>

rq4(self) == /\ pc[self] = "rq4"
             /\ IF c[self] > 0
                   THEN /\ drngLock = NoProc
                        /\ drngLock' = self
                        /\ failLk' = [failLk EXCEPT ![self] = (result # "passed")]
                        /\ pc' = [pc EXCEPT ![self] = "rq4a"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq5"]
                        /\ UNCHANGED << drngLock, failLk >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, readers, writer, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, gLate, ns, failPrev >>

rq4a(self) == /\ pc[self] = "rq4a"
              /\ IF GateEachChunk /\ result # "passed"
                    THEN /\ c' = [c EXCEPT ![self] = 0]
                         /\ drngLock' = NoProc
                         /\ pc' = [pc EXCEPT ![self] = "rq5"]
                    ELSE /\ pc' = [pc EXCEPT ![self] = "rq4b"]
                         /\ UNCHANGED << drngLock, c >>
              /\ UNCHANGED << result, esResult, active, slot, terminate, 
                              mgrTerminate, due, avail, operational, entropy, 
                              initFailed, broken, readers, writer, xof, 
                              poolLock, failRec, joined, lateWorker, viol, 
                              stack, tret, esFail, failLock, failColl, nr, ret, 
                              late, failLk, gLate, ns, failPrev >>

rq4b(self) == /\ pc[self] = "rq4b"
              /\ IF failLk[self]
                    THEN /\ viol' = (viol \cup {"Generate"})
                    ELSE /\ TRUE
                         /\ viol' = viol
              /\ late' = [late EXCEPT ![self] = (result # "passed")]
              /\ pc' = [pc EXCEPT ![self] = "rq4c"]
              /\ UNCHANGED << result, esResult, active, slot, terminate, 
                              mgrTerminate, due, avail, operational, entropy, 
                              initFailed, broken, drngLock, readers, writer, 
                              xof, poolLock, failRec, joined, lateWorker, 
                              stack, tret, esFail, failLock, failColl, nr, c, 
                              ret, failLk, gLate, ns, failPrev >>

rq4c(self) == /\ pc[self] = "rq4c"
              /\ drngLock' = NoProc
              /\ IF RecheckChunk /\ result # "passed"
                    THEN /\ c' = [c EXCEPT ![self] = 0]
                         /\ pc' = [pc EXCEPT ![self] = "rq5"]
                    ELSE /\ pc' = [pc EXCEPT ![self] = "rq4d"]
                         /\ c' = c
              /\ UNCHANGED << result, esResult, active, slot, terminate, 
                              mgrTerminate, due, avail, operational, entropy, 
                              initFailed, broken, readers, writer, xof, 
                              poolLock, failRec, joined, lateWorker, viol, 
                              stack, tret, esFail, failLock, failColl, nr, ret, 
                              late, failLk, gLate, ns, failPrev >>

rq4d(self) == /\ pc[self] = "rq4d"
              /\ viol' = (viol \cup (IF late[self] THEN {"Output"} ELSE {})
                               \cup (IF result # "passed" THEN {"OutputLate"}
                                     ELSE {}))
              /\ c' = [c EXCEPT ![self] = c[self] - 1]
              /\ pc' = [pc EXCEPT ![self] = "rq4"]
              /\ UNCHANGED << result, esResult, active, slot, terminate, 
                              mgrTerminate, due, avail, operational, entropy, 
                              initFailed, broken, drngLock, readers, writer, 
                              xof, poolLock, failRec, joined, lateWorker, 
                              stack, tret, esFail, failLock, failColl, nr, ret, 
                              late, failLk, gLate, ns, failPrev >>

rq5(self) == /\ pc[self] = "rq5"
             /\ readers' = readers \ {self}
             /\ pc' = [pc EXCEPT ![self] = "rq6"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, writer, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

rq6(self) == /\ pc[self] = "rq6"
             /\ IF ret[self] = "notsupp" /\ ~mgrTerminate /\ result = "passed"
                   THEN /\ ret' = [ret EXCEPT ![self] = "none"]
                        /\ failLk' = [failLk EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "wt1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq0"]
                        /\ UNCHANGED << ret, failLk >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             late, gLate, ns, failPrev >>

r(self) == rq0(self) \/ wt0(self) \/ wt1(self) \/ wt2(self) \/ wt3(self)
              \/ wt4(self) \/ wt5(self) \/ wt6(self) \/ wt7(self)
              \/ rq1(self) \/ rq2(self) \/ rq3(self) \/ rq4(self)
              \/ rq4a(self) \/ rq4b(self) \/ rq4c(self) \/ rq4d(self)
              \/ rq5(self) \/ rq6(self)

gs0(self) == /\ pc[self] = "gs0"
             /\ gLate' = [gLate EXCEPT ![self] = (result = "failed")]
             /\ pc' = [pc EXCEPT ![self] = "gs1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, ns, failPrev >>

gs1(self) == /\ pc[self] = "gs1"
             /\ IF result # "passed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "gs2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

gs2(self) == /\ pc[self] = "gs2"
             /\ IF gLate[self]
                   THEN /\ viol' = (viol \cup {"Entry"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ gLate' = [gLate EXCEPT ![self] = (result # "passed")]
             /\ pc' = [pc EXCEPT ![self] = "gs3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, stack, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, ns, failPrev >>

gs3(self) == /\ pc[self] = "gs3"
             /\ IF GateEachChunk /\ result # "passed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "gs4"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

gs4(self) == /\ pc[self] = "gs4"
             /\ viol' = (viol \cup (IF gLate[self] THEN {"Output"} ELSE {})
                              \cup (IF result # "passed" THEN {"OutputLate"} ELSE {}))
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, stack, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

g(self) == gs0(self) \/ gs1(self) \/ gs2(self) \/ gs3(self) \/ gs4(self)

od1(self) == /\ pc[self] = "od1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "run",
                                                      pc        |->  "Done" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "ru1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

o(self) == od1(self)

rs0(self) == /\ pc[self] = "rs0"
             /\ pc["init"] = "Done" /\ (initFailed \/ entropy \/ result = "failed")
             /\ failPrev' = [failPrev EXCEPT ![self] = (result = "failed")]
             /\ IF initFailed
                   THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rs1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns >>

rs1(self) == /\ pc[self] = "rs1"
             /\ IF ns[self] < MaxReseeds /\ ~(GateSeeding /\ result = "failed")
                   THEN /\ ns' = [ns EXCEPT ![self] = ns[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "rs2"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ ns' = ns
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, failPrev >>

rs2(self) == /\ pc[self] = "rs2"
             /\ IF failPrev[self]
                   THEN /\ viol' = (viol \cup {"Worker"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "seed",
                                                      pc        |->  "rs3",
                                                      failLock  |->  failLock[self],
                                                      failColl  |->  failColl[self] ] >>
                                                  \o stack[self]]
             /\ failLock' = [failLock EXCEPT ![self] = FALSE]
             /\ failColl' = [failColl EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "sd0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, tret, 
                             esFail, nr, c, ret, late, failLk, gLate, ns, 
                             failPrev >>

rs3(self) == /\ pc[self] = "rs3"
             /\ failPrev' = [failPrev EXCEPT ![self] = (result = "failed")]
             /\ pc' = [pc EXCEPT ![self] = "rs1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns >>

rs(self) == rs0(self) \/ rs1(self) \/ rs2(self) \/ rs3(self)

ri0(self) == /\ pc[self] = "ri0"
             /\ pc["init"] = "Done"
             /\ IF initFailed
                   THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << stack, tret >>
                   ELSE /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "crypto",
                                                                 pc        |->  "ri1",
                                                                 tret      |->  tret[self] ] >>
                                                             \o stack[self]]
                        /\ tret' = [tret EXCEPT ![self] = FALSE]
                        /\ pc' = [pc EXCEPT ![self] = "cr0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             esFail, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

ri1(self) == /\ pc[self] = "ri1"
             /\ poolLock = NoProc
             /\ poolLock' = self
             /\ xof' = FALSE
             /\ pc' = [pc EXCEPT ![self] = "ri2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             failRec, joined, lateWorker, viol, stack, tret, 
                             esFail, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

ri2(self) == /\ pc[self] = "ri2"
             /\ xof' = TRUE
             /\ poolLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "ri3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             failRec, joined, lateWorker, viol, stack, tret, 
                             esFail, failLock, failColl, nr, c, ret, late, 
                             failLk, gLate, ns, failPrev >>

ri3(self) == /\ pc[self] = "ri3"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "run",
                                                      pc        |->  "Done" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "ru1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, joined, lateWorker, viol, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

ri(self) == ri0(self) \/ ri1(self) \/ ri2(self) \/ ri3(self)

fi0(self) == /\ pc[self] = "fi0"
             /\ pc["init"] = "Done"
             /\ terminate' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "fi1"]
             /\ UNCHANGED << result, esResult, active, slot, mgrTerminate, due, 
                             avail, operational, entropy, initFailed, broken, 
                             drngLock, readers, writer, xof, poolLock, failRec, 
                             joined, lateWorker, viol, stack, tret, esFail, 
                             failLock, failColl, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

fi1(self) == /\ pc[self] = "fi1"
             /\ ~slot
             /\ joined' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "fi2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, lateWorker, viol, stack, 
                             tret, esFail, failLock, failColl, nr, c, ret, 
                             late, failLk, gLate, ns, failPrev >>

fi2(self) == /\ pc[self] = "fi2"
             /\ mgrTerminate' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "fi3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             avail, operational, entropy, initFailed, broken, 
                             drngLock, readers, writer, xof, poolLock, failRec, 
                             joined, lateWorker, viol, stack, tret, esFail, 
                             failLock, failColl, nr, c, ret, late, failLk, 
                             gLate, ns, failPrev >>

fi3(self) == /\ pc[self] = "fi3"
             /\ readers = {} /\ writer = NoProc
             /\ writer' = self
             /\ pc' = [pc EXCEPT ![self] = "fi4"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

fi4(self) == /\ pc[self] = "fi4"
             /\ drngLock = NoProc
             /\ writer' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             mgrTerminate, due, avail, operational, entropy, 
                             initFailed, broken, drngLock, readers, xof, 
                             poolLock, failRec, joined, lateWorker, viol, 
                             stack, tret, esFail, failLock, failColl, nr, c, 
                             ret, late, failLk, gLate, ns, failPrev >>

fi(self) == fi0(self) \/ fi1(self) \/ fi2(self) \/ fi3(self) \/ fi4(self)

pw0 == /\ pc["pw"] = "pw0"
       /\ slot
       /\ lateWorker' = terminate
       /\ pc' = [pc EXCEPT !["pw"] = "pw1"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, mgrTerminate, 
                       due, avail, operational, entropy, initFailed, broken, 
                       drngLock, readers, writer, xof, poolLock, failRec, 
                       joined, viol, stack, tret, esFail, failLock, failColl, 
                       nr, c, ret, late, failLk, gLate, ns, failPrev >>

pw1 == /\ pc["pw"] = "pw1"
       /\ IF ~terminate
             THEN /\ due \/ terminate
                  /\ IF terminate
                        THEN /\ pc' = [pc EXCEPT !["pw"] = "pw4"]
                             /\ UNCHANGED << viol, stack >>
                        ELSE /\ IF lateWorker
                                   THEN /\ viol' = (viol \cup {"LateRun"})
                                   ELSE /\ TRUE
                                        /\ viol' = viol
                             /\ stack' = [stack EXCEPT !["pw"] = << [ procedure |->  "run",
                                                                      pc        |->  "pw3" ] >>
                                                                  \o stack["pw"]]
                             /\ pc' = [pc EXCEPT !["pw"] = "ru1"]
             ELSE /\ pc' = [pc EXCEPT !["pw"] = "pw4"]
                  /\ UNCHANGED << viol, stack >>
       /\ UNCHANGED << result, esResult, active, slot, terminate, mgrTerminate, 
                       due, avail, operational, entropy, initFailed, broken, 
                       drngLock, readers, writer, xof, poolLock, failRec, 
                       joined, lateWorker, tret, esFail, failLock, failColl, 
                       nr, c, ret, late, failLk, gLate, ns, failPrev >>

pw3 == /\ pc["pw"] = "pw3"
       /\ IF result # "passed"
             THEN /\ pc' = [pc EXCEPT !["pw"] = "pw4"]
             ELSE /\ pc' = [pc EXCEPT !["pw"] = "pw1"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, mgrTerminate, 
                       due, avail, operational, entropy, initFailed, broken, 
                       drngLock, readers, writer, xof, poolLock, failRec, 
                       joined, lateWorker, viol, stack, tret, esFail, failLock, 
                       failColl, nr, c, ret, late, failLk, gLate, ns, failPrev >>

pw4 == /\ pc["pw"] = "pw4"
       /\ active' = FALSE
       /\ pc' = [pc EXCEPT !["pw"] = "pw5"]
       /\ UNCHANGED << result, esResult, slot, terminate, mgrTerminate, due, 
                       avail, operational, entropy, initFailed, broken, 
                       drngLock, readers, writer, xof, poolLock, failRec, 
                       joined, lateWorker, viol, stack, tret, esFail, failLock, 
                       failColl, nr, c, ret, late, failLk, gLate, ns, failPrev >>

pw5 == /\ pc["pw"] = "pw5"
       /\ slot' = FALSE
       /\ pc' = [pc EXCEPT !["pw"] = "pw0"]
       /\ UNCHANGED << result, esResult, active, terminate, mgrTerminate, due, 
                       avail, operational, entropy, initFailed, broken, 
                       drngLock, readers, writer, xof, poolLock, failRec, 
                       joined, lateWorker, viol, stack, tret, esFail, failLock, 
                       failColl, nr, c, ret, late, failLk, gLate, ns, failPrev >>

pw == pw0 \/ pw1 \/ pw3 \/ pw4 \/ pw5

ea0 == /\ pc["ent"] = "ea0"
       /\ ~entropy
       /\ entropy' = TRUE
       /\ pc' = [pc EXCEPT !["ent"] = "Done"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, mgrTerminate, 
                       due, avail, operational, initFailed, broken, drngLock, 
                       readers, writer, xof, poolLock, failRec, joined, 
                       lateWorker, viol, stack, tret, esFail, failLock, 
                       failColl, nr, c, ret, late, failLk, gLate, ns, failPrev >>

ea == ea0

en0 == /\ pc["env"] = "en0"
       /\ \/ /\ ~due
             /\ due' = TRUE
             /\ UNCHANGED broken
          \/ /\ CanBreak /\ ~broken
             /\ broken' = TRUE
             /\ due' = due
          \/ /\ /\ \A p \in Finite : pc[p] = "Done"
                /\ pc["pw"] = "pw0" /\ ~slot
             /\ TRUE
             /\ UNCHANGED <<due, broken>>
       /\ pc' = [pc EXCEPT !["env"] = "en0"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, mgrTerminate, 
                       avail, operational, entropy, initFailed, drngLock, 
                       readers, writer, xof, poolLock, failRec, joined, 
                       lateWorker, viol, stack, tret, esFail, failLock, 
                       failColl, nr, c, ret, late, failLk, gLate, ns, failPrev >>

en == en0

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == pw \/ ea \/ en
           \/ (\E self \in ProcSet:  \/ crypto(self) \/ es(self) \/ run(self)
                                     \/ start(self) \/ seed(self))
           \/ (\E self \in InitProcs: ini(self))
           \/ (\E self \in Req: r(self))
           \/ (\E self \in SeedCallers: g(self))
           \/ (\E self \in OnDemand: o(self))
           \/ (\E self \in ReseedProcs: rs(self))
           \/ (\E self \in ReinitProcs: ri(self))
           \/ (\E self \in FiniProcs: fi(self))
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in InitProcs : /\ WF_vars(ini(self))
                                   /\ WF_vars(crypto(self))
                                   /\ WF_vars(run(self))
                                   /\ WF_vars(start(self))
                                   /\ WF_vars(es(self))
        /\ \A self \in Req : WF_vars(r(self)) /\ WF_vars(seed(self)) /\ WF_vars(start(self))
        /\ \A self \in SeedCallers : WF_vars(g(self))
        /\ \A self \in OnDemand : /\ WF_vars(o(self))
                                  /\ WF_vars(run(self))
                                  /\ WF_vars(crypto(self))
                                  /\ WF_vars(es(self))
        /\ \A self \in ReseedProcs : WF_vars(rs(self)) /\ WF_vars(seed(self))
        /\ \A self \in ReinitProcs : /\ WF_vars(ri(self))
                                     /\ WF_vars(crypto(self))
                                     /\ WF_vars(run(self))
                                     /\ WF_vars(es(self))
        /\ \A self \in FiniProcs : WF_vars(fi(self))
        /\ WF_vars(pw) /\ WF_vars(run("pw")) /\ WF_vars(crypto("pw")) /\ WF_vars(es("pw"))
        /\ WF_vars(ea)
        /\ WF_vars(en)

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

-----------------------------------------------------------------------------
(* Safety *)

TypeOK ==
    /\ result \in {"undone", "passed", "failed"}
    /\ esResult \in {"undone", "passed", "failed"}
    /\ drngLock \in AllProcs \cup {NoProc}
    /\ readers \subseteq AllProcs
    /\ (writer # NoProc => readers = {})
    /\ viol \subseteq {"Output", "OutputLate", "Generate", "Entry", "Wait",
                       "Collect", "Inject", "InjectLate", "Worker",
                       "EsSpurious", "LateRun"}

\* Every chunk and every seed handed out was generated or collected while
\* the crypto self tests stood passed: not before they ran, and not after a
\* failure was recorded. The ghost is set where the chunk is generated, the
\* check that keeps the property is the step after it.
OutputGated == "Output" \notin viol

\* No chunk is generated once a failure was recorded before the request took
\* the DRNG lock for it (nor before the self tests ran).
GenerateGated == "Generate" \notin viol

\* A request that found a failure recorded when it took the DRNG instances
\* starts no periodic worker and takes no DRNG lock; a call of
\* esdm_get_seed() that found one collects nothing.
EntryGated == "Entry" \notin viol

\* A blocking request that found a failure recorded when it began or ended
\* its wait returns: it starts no seeding and no request.
WaitGated == "Wait" \notin viol

\* A failure is never lost, to a concurrent passing run or otherwise.
FailureKept == failRec => result = "failed"

\* The entropy source self test fails only for a source that is broken.
EsVerdictSound == "EsSpurious" \notin viol

\* After a failure, no seeding uses the crypto implementations, as far as a
\* check can tell: none collects once the failure was recorded before it
\* took the DRNG lock, none injects once it was recorded before its
\* collection ended, and the reseed worker starts none once it was recorded
\* before its previous one ended.
NoCryptoAfterFailure == viol \cap {"Collect", "Inject", "Worker"} = {}

\* A worker thread is marked active until it leaves: no second one starts.
WorkerMarked == (slot /\ pc["pw"] # "pw5") => active

\* thread_start() waits only for a worker on its way out.
StartWaitsForLeaving ==
    \A p \in Finite : (pc[p] = "ps4" /\ slot) => pc["pw"] = "pw5"

\* A worker that starts after it was asked to leave - a request can start
\* one after the join in esdm_fini(), see NoStartAfterJoin - runs no self
\* test pass.
LateWorkerIdle == "LateRun" \notin viol

\* The verdict only moves from undone to passed or failed, and from passed
\* to failed.
VerdictFinal ==
    [][/\ result = "failed" => result' = "failed"
       /\ result = "passed" => result' \in {"passed", "failed"}]_result

\* What the code does not deliver, each shown by a configuration that
\* expects the violation with every fix on. A failure recorded after the
\* last check of a chunk, a seed or an injection does not stop it: the
\* verdict is not written under the lock the check is made under.
NoOutputAfterFailure == "OutputLate" \notin viol
NoInjectAfterFailure == "InjectLate" \notin viol
\* A request that read the stop flag before esdm_fini() set it starts the
\* worker after esdm_fini() joined the threads.
NoStartAfterJoin == ~(joined /\ slot)

-----------------------------------------------------------------------------
(* Liveness *)

\* Every thread but the worker and the environment finishes: no deadlock
\* between the DRNG lock, esdm_node_cleanup_lock, the thread slot and the
\* worker's join, and no request left waiting for an ESDM that does not
\* become operational any more.
Progress == \A p \in Finite : <>(pc[p] = "Done")

\* A worker on duty repeats the self tests as long as nothing breaks and
\* nobody stops it.
PeriodicRuns ==
    ([]~broken /\ []~terminate) => [](slot => []<>(pc["pw"] = "ru3"))

\* A request that passed the gate leaves a worker on duty for good.
WorkerOnDuty ==
    (Threads /\ ~ThreadFail /\ []~broken /\ []~terminate) =>
        \A p \in Req : [](pc[p] = "rq4" => <>[]slot)

\* After a failure, or once asked to stop, the worker leaves for good.
FailureStopsWorker == [](result = "failed" => <>[]~slot)
StopLeaves == [](terminate => <>[]~slot)
=============================================================================
