----------------------------- MODULE EsdmSelftest -----------------------------
(***************************************************************************)
(* The self test gate on the output of the ESDM: esdm/esdm_selftest.c,     *)
(* the verdict it records and the periodic self test worker, and the       *)
(* callers that depend on it in esdm/esdm_drng_mgr.c and esdm/esdm_lib.c,  *)
(* at the granularity of their locks and atomics. One step is one atomic   *)
(* variable access or one critical section; the labels name the C          *)
(* functions they come from.                                               *)
(*                                                                         *)
(* Abstractions:                                                           *)
(* - The crypto implementations either work or are broken; the             *)
(*   environment may break them once at any time. A self test of a broken  *)
(*   implementation fails, of a working one passes.                        *)
(* - One DRNG lock stands for the lock of the DRNG a request, a seeding    *)
(*   and esdm_selftest_crypto() take; esdm_node_cleanup_lock is a          *)
(*   reader-preferring lock: readers wait for a writer holding it only.    *)
(* - esdm_drng_get() is reduced to its gates and its chunks, each one      *)
(*   generate under the DRNG lock; esdm_get_seed() to its gate and the     *)
(*   collection it hands out.                                              *)
(* - The worker's timed waits are one wait until the next pass is due or   *)
(*   it is asked to leave; the environment makes the pass due after the    *)
(*   interval. The worker has one thread slot (its special thread group):  *)
(*   thread_start() waits while the slot is busy, or fails where           *)
(*   ThreadFail says so; without Threads, thread_available() is false.     *)
(* - Of the entropy source self tests only the one of the auxiliary pool   *)
(*   is modelled: whether its XOF context is there, which esdm_aux_init()  *)
(*   replaces in esdm_reinit().                                            *)
(* - Not modelled: the seeding state (the ESDM is operational once         *)
(*   esdm_init() seeded), the request and reseed logic of EsdmReseed, the  *)
(*   shared memory status and the log messages.                            *)
(* - The threads but the worker and the environment are bounded; every     *)
(*   process is weakly fair.                                               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Req,          \* threads requesting random bits, esdm_drng_get()
    Chunks,       \* chunks of a request
    MaxReq,       \* requests per thread
    SeedCallers,  \* threads calling esdm_get_seed()
    OnDemand,     \* threads running esdm_selftest_run() (the RPC self test)
    InitMonitor,  \* esdm_init_monitor() starts the periodic self tests
    Reseeder,     \* the reseed worker seeds MaxReseeds times
    MaxReseeds,
    Reinit,       \* esdm_reinit() runs once
    Fini,         \* esdm_fini() runs once
    CanBreak,     \* the crypto implementations may break
    Threads,      \* thread_available(): the process has a thread pool
    ThreadFail,   \* thread_start() may fail
    \* the fixes, FALSE for the code before them:
    GateEachChunk, \* the verdict is checked before every chunk and before
                   \* esdm_get_seed() hands out
    GateSeeding,  \* a recorded failure stops the seedings and the reseed
                  \* worker
    EsLocked      \* esdm_aux_selftest() reads under the pool lock

NoProc == "none"
InitProcs == {"init"}
ReseedProcs == IF Reseeder THEN {"reseed"} ELSE {}
ReinitProcs == IF Reinit THEN {"reinit"} ELSE {}
FiniProcs == IF Fini THEN {"fini"} ELSE {}
\* the threads that finish
Finite == InitProcs \cup Req \cup SeedCallers \cup OnDemand \cup ReseedProcs
          \cup ReinitProcs \cup FiniProcs
AllProcs == Finite \cup {"pw", "env"}

(* --algorithm EsdmSelftest {
variables
    result = "undone",      \* esdm_selftest_result
    esResult = "undone",    \* esdm_es_selftest_result
    active = FALSE,         \* esdm_selftest_worker_active
    slot = FALSE,           \* the worker's thread slot is in use
    terminate = FALSE,      \* esdm_selftest_worker_terminate, or the DRNG
                            \* manager terminating
    due = TRUE,             \* esdm_selftest_due(), no pass recorded yet
    operational = FALSE,
    initFailed = FALSE,     \* esdm_init() failed
    broken = FALSE,
    drngLock = NoProc,      \* drng->lock
    readers = {},           \* esdm_node_cleanup_lock held for reading
    writer = NoProc,        \* ... and for writing
    xof = TRUE,             \* esdm_pools[0].xdrbg.xof is there
    poolLock = NoProc,      \* esdm_pools[0].lock
    \* ghosts: a failing self test was recorded; properties violated
    failRec = FALSE,
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
     \* esdm_drng_put_instances(), then esdm_selftest_record(): a failure by
     \* atomic_exchange(), a pass by atomic_compare_exchange_strong() from
     \* undone
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

\* esdm_selftest_periodic_start()
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

\* esdm_init(), then esdm_init_monitor()
fair process (ini \in InitProcs)
{
     \* esdm_drng_mgr_initialize()
in1: call crypto();
in2: if (result # "passed") {
         initFailed := TRUE;
         goto Done;
     } else {
         \* esdm_es_mgr_initialize() seeds the DRNGs
         operational := TRUE;
     };
     \* the initial self test pass
in3: call run();
in4: if (InitMonitor) call start();
}

\* esdm_drng_get_sleep() and esdm_drng_get()
fair process (r \in Req)
    variables nr = 0, c = 0;
{
rq0: while (nr < MaxReq) {
         nr := nr + 1;
         \* esdm_drng_get_instances(), then the gates at the entry of
         \* esdm_drng_get()
rq1:     await writer = NoProc;
         readers := readers \cup {self};
         if (operational /\ result = "passed") {
             c := Chunks;
             call start();
         } else {
             goto rq5;
         };
rq4:     while (c > 0) {
             \* a chunk: drng_generate() under drng->lock
             await drngLock = NoProc;
             if (GateEachChunk /\ result # "passed") {
                 c := 0;
             } else {
                 if (result # "passed") viol := viol \cup {"Output"};
                 c := c - 1;
             };
         };
         \* esdm_drng_put_instances()
rq5:     readers := readers \ {self};
     };
}

\* esdm_get_seed()
fair process (g \in SeedCallers)
{
gs1: if (result = "passed") {
         \* the collection, esdm_get_seed_buffers(), and handing it out
gs2:     if (GateEachChunk /\ result # "passed") {
             skip;
         } else if (result # "passed") {
             viol := viol \cup {"Output"};
         };
     };
}

\* the privileged RPC self test, esdm_rpc_selftest()
fair process (o \in OnDemand)
{
od1: call run();
}

\* the reseed worker, started by esdm_init_monitor(): each seeding, esdm_drng_seed(), holds drng->lock
\* across the collection and the injection
fair process (rs \in ReseedProcs)
    variables ns = 0;
{
rs0: await pc["init"] = "Done";
     if (initFailed) goto Done;
     \* esdm_drng_reseed_stop(): a recorded failure, not one undone, ends it
rs1: while (ns < MaxReseeds /\ ~(GateSeeding /\ result = "failed")) {
         ns := ns + 1;
         await drngLock = NoProc;
         drngLock := self;
         \* esdm_get_seed_buffers(), then esdm_drng_inject(), which
         \* esdm_drng_seed_es() skips after a failure, checked under the lock
rs2:     if (~GateSeeding \/ result # "failed") {
             if (result = "failed") viol := viol \cup {"Crypto"};
         };
         drngLock := NoProc;
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
     \* esdm_node_fini(): the DRNGs released under their locks
fi2: await readers = {} /\ writer = NoProc;
     writer := self;
fi3: await drngLock = NoProc;
     writer := NoProc;
}

\* esdm_periodic_selftest_worker() in the thread slot
fair process (pw = "pw")
{
pw0: while (TRUE) {
         await slot;
pw1:     while (~terminate) {
             await due \/ terminate;
             if (terminate) {
                 goto pw4;
             } else {
                 call run();
             };
             \* a failure is not recovered from: the worker leaves
pw3:         if (result # "passed") goto pw4;
         };
pw4:     active := FALSE;
pw5:     slot := FALSE;
     };
}

\* the interval passing, and the implementations breaking
fair process (en = "env")
{
en0: while (TRUE) {
         either {
             await ~due;
             due := TRUE;
         } or {
             await CanBreak /\ ~broken;
             broken := TRUE;
         };
     };
}

} *)
\* BEGIN TRANSLATION
VARIABLES result, esResult, active, slot, terminate, due, operational, 
          initFailed, broken, drngLock, readers, writer, xof, poolLock, 
          failRec, viol, pc, stack, tret, esFail, nr, c, ns

vars == << result, esResult, active, slot, terminate, due, operational, 
           initFailed, broken, drngLock, readers, writer, xof, poolLock, 
           failRec, viol, pc, stack, tret, esFail, nr, c, ns >>

ProcSet == (InitProcs) \cup (Req) \cup (SeedCallers) \cup (OnDemand) \cup (ReseedProcs) \cup (ReinitProcs) \cup (FiniProcs) \cup {"pw"} \cup {"env"}

Init == (* Global variables *)
        /\ result = "undone"
        /\ esResult = "undone"
        /\ active = FALSE
        /\ slot = FALSE
        /\ terminate = FALSE
        /\ due = TRUE
        /\ operational = FALSE
        /\ initFailed = FALSE
        /\ broken = FALSE
        /\ drngLock = NoProc
        /\ readers = {}
        /\ writer = NoProc
        /\ xof = TRUE
        /\ poolLock = NoProc
        /\ failRec = FALSE
        /\ viol = {}
        (* Procedure crypto *)
        /\ tret = [ self \in ProcSet |-> FALSE]
        (* Procedure es *)
        /\ esFail = [ self \in ProcSet |-> FALSE]
        (* Process r *)
        /\ nr = [self \in Req |-> 0]
        /\ c = [self \in Req |-> 0]
        (* Process rs *)
        /\ ns = [self \in ReseedProcs |-> 0]
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> CASE self \in InitProcs -> "in1"
                                        [] self \in Req -> "rq0"
                                        [] self \in SeedCallers -> "gs1"
                                        [] self \in OnDemand -> "od1"
                                        [] self \in ReseedProcs -> "rs0"
                                        [] self \in ReinitProcs -> "ri0"
                                        [] self \in FiniProcs -> "fi0"
                                        [] self = "pw" -> "pw0"
                                        [] self = "env" -> "en0"]

cr0(self) == /\ pc[self] = "cr0"
             /\ writer = NoProc
             /\ readers' = (readers \cup {self})
             /\ pc' = [pc EXCEPT ![self] = "cr1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, writer, 
                             xof, poolLock, failRec, viol, stack, tret, esFail, 
                             nr, c, ns >>

cr1(self) == /\ pc[self] = "cr1"
             /\ IF broken
                   THEN /\ tret' = [tret EXCEPT ![self] = TRUE]
                        /\ pc' = [pc EXCEPT ![self] = "cr3"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "cr2"]
                        /\ tret' = tret
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, esFail, nr, c, ns >>

cr2(self) == /\ pc[self] = "cr2"
             /\ drngLock = NoProc
             /\ tret' = [tret EXCEPT ![self] = broken]
             /\ pc' = [pc EXCEPT ![self] = "cr3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, esFail, nr, c, ns >>

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
             /\ UNCHANGED << esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, writer, 
                             xof, poolLock, viol, esFail, nr, c, ns >>

crypto(self) == cr0(self) \/ cr1(self) \/ cr2(self) \/ cr3(self)

es1(self) == /\ pc[self] = "es1"
             /\ IF EsLocked
                   THEN /\ poolLock = NoProc
                   ELSE /\ TRUE
             /\ esFail' = [esFail EXCEPT ![self] = ~xof]
             /\ pc' = [pc EXCEPT ![self] = "es2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, tret, nr, c, ns >>

es2(self) == /\ pc[self] = "es2"
             /\ esResult' = IF esFail[self] THEN "failed" ELSE "passed"
             /\ IF esFail[self]
                   THEN /\ viol' = (viol \cup {"EsSpurious"})
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ esFail' = [esFail EXCEPT ![self] = Head(stack[self]).esFail]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, active, slot, terminate, due, operational, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, tret, nr, c, ns >>

es(self) == es1(self) \/ es2(self)

ru1(self) == /\ pc[self] = "ru1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "crypto",
                                                      pc        |->  "ru2",
                                                      tret      |->  tret[self] ] >>
                                                  \o stack[self]]
             /\ tret' = [tret EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "cr0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             esFail, nr, c, ns >>

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
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, nr, c, ns >>

ru3(self) == /\ pc[self] = "ru3"
             /\ due' = FALSE
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, esResult, active, slot, terminate, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

run(self) == ru1(self) \/ ru2(self) \/ ru3(self)

ps1(self) == /\ pc[self] = "ps1"
             /\ IF terminate \/ active \/ ~Threads
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "ps3"]
                        /\ stack' = stack
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

ps3(self) == /\ pc[self] = "ps3"
             /\ IF active
                   THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED active
                   ELSE /\ active' = TRUE
                        /\ pc' = [pc EXCEPT ![self] = "ps4"]
                        /\ stack' = stack
             /\ UNCHANGED << result, esResult, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

ps4(self) == /\ pc[self] = "ps4"
             /\ \/ /\ ~slot
                   /\ slot' = TRUE
                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                \/ /\ ThreadFail
                   /\ pc' = [pc EXCEPT ![self] = "ps5"]
                   /\ UNCHANGED <<slot, stack>>
             /\ UNCHANGED << result, esResult, active, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

ps5(self) == /\ pc[self] = "ps5"
             /\ active' = FALSE
             /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
             /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
             /\ UNCHANGED << result, esResult, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

start(self) == ps1(self) \/ ps3(self) \/ ps4(self) \/ ps5(self)

in1(self) == /\ pc[self] = "in1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "crypto",
                                                      pc        |->  "in2",
                                                      tret      |->  tret[self] ] >>
                                                  \o stack[self]]
             /\ tret' = [tret EXCEPT ![self] = FALSE]
             /\ pc' = [pc EXCEPT ![self] = "cr0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             esFail, nr, c, ns >>

in2(self) == /\ pc[self] = "in2"
             /\ IF result # "passed"
                   THEN /\ initFailed' = TRUE
                        /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED operational
                   ELSE /\ operational' = TRUE
                        /\ pc' = [pc EXCEPT ![self] = "in3"]
                        /\ UNCHANGED initFailed
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             broken, drngLock, readers, writer, xof, poolLock, 
                             failRec, viol, stack, tret, esFail, nr, c, ns >>

in3(self) == /\ pc[self] = "in3"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "run",
                                                      pc        |->  "in4" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "ru1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

in4(self) == /\ pc[self] = "in4"
             /\ IF InitMonitor
                   THEN /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "start",
                                                                 pc        |->  "Done" ] >>
                                                             \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ps1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ stack' = stack
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

ini(self) == in1(self) \/ in2(self) \/ in3(self) \/ in4(self)

rq0(self) == /\ pc[self] = "rq0"
             /\ IF nr[self] < MaxReq
                   THEN /\ nr' = [nr EXCEPT ![self] = nr[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "rq1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ nr' = nr
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, tret, esFail, c, ns >>

rq1(self) == /\ pc[self] = "rq1"
             /\ writer = NoProc
             /\ readers' = (readers \cup {self})
             /\ IF operational /\ result = "passed"
                   THEN /\ c' = [c EXCEPT ![self] = Chunks]
                        /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "start",
                                                                 pc        |->  "rq4" ] >>
                                                             \o stack[self]]
                        /\ pc' = [pc EXCEPT ![self] = "ps1"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq5"]
                        /\ UNCHANGED << stack, c >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, writer, 
                             xof, poolLock, failRec, viol, tret, esFail, nr, 
                             ns >>

rq4(self) == /\ pc[self] = "rq4"
             /\ IF c[self] > 0
                   THEN /\ drngLock = NoProc
                        /\ IF GateEachChunk /\ result # "passed"
                              THEN /\ c' = [c EXCEPT ![self] = 0]
                                   /\ viol' = viol
                              ELSE /\ IF result # "passed"
                                         THEN /\ viol' = (viol \cup {"Output"})
                                         ELSE /\ TRUE
                                              /\ viol' = viol
                                   /\ c' = [c EXCEPT ![self] = c[self] - 1]
                        /\ pc' = [pc EXCEPT ![self] = "rq4"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rq5"]
                        /\ UNCHANGED << viol, c >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, stack, 
                             tret, esFail, nr, ns >>

rq5(self) == /\ pc[self] = "rq5"
             /\ readers' = readers \ {self}
             /\ pc' = [pc EXCEPT ![self] = "rq0"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, writer, 
                             xof, poolLock, failRec, viol, stack, tret, esFail, 
                             nr, c, ns >>

r(self) == rq0(self) \/ rq1(self) \/ rq4(self) \/ rq5(self)

gs1(self) == /\ pc[self] = "gs1"
             /\ IF result = "passed"
                   THEN /\ pc' = [pc EXCEPT ![self] = "gs2"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, tret, esFail, nr, c, ns >>

gs2(self) == /\ pc[self] = "gs2"
             /\ IF GateEachChunk /\ result # "passed"
                   THEN /\ TRUE
                        /\ viol' = viol
                   ELSE /\ IF result # "passed"
                              THEN /\ viol' = (viol \cup {"Output"})
                              ELSE /\ TRUE
                                   /\ viol' = viol
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, stack, 
                             tret, esFail, nr, c, ns >>

g(self) == gs1(self) \/ gs2(self)

od1(self) == /\ pc[self] = "od1"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "run",
                                                      pc        |->  "Done" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "ru1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

o(self) == od1(self)

rs0(self) == /\ pc[self] = "rs0"
             /\ pc["init"] = "Done"
             /\ IF initFailed
                   THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "rs1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, tret, esFail, nr, c, ns >>

rs1(self) == /\ pc[self] = "rs1"
             /\ IF ns[self] < MaxReseeds /\ ~(GateSeeding /\ result = "failed")
                   THEN /\ ns' = [ns EXCEPT ![self] = ns[self] + 1]
                        /\ drngLock = NoProc
                        /\ drngLock' = self
                        /\ pc' = [pc EXCEPT ![self] = "rs2"]
                   ELSE /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED << drngLock, ns >>
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, readers, writer, 
                             xof, poolLock, failRec, viol, stack, tret, esFail, 
                             nr, c >>

rs2(self) == /\ pc[self] = "rs2"
             /\ IF ~GateSeeding \/ result # "failed"
                   THEN /\ IF result = "failed"
                              THEN /\ viol' = (viol \cup {"Crypto"})
                              ELSE /\ TRUE
                                   /\ viol' = viol
                   ELSE /\ TRUE
                        /\ viol' = viol
             /\ drngLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "rs1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, readers, writer, 
                             xof, poolLock, failRec, stack, tret, esFail, nr, 
                             c, ns >>

rs(self) == rs0(self) \/ rs1(self) \/ rs2(self)

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
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             esFail, nr, c, ns >>

ri1(self) == /\ pc[self] = "ri1"
             /\ poolLock = NoProc
             /\ poolLock' = self
             /\ xof' = FALSE
             /\ pc' = [pc EXCEPT ![self] = "ri2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, failRec, viol, stack, tret, 
                             esFail, nr, c, ns >>

ri2(self) == /\ pc[self] = "ri2"
             /\ xof' = TRUE
             /\ poolLock' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "ri3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, failRec, viol, stack, tret, 
                             esFail, nr, c, ns >>

ri3(self) == /\ pc[self] = "ri3"
             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "run",
                                                      pc        |->  "Done" ] >>
                                                  \o stack[self]]
             /\ pc' = [pc EXCEPT ![self] = "ru1"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             tret, esFail, nr, c, ns >>

ri(self) == ri0(self) \/ ri1(self) \/ ri2(self) \/ ri3(self)

fi0(self) == /\ pc[self] = "fi0"
             /\ pc["init"] = "Done"
             /\ terminate' = TRUE
             /\ pc' = [pc EXCEPT ![self] = "fi1"]
             /\ UNCHANGED << result, esResult, active, slot, due, operational, 
                             initFailed, broken, drngLock, readers, writer, 
                             xof, poolLock, failRec, viol, stack, tret, esFail, 
                             nr, c, ns >>

fi1(self) == /\ pc[self] = "fi1"
             /\ ~slot
             /\ pc' = [pc EXCEPT ![self] = "fi2"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, writer, xof, poolLock, failRec, viol, 
                             stack, tret, esFail, nr, c, ns >>

fi2(self) == /\ pc[self] = "fi2"
             /\ readers = {} /\ writer = NoProc
             /\ writer' = self
             /\ pc' = [pc EXCEPT ![self] = "fi3"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, xof, poolLock, failRec, viol, stack, 
                             tret, esFail, nr, c, ns >>

fi3(self) == /\ pc[self] = "fi3"
             /\ drngLock = NoProc
             /\ writer' = NoProc
             /\ pc' = [pc EXCEPT ![self] = "Done"]
             /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                             operational, initFailed, broken, drngLock, 
                             readers, xof, poolLock, failRec, viol, stack, 
                             tret, esFail, nr, c, ns >>

fi(self) == fi0(self) \/ fi1(self) \/ fi2(self) \/ fi3(self)

pw0 == /\ pc["pw"] = "pw0"
       /\ slot
       /\ pc' = [pc EXCEPT !["pw"] = "pw1"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                       operational, initFailed, broken, drngLock, readers, 
                       writer, xof, poolLock, failRec, viol, stack, tret, 
                       esFail, nr, c, ns >>

pw1 == /\ pc["pw"] = "pw1"
       /\ IF ~terminate
             THEN /\ due \/ terminate
                  /\ IF terminate
                        THEN /\ pc' = [pc EXCEPT !["pw"] = "pw4"]
                             /\ stack' = stack
                        ELSE /\ stack' = [stack EXCEPT !["pw"] = << [ procedure |->  "run",
                                                                      pc        |->  "pw3" ] >>
                                                                  \o stack["pw"]]
                             /\ pc' = [pc EXCEPT !["pw"] = "ru1"]
             ELSE /\ pc' = [pc EXCEPT !["pw"] = "pw4"]
                  /\ stack' = stack
       /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                       operational, initFailed, broken, drngLock, readers, 
                       writer, xof, poolLock, failRec, viol, tret, esFail, nr, 
                       c, ns >>

pw3 == /\ pc["pw"] = "pw3"
       /\ IF result # "passed"
             THEN /\ pc' = [pc EXCEPT !["pw"] = "pw4"]
             ELSE /\ pc' = [pc EXCEPT !["pw"] = "pw1"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, due, 
                       operational, initFailed, broken, drngLock, readers, 
                       writer, xof, poolLock, failRec, viol, stack, tret, 
                       esFail, nr, c, ns >>

pw4 == /\ pc["pw"] = "pw4"
       /\ active' = FALSE
       /\ pc' = [pc EXCEPT !["pw"] = "pw5"]
       /\ UNCHANGED << result, esResult, slot, terminate, due, operational, 
                       initFailed, broken, drngLock, readers, writer, xof, 
                       poolLock, failRec, viol, stack, tret, esFail, nr, c, ns >>

pw5 == /\ pc["pw"] = "pw5"
       /\ slot' = FALSE
       /\ pc' = [pc EXCEPT !["pw"] = "pw0"]
       /\ UNCHANGED << result, esResult, active, terminate, due, operational, 
                       initFailed, broken, drngLock, readers, writer, xof, 
                       poolLock, failRec, viol, stack, tret, esFail, nr, c, ns >>

pw == pw0 \/ pw1 \/ pw3 \/ pw4 \/ pw5

en0 == /\ pc["env"] = "en0"
       /\ \/ /\ ~due
             /\ due' = TRUE
             /\ UNCHANGED broken
          \/ /\ CanBreak /\ ~broken
             /\ broken' = TRUE
             /\ due' = due
       /\ pc' = [pc EXCEPT !["env"] = "en0"]
       /\ UNCHANGED << result, esResult, active, slot, terminate, operational, 
                       initFailed, drngLock, readers, writer, xof, poolLock, 
                       failRec, viol, stack, tret, esFail, nr, c, ns >>

en == en0

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == pw \/ en
           \/ (\E self \in ProcSet:  \/ crypto(self) \/ es(self) \/ run(self)
                                     \/ start(self))
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
        /\ \A self \in Req : WF_vars(r(self)) /\ WF_vars(start(self))
        /\ \A self \in SeedCallers : WF_vars(g(self))
        /\ \A self \in OnDemand : /\ WF_vars(o(self))
                                  /\ WF_vars(run(self))
                                  /\ WF_vars(crypto(self))
                                  /\ WF_vars(es(self))
        /\ \A self \in ReseedProcs : WF_vars(rs(self))
        /\ \A self \in ReinitProcs : /\ WF_vars(ri(self))
                                     /\ WF_vars(crypto(self))
                                     /\ WF_vars(run(self))
                                     /\ WF_vars(es(self))
        /\ \A self \in FiniProcs : WF_vars(fi(self))
        /\ WF_vars(pw) /\ WF_vars(run("pw")) /\ WF_vars(crypto("pw")) /\ WF_vars(es("pw"))
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

\* No bits are handed out unless the crypto self tests passed: neither
\* before they ran nor after one failed.
OutputGated == "Output" \notin viol

\* A failure is never lost, to a concurrent passing run or otherwise.
FailureKept == failRec => result = "failed"

\* The entropy source self test fails only for a source that is broken.
EsVerdictSound == "EsSpurious" \notin viol

\* After a failure, no seeding uses the crypto implementations.
NoCryptoAfterFailure == "Crypto" \notin viol

\* A worker thread is marked active until it leaves: no second one starts.
WorkerMarked == (slot /\ pc["pw"] # "pw5") => active

\* thread_start() waits only for a worker on its way out.
StartWaitsForLeaving ==
    \A p \in Finite : (pc[p] = "ps4" /\ slot) => pc["pw"] = "pw5"

\* The verdict only moves from undone to passed or failed, and from passed
\* to failed.
VerdictFinal ==
    [][/\ result = "failed" => result' = "failed"
       /\ result = "passed" => result' \in {"passed", "failed"}]_result

-----------------------------------------------------------------------------
(* Liveness *)

\* Every thread but the worker and the environment finishes: no deadlock
\* between the DRNG lock, esdm_node_cleanup_lock, the thread slot and the
\* worker's join.
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
