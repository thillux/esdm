Changes 1.2.4
* Add an optional EGD (Entropy Gathering Daemon) protocol interface to the
esdm-server, enabled by starting esdm-server-egd.socket or with
--egd_socket <path>, which serves legacy entropy consumers such as libgcrypt's
rndegd backend or OpenSSL's RAND_egd()

* Add libesdm_egd_client, a client library for the EGD interface, and
libesdm-egd-provider.so, an OpenSSL 3 RAND provider based on it: both need
nothing but the one EGD socket and therefore work where the RPC interface
cannot be reached, OpenSSH's sandboxed pre-authentication child included

* Add a second EGD socket serving the prediction resistance generator
(esdm-server-egd-pr.socket, --egd_socket_pr) together with the matching
libesdm-egd-provider-pr.so - the EGD protocol cannot ask for prediction
resistance per request, so it is a property of the socket

* Split the build option ais2031 into ais2031_ntg1 (NTG.1 seeding strategy),
ais2031_drg3 (DRG.3 class) and ais2031_drg4 (DRG.4.10 reseeding limits), which
can now be selected independently - ais2031_drg3 and ais2031_drg4 are mutually
exclusive

* Add the build option ais2031_drg3: it applies the entropy source oversampling of
the sp80090c option without the request size based reseeding limits of DRG.4,
which are not brought back by setting sp80090c alongside; the status reports the
AIS 20/31 DRG classes the build satisfies (a DRG.4 build reports DRG.3 as well)

* NTG.1 seeding strategy: seed from the jitter RNG alone when it is operated in
its own NTG.1 mode (es_jent_ntg1 with jitterentropy >= 3.7.0), as it is NTG.1
conformant without a second entropy source

* Add eBPF-based scheduler and interrupt entropy sources (es_sched_ebpf,
es_irq_ebpf): no kernel patches required, in-program SP800-90B health tests,
zeroization of every collected raw sample when the sources are unloaded - the
in-program collection buffers and the ring buffer holding the events included -
raw entropy measurement tooling including the SP800-90B restart test in
addon/es_ebpf_testing

* Centralize asynchronous buffer management to collect entropy from slow entropy sources

* Add TPM2 entropy source

* Add PKCS11 entropy source

* SP800-90C compliance: all ES with zero entropy are inserted into DRBG as "additional info" or "personalization string" (compliance to section 2.6)

* SP800-90C / AIS 20/31 DRG.4.10: with sp80090c or ais2031_drg4 the bits a DRNG may produce without a full reseed are capped at 2^17 (drng_max_reseed_bits), and the reseed is triggered at three quarters of that limit (drng_reseed_threshold_bits capped at 98304 bits instead of 2^16) - reseeding dominates the throughput, so this gains 13-16% while leaving 32768 bits of output for the asynchronous reseed of a node DRNG to complete in

* fix: esdm_get_seed() hands back the output of all entropy sources again, the zero-entropy ones collected as additional data included, without clearing the entropy estimates of the creditable sources; the returned entropy count covers the creditable sources only

* Reseed the DRNGs proactively: an asynchronous worker reseeds a DRNG whose interval elapsed whether or not data was ever requested from it, brings up instances that never reached the fully seeded level, spreads the seed times over a random offset and sleeps until the next reseed falls due; the status reports the worker, its passes and the time left before each reseed

* fix: An RPC client decoded a response whose header it had just rejected, handing the caller a payload reaching past the receive buffer - for the random calls, data generated for an earlier request (found by the new fuzz harnesses)

* fix: An interrupted RPC call left its answer on the connection, where it was handed out as the reply to the next call and every call after it; the connection is now dropped when a call abandons its answer (found by the new fuzz harnesses)

* fix: The OpenSSL RAND providers stored a new context lock over the old one when locking was enabled twice, leaking it and leaving the users of the shared context locking different things (found by the new fuzz harnesses)

* Add fuzz harnesses for the RPC requests, responses and wire codec, the server as a client reaches it, both sides of the EGD interface and the library API (build option 'fuzzing', see tests/fuzz/README.md); beyond crashes they check what the code promised, and when building with -Dfuzzing=enabled their seeds are additionally replayed as regression tests by the ordinary test suite (meson test), also without libFuzzer

* Add a fuzz harness per shipped OpenSSL RAND provider module (build option 'openssl-rand-provider'), each loading its provider the way libcrypto does and holding it to the contract of <openssl/core_dispatch.h>

* Add a stress test of the RPC request path under concurrent load, every request carrying an ID the answer has to carry back

* FIPS 140 integrity test: a missing HMAC file is now a failed integrity test rather than a pass; the reference values are written at installation time with esdm-tool (see README.usage.md)

* FIPS 140 integrity test: attest every component of the module - the ESDM library, the Jitter RNG and the crypto library of the selected backend - and not only the executable

* Run the self tests of the hash and the DRNG implementation every 10 minutes, and hand out random bits only while their outcome, reported in the status, is that they passed

* Add a self test to every entropy source and run them in the same pass as the crypto ones, at start up and on the interval; a failing source is logged and reported but does not stop the ESDM, as it stops being credited on its own

* Run the self tests on demand over the privileged RPC socket (esdm_rpcc_selftest, esdm-tool --selftest), answered with the state of both test groups and how many entropy sources were tested and failed

* DRBG self tests: use CAVP records that reseed, so instantiate, reseed and generate are all covered as SP800-90A section 11.3 and FIPS 140-3 IG 10.3.A require

* Self tests: accompany every known answer test with two negative tests, so that neither a comparison that cannot fail nor an implementation ignoring its input passes as a self test

* esdm-tool: add --max-reseed-secs SECS to set the maximum interval between two DRNG reseeds

* Add the status as a JSON document next to the human-readable text: esdm_status_json() in libesdm, the RPC call esdm_rpcc_status_json() and esdm-tool --status-json; the ESDM properties are members, the entropy sources an array below "entropy_sources" (json-c is a new build dependency)

* Status report: add one section per DRNG instance - seeding state, reseed counters, seed generation and the time of the last seeding - to the status text and to the JSON document ("drngs" array), carrying the initial and the prediction resistance instance; an instance is identified by type and node now, so the "id" member is gone

* Status reports are no longer truncated silently: a report that does not fit into the buffer is answered with -EMSGSIZE, a JSON document empty and a text report as far as it got, so esdm_status() returns a value now

* Add an RPC call to obtain the status of a single DRNG instance as JSON, addressed by the node it serves or by asking for the prediction resistance instance

* esdm-tool: add --drng-status [=NODE|pr] and --drng-status-json [=NODE|pr] to print one DRNG instance or, without an argument, all of them as a JSON array

* libesdm: export only the supported API, versioned by a linker version script (symbol versions LIBESDM_1.0 for the API of esdm.h and esdm_config.h, LIBESDM_PRIVATE_1.0 for in-tree consumers); every other DSO_PUBLIC symbol is hidden

* Add man pages for esdm-server, esdm-tool, the CUSE daemons, esdm-proc, esdm-kernel-seeder, esdm-server-signal-helper, esdm-ebpf-collect, esdm-getrawentropy, esdm-extractlsb, the OpenSSL providers and the libesdm, libesdm_rpc_client, libesdm_egd_client, libesdm_getrandom and libesdm_aux_client libraries

* esdm-server and the CUSE daemons no longer fork into an isolating PID namespace by default; pass --pid_namespace to enable it (without it, esdm-server removes its IPC resources itself at exit, best effort)

* CPU ES: retry RDSEED up to 1024 times with PAUSE in between, as it underflows routinely under load, and retry transient RNDRRS failures on aarch64 the same way; a read failure no longer disables the CPU ES for the lifetime of the daemon, it is credited with no entropy until the next successful read

* CPU ES: on s390, only use PRNO-TRNG when the facility list and the PRNO query report it, instead of dying with SIGILL on hardware without it (pre-z14)

* Add a test that assesses 1 MiB of ESDM output with the SP800-90B non-IID estimators (ea_non_iid, skipped when not installed) and requires more than 6 bits of min-entropy per byte

* Add a thread sanitizer build (nix build .#esdm-tsan) running the test suite

* fix: data race on the job pointer of the worker thread slots (found by the thread sanitizer)

* fix: SHA-3 on big-endian machines: the aligned input path absorbed host-endian lanes, so the digest depended on the alignment of the input and the known-answer self tests failed

* fix: CUSE: a fallback read returning 0 bytes made the read loop spin forever; it now fails with -EIO

* fix: CUSE: writes at a non-zero file offset to the proc tunables read the wrong bytes of the payload

* fix: getentropy() of libesdm_getrandom returned -EIO for requests above 256 bytes instead of -1 with errno set

* fix: status shared memory: access the mapping through an atomic pointer so that a concurrent detach is not dereferenced, do not remove the segment at exit while CUSE daemons are still attached, and do not destroy and recreate the live IPC on esdm_reinit(), which stranded attached CUSE daemons on an orphaned mapping and unlinked semaphores

* fix: RPC client use-after-free when esdm_rpcc_fini_service() ran concurrently with a call, and a double free with two concurrent reallocating esdm_rpcc_init_*() calls

* fix: Linux kernel addon: the boot-time raw entropy capture overwrote its first sample, the read pointer of the per-CPU rings was published before the DRBG consumed the data, letting the producer overwrite it mid-hash, the block size guard compared bytes with bits, and a reset scrubbed only the online CPUs, so events of an offline CPU were credited after a VM fork or an SP800-90B failure

* fix: esdm-proc: /proc/sys/kernel/random/uuid read empty; a fresh UUID is now generated on every open, like the kernel's

* fix: OpenSSL backend: the additional data from the uncredited entropy sources was dropped on every reseed instead of entering the DRBG as additional input

* fix: Jitter RNG ES: a failed startup health test went unnoticed, and the Jitter RNG was credited regardless; when its collector could not be set up either, the initialization of the whole ESDM failed instead of continuing without the Jitter RNG

* fix: without a reseed worker (esdm_init() without esdm_init_monitor()), node DRNGs were never reseeded; a request now reseeds them itself

* fix: RPC server: a new connection could be closed as idle before its first request was read; the client now also retries once on a fresh connection when the server closes it without an answer

* fix: RPC and EGD servers: running out of file descriptors made the workers spin on the listening socket; they stop accepting until a connection closes or the idle timer fires

* fix: worker threads were cancelled asynchronously, which can strike in the middle of malloc(), the logger or a DRNG reseed holding its locks; cancellation is deferred now

* fix: esdm.spec: package the EGD client library and the EGD OpenSSL providers

* fix: DRNG manager: index the per-node DRNGs by the allocated array, so raising the node limit after the allocation no longer reads or frees past its end

* fix: a prediction resistance request no longer drops all DRNGs out of the seeded state; esdm_get_seed() could return nothing afterwards

* fix: SP800-90C: the prediction resistance DRNG counts as fully seeded only with the additional 64 bits of RBG3(RS) and withholds them from its output

* fix: only the seeding of the initial DRNG makes the ESDM operational, not that of any node DRNG

* fix: with a reseed interval of zero the initial DRNG was seeded twice per request

* fix: the auxiliary pool reports the digest size of its conditioning hash instead of the maximum

* fix: a failed Jitter RNG initialization no longer zeroes its configured entropy rate, so a later successful reinitialization is credited again

* fix: esdm_init() tears down what it set up when it fails; the timing entropy source rate setters are serialized; the start-up rate check counts every entropy source

* fix: RPC server: all server threads run in the isolating mount, cgroup and network namespaces, not only the main thread (a PKCS#11 module reaching a network HSM over TCP needs the network namespace switched off)

* fix: RPC server: the self test is refused to unprivileged clients; a response that cannot be packed is answered with a failure; a connection whose answer cannot be written is dropped instead of stalling the worker per request; a worker thread that cannot be started is noticed

* fix: RPC client: a past poll timeout no longer suppresses the reconnect after a broken connection

* fix: libesdm_getrandom: getrandom() with GRND_NONBLOCK returns EAGAIN while the ESDM is not seeded, and the library drops only the RPC client reference it took

* fix: CUSE: a non-blocking read that would block returns EAGAIN; the privileged ioctls require CAP_SYS_ADMIN instead of UID 0, as the kernel does; a negative RNDADDTOENTCNT is refused; 32 bit callers are served; the status ioctl serves a complete report only; a failed privilege drop ends the daemon instead of leaving it running as root

* fix: esdm-proc: every file's content is generated per open, so concurrent readers no longer share one buffer

* fix: esdm-kernel-seeder: refuse an interval outside 1 to INT32_MAX seconds

* fix: Linux kernel addon: convert entropy rates in 64 bit arithmetic

* fix: leancrypto backend: additional input beyond the 84 bytes the XDRBG accepts is condensed with SHA3-512 - leancrypto >= 1.9 refused the seed, so no DRNG was ever seeded; the hash init result is checked where leancrypto returns one

* fix: the DRBG sanity health check seeds the DRBG first, so its limit checks are reached; the Hash DRBG state is locked into memory; SHA-2 wipes its message schedule with memset_secure

* fix: logger: the log file is no longer closed at exit under a thread still writing to it; threading: the thread and parent of a worker slot are read atomically when signaling

* fix: esdm_safe_read()/esdm_safe_write() return the bytes transferred before a later error

* fix: a DRNG seed serves exactly ESDM_DRNG_RESEED_THRESH generate requests - the request that ran the counter out triggered the reseed and was counted against the old seed, so one fewer was served

* fix: esdm.spec requires the protobuf-c runtime instead of protobuf

* flake: provide the FIPS integrity reference values of the ESDM, the jitter RNG and Botan, and of the build tree in the coverage VMs; update nixpkgs; support Linux 7.2 and 7.3 in the kernel addon

* tests: integration test environments detect a missing daemon binary and a server that never came up; fixed sleeps replaced by polling for the seeded state; new regression tests for the fixes above

Changes 1.2.3
* Fix handling of non-blocking server response

* Reduce chunk size for the PR IPC interface to 32 bytes for more responsive
server

* CPU ES: Fix RDSEED to RDRAND fallback

* Allow PR DRNG to be used as RBG3(RS) in SP800-90C mode

* Fix SP800-90C instantiate for OpenSSL backend

Changes 1.2.2
* Add TPM 2.0 entropy source

* Reworked threading concept towards multi-connection workers for less memory usage

* Add jitterentropy status RPC call and expose in esdm-tool

* Kernel seeder: add systemd notify support, improve startup speed, double inserted entropy amount

* RPC: set non-blocking sockets, add timeout to non-blocking writes, simplify per-connection buffers, improved performance

* More robust signal handling, overflow checks and argument validation

* RPM SPEC file fixes for openSUSE

* add PPC DARN instruction availability check

* fix crasher in CUSE poller thread

* fix compilation with systemd=disabled

* esdm-server: Fix handling of SIGUSR1 sent by suspend/resume helper (they caused the server to terminate)

* Add backtracking resistance to internal state/output of aux pool

* Automatically add device specific personalization string based on product uuid from DMI, when available

* Assure 256 bit security level on all Intel CPUs

* Fixes for esdm_es and switch to 64 bit timestamps and usage of time deltas

* Support for Linux kernel 6.18 in esdm_es

* Added support for NTG.1 compliant jitterentropy-library 3.7.0

* remove minimally seeded stage

* remove placeholder for atomic DRNG

Changes 1.2.1
* Reduce lock contention and increase throughput (thanks to Markus Theil)

* Add helper tool to externalize the C API to command line (thanks to Markus Theil)

* Update OpenSSL backend (thanks to Markus Theil)

* Update Botan backend (thanks to Markus Theil)

* Update systemd for SLES / Tumbleweed to prevent shutdown hangs

* Establish AIS20/31 DRG.4 compliance (thanks to Markus Theil)

* Place Linux RNG seeder into its own application to avoid chicken-egg problem inside the ESDM (thanks to Markus Theil)

* NTG.1 updates to comply with AIS 20/31 v3.0

* Linux kernel ES: Add cryptographic post-processing with state for esdm_es (SP800-90A DRBG).
  Only use high resolution time code path from now on. All known current CPUs
  support this and allow for storage of fixed with timestamps. Timestamps
  are now stored per CPU and directly take part in a combined seed of multiple
  per-CPU buffers via a scather gather list. Clear state when suspending or
  rebooting.

* Don't expose testing interface of esdm_es when in lockdown mode.

* Add NIST test vectors for Botan HMAC-DRBG(SHA-512).

* Fix: RDRAND feature detection.

* Fix: performance with many worker threads on many core systems.

* Added improved systemd support (notify, socket activation). Switch default
  path to /run in order to prevent systemd deprecation notices. Small refactoring
  of systemd service generation to unify socket and non-socket activation paths.

* Fix: FIPS 140 init works now, added checksum generation to esdm-tool for better
  scripting.

* Add explicit OSR to esdm_es. Expose different ES' via Makefile options.

Changes 1.2.0
* fix: to prevent a DoS against the RPC channel, limit the slow operations of esdm_get_random_bytes_pr and esdm_get_seed to allow only one call in flight. If another call comes in while one process is ongoing, return -EAGAIN to free the RPC channel.

* fix: handle rogue libesdm-aux clients more gracefully - if a client received a notification to supply entropy, but it fails to send anything, the ESDM will not send a notification again. This issue is alleviated by checking the need_entropy common variable

* switch from CLOCK_REALTIME to CLOCK_MONOTONIC for wait operations

* add esdm.spec file for generating an RPM

Changes 1.1.1:
* fix: properly use the mutex absolute time argument, timedlock handling and mutex destruction in the ESDM RPC client lib

* fix: race condition in worker thread execution

Changes 1.1.0:
* fix: name of leancrypto DRNG

* fix: getentropy returns 0 on success

* enhancement: only establish connection to server once and when needed

* fix: SHM in CUSE must be attached RD/WR

* enhancement: add esdm_aux_client library

Changes 1.0.2:
* hardening: enable -fzero-call-used-regs=used-gpr

* editorial: rename logging* symbols to esdm_logging* - this is purely internal, but considering some of these symbols are externally visible, libesdm_rpc_client pollutes the namespace of consumers

* enhancement: significant performance increase of RPC communication

* fix: Poll writer woke up as status variable was not properly initialized

* fix: proper shut down sequence of ESDM daemons

Changes 1.0.1:
* enhancement/fix: add support for multiple ESDM RPC client connection initializations

* fix: If a process select/poll on a CUSE file, the system now goes properly to sleep

* fix: If there is high load on the CUSE daemons - make sure they properly shut down on reboot

Changes 1.0.0:
* fix (re)initialization of ESDM to set correct entropy level

* IRQ/Sched ES: add support to retry accessing the kernel with -i and -s flags

* enhancement: Jitter RNG ES generates data asynchronously

* enhancement: add kernel Jitter RNG ES

* enhancement: add leancrypto, OpenSSL and Botan crypto provider backends

* enhancement: add OpenSSL, Botan seed provider (leancrypto ESDM seed provider is found in leancrypto source code)

* fix: ESDM server - systemd unit executes server in current mount namespace

* editorial: apply clang-format

* fix: CUSE daemons may hang during shutdown due to busy mounts

* fix: resynchronize CUSE daemons and ESDM server upon ESDM server restart

* enhancement: ESDM server status splits up FIPS 140 and SP800-90C compliance

* rename compile time option "oversample_es" to "sp80090c" which is now disabled
  by default considering that with its enabling, the oversampling is applied
  unconditionally during startup

Changes 0.6.0:
* Move ESDM apps into separate namespaces to limit their privilege even further (e.g. no possibility to create network connections)

* Add German AIS 20/31 (draft 2022) NTG.1 compliance support

* the blocking property of an interface is implemented in the client - the
  server reports -EAGAIN for a blocking behavior

* add "emergency seeding" when entropy sources cannot collectively deliver
  256 bits of entropy, pull data repeatedly until 256 bits are received

* export esdm_rpc_client.h with all depending header files to allow external
  clients to be developed

* update IRQ/Scheduler ES health test to match LRNG

* bug fix: correctly calculate memory offsets

* enhancement: Sched/IRQ ES code in ESDM can handle if kernel-parts have
  different data structure size for sending entropy to user space

* IRQ/Sched ES: Switch to /dev/esdm_es character devices a user space interfaces

Changes 0.5.0:
* Linux kernel entropy feeder is now always enabled

* Add Linux /dev/hwrng entropy source

* FIPS IG 7.19/D.K / BSI NTG.1: use a new DRNG instance executed with PR

* Handle communication errors between client and server gracefully

* ES monitor now runs for lifetime of the ESDM

* add interface to access entropy sources - esdm_get_seed including making it accessible via getrandom(2)

* fix of deadlocks during shutdown

Changes 0.4.0:
* Start CUSE daemons independently from ESDM server

* add support for invoking DRNG with prediction resistance when opening
  /dev/random with O_SYNC or using the esdm_get_random_bytes_pr API.
  This reestablishes the NTG.1 property as well as well as supports
  using the DRBG as a conditioning component pursuent to SP800-90C and
  FIPS 140 IG 7.19 / D.K.

* initialize the DRNG immediately with 256 bits (disregarding 32/128 bits)

* add interrupt entropy source

* modify collection in scheduler ES: maintain a hash state per CPU as a per-CPU entropy pool

* add proper interrupt/signal handling code to the ESDM RPC client library

* privilege level change in CUSE is now limited to caller only

* add support to allow ld.so.preload to be used to refer to libesdm-getrandom.so for a system-wide replacement of getrandom/getentropy system call.

Changes 0.3.0:
* Replace protobuf-c-rpc with built-in RPC mechanism reducing amount of mallocs,
  performing proper zeroization and being fully thread-aware

* Testing: disable /dev/random fallbacks for verifying RPC operation

* RNDGETENTCNT returns the seed state of the auxiliary entropy pool only. This
  makes it 100% ABI compliant to random.c

* Add ChaCha20 DRNG to regular code base

* Add SHA-3 conditioning hash to regular code base

* Add /proc/sys/kernel/random files handler along with SELinux policy, tested
  with:
	- rng-tools
	- jitterentropy-rngd
	- haveged

Changes 0.2.0:
* Initial public version
