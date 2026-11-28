#import "../template.typ": *

= Developing with the ESDM <sec:development>

This chapter addresses developers who integrate the #ac("ESDM") or extend it.
It covers where the code is located, which processes it runs, how the two
managers at its core work, how to use it from C, Rust and Python, how to feed
it entropy, how to add an entropy source, a crypto backend, an #ac("RPC") call
or a build option, how to debug the #ac("ESDM"), and which conventions the
tree follows.
Chapter @sec:design gives the design the code implements, chapter
@sec:building-installing the build, chapter @sec:testing the tests; the man
pages in `man/` document every program and library.

== Code Structure <sec:code-structure>

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Directory], [Content]),
    [#icon("folder") `esdm/`],
      [The library `libesdm`: the entropy source manager (`esdm_es_mgr.c`), the
      #ac("DRNG") manager (`esdm_drng_mgr.c`), the entropy sources
      (`esdm_es_*.c`, `es_cpu/`, `es_ebpf/`), the crypto backends
      (`esdm_builtin_*.c`, `esdm_openssl.c`, ...), the configuration
      (`esdm_config.c`), the status (`esdm_info.c`) and the #ac("FIPS") self
      tests],
    [#icon("folder") `crypto/`],
      [The builtin primitives: ChaCha20, the Hash #ac("DRBG"), SHA-2, SHA-3,
      #ac("HMAC")],
    [#icon("folder") `common/`],
      [Code shared by all parts: logging, threads, locks, buffers, the
      #ac("FIPS") integrity test, systemd support],
    [#icon("folder") `service-rpc/`],
      [The #ac("RPC") protocol (protobuf-c), its server inside `esdm-server` and
      the client library `libesdm_rpc_client`],
    [#icon("folder") `service-egd/`],
      [The #ac("EGD") server inside `esdm-server` and the client library
      `libesdm_egd_client`],
    [#icon("folder") `frontends/`],
      [The programs: `esdm-server`, the #ac("CUSE") daemons (`cuse/`),
      `libesdm-getrandom.so`, the OpenSSL providers, `esdm-kernel-seeder`, the
      auxiliary client, `esdm-tool`, the suspend and resume helper],
    [#icon("folder") `es-ext/`],
      [The library for external entropy source providers, the #acs("PKCS")\#11
      and #ac("PC/SC") providers and an example],
    [#icon("folder") `kernel/`],
      [The kernel modules `esdm_es` (interrupt and scheduler entropy sources)
      and `esdm_cdev` (character devices)],
    [#icon("folder") `addon/`],
      [The SELinux policy of `esdm-proc`, helper scripts],
    [#icon("folder") `tests/`],
      [The test suite, one directory per component],
    [#icon("folder") `doc/`],
      [This document, the slides and the poster (`doc/typst`)],
  ),
  caption: [The directories of the source tree],
) <tab:code-structure>

== Processes <sec:processes>

#figure(
  image("../figures/processes.svg", width: 100%),
  caption: [Processes and #ac("IPC") of the #ac("ESDM")],
) <fig:processes>

Figure @fig:processes shows the processes and how they communicate:

- `esdm-server` holds the #ac("ESDM"): the library `libesdm` with its two
  managers, the #ac("RPC") workers and the #ac("EGD") server. It starts as root
  to set up its namespaces and the entropy sources that need privileges, then
  drops its privileges (section @sec:components). Its threads are the #ac("RPC")
  workers – `threading_max_worker_threads` at most – the #ac("EGD") server, the
  reseed worker that seeds the #ac("DRNG") instances and, with
  `es_parallel_fetch`, one thread per entropy source during a reseed.

- The frontends – the #ac("CUSE") daemons, `esdm-proc`, `esdm-kernel-seeder` –
  and the libraries in consumer processes reach the server over the #ac("RPC")
  protocol on two Unix domain sockets, an unprivileged and a privileged
  one. The #ac("CUSE") daemons and the auxiliary client learn the state of the
  #ac("ESDM") from a shared memory segment without an #ac("RPC") call.

- Consumers that need a minimal protocol – sandboxed processes, the OpenSSL
  #ac("EGD") providers – and the kernel module `esdm_cdev` use the #ac("EGD")
  sockets.

- The kernel module `esdm_es` delivers the timestamps of interrupts and
  scheduler events through `/dev/esdm_es`; external entropy source providers
  are processes of their own on a Unix domain socket (section
  @sec:ext-es).

== Entropy Source Manager <sec:es-manager>

`esdm/esdm_es_mgr.c` gathers the entropy for every seed. Each entropy source
registers a `struct esdm_es_cb` (`esdm_es_mgr_cb.h`) in the array `esdm_es`
of `esdm_es_mgr.c`:

```c
struct esdm_es_cb {
	const char *name;
	int (*init)(void);
	int (*monitor_es)(void);
	void (*fini)(void);
	void (*get_ent)(struct entropy_es *eb, uint32_t requested_bits);
	uint32_t (*curr_entropy)(uint32_t requested_bits);
	uint32_t (*max_entropy)(void);
	void (*state_json)(char *buf, size_t buflen);
	void (*reset)(void);
	bool (*active)(void);
	int (*selftest)(void);
	bool (*read_failed)(void);
};
```

`get_ent` fills the slot of the source in the seed buffer with data and the
entropy it credits to them; `curr_entropy` and `max_entropy` tell the manager
beforehand what the source can deliver. The credit is the configured
entropy rate of the source; a source whose read or health test failed
credits nothing. The manager fills the seed buffer from all sources –
in parallel with `es_parallel_fetch` – and adds up the credits (section
@sec:seeding). `esdm_fully_seeded()` decides whether that suffices:

- by default 256 bits;
- 384 bits for the initial seed with oversampling (`sp80090c`, `fips140`,
  `ais2031_drg3`, `ais2031_drg4`);
- with `ais2031_ntg1`, 240 bits from each of two sources for the initial
  seed, or 240 bits from the Jitter #acs("RNG") in its NTG.1 mode;
- with `es_jent_ntg1` alone, as by default: the Jitter #acs("RNG") in its NTG.1
  mode applies the start-up rule of NTG.1 – 240 bits from each of its two
  noise sources – itself, so that the #ac("ESDM") need not apply it;
- 256 bits for every later reseed.

#par(first-line-indent: 0pt)[A reseed is skipped while less than 256 bits
are available. The #ac("ESDM") is operational once its initial #ac("DRNG") is
fully seeded. Figure @fig:es-manager shows the flow.]

#figure(
  image("../figures/es-manager.svg", width: 75%),
  caption: [How the entropy source manager seeds a #ac("DRNG")],
) <fig:es-manager>

== DRNG Manager <sec:drng-manager>

`esdm/esdm_drng_mgr.c` runs the #ac("DRNG") instances: one per node up to the
number of worker threads, the one of node zero being the initial #ac("DRNG"),
and the prediction resistance #ac("DRNG") (section @sec:numa). A request goes to
a fully seeded node #ac("DRNG") with budget left, else to the initial
#ac("DRNG")\; each generate operation produces at most 4096 bytes, 65536 bytes
with the reseeding limits of `sp80090c` and `ais2031_drg4`. Table
@tab:path-classes lists how each call is served.

A #ac("DRNG") instance is reseeded

- after $2^20$ generate operations,
- after 600 seconds (`esdm_set_reseed_max_time`),
- after `drng_reseed_threshold_bits` of output, three quarters of $2^17$
  bits with the reseeding limits,
- on demand: the #ac("IOCTL") `RNDRESEEDCRNG`, a resume, and data written to
  the auxiliary pool while not all #ac("DRNG") instances are fully seeded
  (section @sec:seeding-triggers).

#par(first-line-indent: 0pt)[The prediction resistance #ac("DRNG") is reseeded
before every chunk it generates. A #ac("DRNG") instance that reaches $2^30$
generate operations or `drng_max_reseed_bits` of output without a full
reseed is no longer fully seeded; for the initial #ac("DRNG"), the #ac("ESDM")
is no longer operational until a full reseed succeeds (section
@sec:not-fully-seeded). Figure @fig:drng-states shows the states.]

#figure(
  image("../figures/drng-states.svg", width: 50%),
  caption: [The states of a #ac("DRNG") instance],
) <fig:drng-states>

== A Development Build <sec:building>

A development build enables the test interfaces, and with clang or gcc the
sanitizers of section @sec:sanitizers:

```sh
meson setup build -Dtestmode=enabled -Db_sanitize=address,undefined
meson compile -C build
meson test -C build
nix flake check     # the builds, the VM tests, this documentation
```

`testmode` compiles in the hooks and test interfaces the suite needs
(section @sec:test-suite); chapter @sec:building-installing gives the
requirements and chapter @sec:build-options every option.

#warning-note[Never enable `testmode` in production: it compiles in fault
injection and test hooks and moves the sockets of the #ac("ESDM") to `/tmp`.]

== Using the ESDM from C <sec:using-c>

A program reaches the #ac("ESDM") server over the #ac("RPC") client library,
without linking the #ac("ESDM") itself:

```c
#include <stdint.h>
#include <stdio.h>
#include <esdm/esdm_rpc_client.h>

int main(void)
{
	uint8_t buf[32];
	ssize_t ret;

	/* One connection setup per process, NULL: no interrupt callback */
	if (esdm_rpcc_init_unpriv_service(NULL))
		return 1;

	/* Full path: waits until the ESDM is operational */
	ret = esdm_rpcc_get_random_bytes_full(buf, sizeof(buf));
	esdm_rpcc_fini_unpriv_service();
	if (ret != sizeof(buf))
		return 1;

	for (size_t i = 0; i < sizeof(buf); i++)
		printf("%02x", buf[i]);
	printf("\n");
	return 0;
}
```

```sh
cc -o example example.c $(pkg-config --cflags --libs esdm_rpc_client)
```

`esdm_rpcc_get_random_bytes_pr` serves the prediction resistance path,
`esdm_rpcc_get_seed` the seed path; table @tab:interfaces lists all calls.
A program that runs the #ac("ESDM") itself, as `esdm-server` does, links
`libesdm` and calls `esdm_init()`, `esdm_get_random_bytes_full()` and
`esdm_fini()` of `esdm.h` instead. Without `esdm_init_monitor()`, which the
server runs on a thread, such a process has neither the reseed worker nor the
#ac("ES") monitor: its #ac("DRNG", pl: true) are seeded by `esdm_init()` and
reseeded by the requests that find a reseed due, and a blocking call that
waits for the #ac("ESDM") to be seeded collects from the entropy sources
itself, about twice a second, until they deliver. Such a process does not take the
#ac("ESDM") across a `fork()`: the child holds a copy of every #ac("DRNG")
state, which would repeat the output of the parent, but none of the threads
that seed. In the child, every call for random data or a seed fails with
`-EOPNOTSUPP`, the copied states of the builtin #ac("DRNG", pl: true) are
cleared and `esdm_fini()` returns at once; states held by another crypto
library and the entropy still in the pools stay in the memory of the child,
but are never output. A process therefore initializes the #ac("ESDM") after
its fork, as `esdm-server` does. `esdm_fini()` is final as well: after it,
every call for random data or a seed fails with `-EOPNOTSUPP`, a call that
waited for the #ac("ESDM") to be seeded at that time included, and
`esdm_init()` fails with `-ESHUTDOWN`.

== Using the ESDM from Rust and Python <sec:using-languages>

A program in any language reaches the #ac("ESDM") in one of three ways:

- Over a binding of the #ac("RPC") client library, the most direct way: it
  serves every path and waits until the #ac("ESDM") is operational.

- Through glibc's `getrandom()`, which `libesdm-getrandom.so` replaces when
  preloaded with `LD_PRELOAD`: Python's `os.urandom()`, `os.getrandom()`
  and `secrets` call it, as does Rust's crate `getrandom` from version 0.3
  on, and with it `rand::rng()`. The crate `getrandom` 0.2 and statically
  linked programs call the kernel directly and bypass the shim.

- Through the #ac("CUSE") `/dev/random` or `/dev/esdm_random` of `esdm_cdev`, as
  a file.

#par(first-line-indent: 0pt)[The shim and the #ac("CUSE") devices fall back to
the kernel when the #ac("ESDM") cannot be reached (table
@tab:integration-gate).]

#paragraph[Rust][The crate `rand-esdm` (version 0.5.0 or later) wraps the
client libraries. `EsdmRng` serves the full path (`FullySeeded`) or the
prediction resistance path (`PredictionResistant`) and implements the
traits of `rand_core`; `EsdmConnection` reads the status,
`EsdmPrivConnection` offers the privileged calls to root. Building it needs
the client libraries through `pkg-config` and clang for its bindings:]

```sh
cargo add rand-esdm rand
```

```rust
use rand::RngExt;
use rand::rand_core::{TryRng, UnwrapErr};
use rand_esdm::{EsdmConnection, EsdmRng, EsdmRngType};

fn main() -> std::io::Result<()> {
    // Fallible: waits until the ESDM is fully seeded, reports an io::Error
    let mut rng = EsdmRng::try_new(EsdmRngType::FullySeeded)?;
    let mut key = [0u8; 32];
    rng.try_fill_bytes(&mut key)?;

    // An Rng of the rand crate; panics if the ESDM cannot deliver
    let mut rng = UnwrapErr(EsdmRng::new(EsdmRngType::PredictionResistant));
    let nonce: u64 = rng.random();
    println!("{nonce:016x}");

    let status = EsdmConnection::try_new()?.status()?;
    println!("fully seeded: {}", status.fully_seeded);
    Ok(())
}
```

#paragraph[Python][Preloading the shim serves `os.urandom()`, `secrets`
and `os.getrandom()` from the #ac("ESDM"), `os.getrandom(n, os.GRND_RANDOM)`
from the prediction resistance path; `ssl.RAND_bytes()` follows the OpenSSL
configuration of section @sec:integration-openssl:]

```sh
LD_PRELOAD=/usr/lib64/libesdm-getrandom.so \
    python3 -c 'import secrets; print(secrets.token_hex(32))'
```

#par(first-line-indent: 0pt)[`ctypes` binds the #ac("RPC") client library
without a compiler; it releases the global interpreter lock during the call, so
a request waiting for the #ac("ESDM") does not hold up the other threads:]

```python
import ctypes
import ctypes.util

esdm = ctypes.CDLL(ctypes.util.find_library("esdm_rpc_client")
                   or "libesdm_rpc_client.so.1")
esdm.esdm_rpcc_init_unpriv_service.argtypes = [ctypes.c_void_p]
esdm.esdm_rpcc_get_random_bytes_full.argtypes = [ctypes.c_char_p,
                                                 ctypes.c_size_t]
esdm.esdm_rpcc_get_random_bytes_full.restype = ctypes.c_ssize_t


def esdm_random(n):
    """n bytes of the full path; waits until the ESDM is operational"""
    buf = ctypes.create_string_buffer(n)
    ret = esdm.esdm_rpcc_get_random_bytes_full(buf, n)
    if ret != n:
        raise OSError(-ret if ret < 0 else 0, "ESDM request failed")
    return buf.raw


if esdm.esdm_rpcc_init_unpriv_service(None):
    raise OSError("ESDM RPC client setup failed")
print(esdm_random(32).hex())
```

== Feeding Entropy with the Auxiliary Client <sec:aux-client>

`libesdm_aux_client` lets a daemon feed the auxiliary pool when the #ac("ESDM")
asks for entropy rather than on a timer: `esdm-server` posts a #ac("POSIX")
semaphore while its auxiliary pool holds less entropy than
`write_wakeup_threshold`, and the daemon waits on it, reads its noise
source and inserts the data. Crediting entropy requires the privileged
#ac("RPC") call, so the daemon runs as root; the deadline of the wait is absolute, on
`CLOCK_MONOTONIC`:

```c
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <esdm/esdm_aux_client.h>
#include <esdm/esdm_rpc_client.h>

/* The daemon's noise source: fills buf, returns 0 on success */
int read_noise(uint8_t *buf, size_t len);

int main(void)
{
	uint8_t buf[64];
	int ret;

	if (esdm_aux_init_wait_for_need_entropy() ||
	    esdm_rpcc_init_priv_service(NULL))
		return 1;

	for (;;) {
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec += 60;
		if (esdm_aux_timedwait_for_need_entropy(&ts)) {
			if (errno == ETIMEDOUT)
				continue;	/* the ESDM did not ask */
			break;
		}

		if (read_noise(buf, sizeof(buf)))
			break;
		/* credited with what the assessment of the source gives */
		esdm_invoke(esdm_rpcc_rnd_add_entropy(buf, sizeof(buf), 256));
		explicit_bzero(buf, sizeof(buf));
		if (ret)
			break;
	}

	esdm_rpcc_fini_priv_service();
	esdm_aux_fini_wait_for_need_entropy();
	return 0;
}
```

```sh
cc -o feeder feeder.c noise.c \
    $(pkg-config --cflags --libs esdm_aux_client esdm_rpc_client)
```

Data inserted this way has no slot, health test or status of its own in
the #ac("ESDM") (section @sec:aux); a noise source that should have them is
implemented as an external entropy source (section @sec:writing-es-ext).

== Writing an External Entropy Source <sec:writing-es-ext>

An external entropy source runs in a provider process of its own, which the
#ac("ESDM") server reads over a Unix domain socket
(`esdm-server --es_ext PATH`). A provider implements the callbacks of
`struct esdm_es_ext_plugin` (`esdm_es_ext.h`) and hands them to
`esdm_es_ext_provider_main()` of `libesdm_es_ext`:

```c
static const struct esdm_es_ext_plugin my_source = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = "my-noise-source",
	.init = my_init,
	.fini = my_fini,
	.get_entropy = my_get_entropy,   /* data and its entropy in bits */
	.selftest = my_selftest,
	.status_json = my_status_json,
	.entropy_rate = my_entropy_rate,
};

int main(int argc, char *argv[])
{
	return esdm_es_ext_provider_main(&my_source, argc, argv);
}
```

`es-ext/example/esdm_es_ext_example.c` is a complete example provider; the
#acs("PKCS")\#11 and #ac("PC/SC") providers serve real devices. The #ac("ESDM")
trusts a provider's claim up to `es_ext_entropy_rate`; a crash of a provider
affects only the provider itself, and the #ac("ESDM") connects again once the
provider runs again (`libesdm_es_ext`(3)).

== Adding a Crypto Backend <sec:adding-backend>

A crypto backend provides a #ac("DRNG") and a hash through the callbacks of
`esdm/esdm_crypto.h`:

```c
struct esdm_drng_cb {
	const char *(*drng_name)(void);
	int (*drng_selftest)(void);
	int (*drng_alloc)(void **drng, uint32_t sec_strength);
	void (*drng_dealloc)(void *drng);
	int (*drng_seed)(void *drng, const uint8_t *inbuf, size_t inbuflen,
			 const uint8_t *addtl, size_t addtllen);
	ssize_t (*drng_generate)(void *drng, uint8_t *outbuf, size_t outbuflen);
};
```

`struct esdm_hash_cb` follows the same pattern for the hash. The existing
backends – `esdm_builtin_*.c`, `esdm_openssl.c`, `esdm_gnutls.c`,
`esdm_leancrypto.c`, `esdm_botan.cpp` – show the pattern; the meson option
`crypto_backend` selects one (section @sec:backends). A backend's #ac("DRNG")
must meet DRG.3 to keep the claims of chapter @sec:configurations.

== Adding an Entropy Source <sec:adding-es>

A noise source that needs no privileges of the server and no access to its
internals is best implemented as an external entropy source (section
@sec:writing-es-ext): it builds and runs without a change to the #ac("ESDM").
A source that must run inside the server, as the Jitter #acs("RNG") or the
kernel interfaces do,
requires the following steps, for which `esdm/esdm_es_hwrand.c` is a short example:

+ `esdm/esdm_es_<name>.c` and `.h` implement the callbacks of
  `struct esdm_es_cb` (section @sec:es-manager) and export the instance.
+ `esdm/esdm_es_mgr_cb.h` adds an entry to `enum esdm_external_es` before
  `esdm_ext_es_aux`, which must stay the last source, and
  `esdm/esdm_es_mgr.c` the instance to the array `esdm_es`, both under the
  define `ESDM_ES_<NAME>`.
+ `meson_options.txt` receives the options `es_<name>` and
  `es_<name>_entropy_rate`, `common/meson.build` turns them into the defines
  of `config.h`, and `esdm/meson.build` adds the source file when the option
  is enabled.
+ `esdm/esdm_config.c` holds the entropy rate: a member of `esdm_config`
  with the build option as its default, a getter and a setter, and the check
  in `esdm_config_init()` that caps the rate at the security strength.
+ `state_json` reports the state of the source in the status of the
  #ac("ESDM")\; a test below `tests/es/` checks its reads and its state with
  `tests/es_state_check.h`.
+ `doc/tools/gen_meson_options.py` updates the option reference, and a
  source that changes what the #ac("ESDM") can claim updates chapter
  @sec:configurations in the same commit.

#par(first-line-indent: 0pt)[The entropy rate of a new source defaults to 0
until an assessment such as those of chapters @sec:kernel-es-assessment and
@sec:ebpf-assessment justifies a credit.]

== Adding an RPC Call <sec:adding-rpc>

The #ac("RPC") protocol is defined in protobuf: `service-rpc/service/pb/`
holds `unpriv_access.proto`, the calls of every user, and
`priv_access.proto`, those of root. A new call requires the following steps,
following the example of `RpcGetEntLvl`:

+ The `.proto` file receives the call in its `service` and, where needed, its
  request and response messages; the C code of the protocol is generated
  again and checked in:

  ```sh
  cd service-rpc/service/pb
  protoc-c --c_out=.. common.proto priv_access.proto unpriv_access.proto
  ```

+ `service-rpc/server/esdm_rpc_<call>_s.c` serves it: a function
  `esdm_rpc_<call>`, which the macro `UNPRIV_ACCESS__INIT(esdm_)` or
  `PRIV_ACCESS__INIT(esdm_)` of the generated code finds by its name, declared
  in
  `service-rpc/service/esdm_rpc_service.h`. It checks the request, calls the
  library and answers exactly once through the closure.
+ `service-rpc/client/esdm_rpc_<call>_c.c` calls it: `esdm_rpcc_<call>` and
  `esdm_rpcc_<call>_int`, declared in `esdm_rpc_client.h`.
+ Both files go into the source lists of their `meson.build`; tests in
  `tests/rpc_client/` and `tests/rpc_service/` and the request and response
  fuzzers of `tests/fuzz/` cover the new messages.

#par(first-line-indent: 0pt)[The server reads requests of any client, so a
handler bounds every length it takes from a request (section
@sec:bounded-input).]

== Adding a Build Option <sec:adding-option>

A build option is added to `meson_options.txt`, in the group it belongs to.
The first line of its description is its summary, which `meson configure`
and chapter @sec:build-options show; the following paragraphs give the
details.
`common/meson.build` passes it to the code as a define of `config.h`; a
source file that only the option needs is added in its `meson.build` when
the option is enabled, as `esdm/meson.build` does for the entropy sources.
`doc/tools/gen_meson_options.py` then updates the reference of chapter
@sec:build-options; its `--check` and `doc/tools/check_identifiers.py` fail
when the documentation names an option that does not exist or the reference
is not current.

== Debugging <sec:debugging>

Each `-v` of `esdm-server` raises the verbosity of its log by one level, up
to debug output, and keeps the server in the foreground; `-S` sends the log to
syslog instead.
`esdm-tool --status` shows the state of every entropy source and #ac("DRNG")
instance, `--status-json` the same as #ac("JSON"). A debugger attaches best
to a server started in the foreground without `--pid_namespace`, and needs
root, as the server changes its user after its initialization. `meson test`
keeps the output of every test in `build/meson-logs/testlog.txt`; `meson test -C build <name> -v` runs a
single test with its output on the terminal. The commands of chapter
@sec:tools list every option.

== Protocol Compatibility <sec:protocol-compat>

The #ac("RPC") protocol has no version field and no handshake: the framing
header gives the index of the call in its protobuf service, the length and a
request identifier. A call added at the end of a service and a field added to
a message leave older peers working, as protobuf skips unknown fields; a
call inserted or removed, or a field changed, breaks them without either side
noticing. The project gives no compatibility promise across releases:
client libraries and server are released and updated together (section
@sec:usage-updating). The shared libraries carry the major version as their
soname. The status in shared memory, the protocol of the external entropy
sources and `struct esdm_es_ext_plugin` do carry versions, which their
readers check.

== Reporting Vulnerabilities <sec:vuln-reporting>

The repository defines no process for reporting vulnerabilities: it has no
`SECURITY.md` and names no security contact. Stating a contact and a
disclosure policy remains an open point for the authors. Until then, a report goes to the
authors named on the title page rather than to the public issue tracker.

== Conventions <sec:conventions>

- The code follows the Linux kernel coding style: tabs of eight columns,
  lines of 80 columns, `.clang-format` and `.editorconfig` at the top of the
  tree; `addon/clang-format-helper.sh` formats the tree, the generated
  protobuf code excepted.
- A commit message starts with the component it changes and a lowercase
  summary – `server: no core dumps after the privilege drop` – and carries a
  `Signed-off-by` line.
- A change that users notice adds an entry to `CHANGES.md`; a change of a
  compliance claim updates chapter @sec:configurations in the same commit.
