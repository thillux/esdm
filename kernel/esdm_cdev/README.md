# ESDM Character Devices in the Kernel

The kernel module `esdm_cdev` serves the random numbers of the ESDM running in
user space through character devices of the kernel, as the CUSE frontend
(`esdm-cuse-random`, `esdm-cuse-urandom`, `esdm-proc`) does from user space:

* `/dev/esdm_random` with the semantics of the kernel's `/dev/random`,
* `/dev/esdm_urandom` with the semantics of the kernel's `/dev/urandom`,
* `/proc/esdm/` with the files of `/proc/sys/kernel/random` and the status of
  the ESDM.

The kernel's own `/dev/random`, `/dev/urandom` and `/proc/sys/kernel/random`
stay untouched.

The module reaches the ESDM over its EGD socket, with the standard EGD commands
and the ESDM's extensions of them (see `service-egd/esdm_egd_protocol.h`). That
interface is opt-in, so it has to be enabled for the module to be served:

    systemctl enable --now esdm-server-egd.socket

or `esdm-server --egd_socket /run/esdm-egd.socket`. An ESDM from before the
extensions closes the connection on them; the module then behaves as with no
ESDM at all, see below.

## Building and Loading

    make KERNEL_DIR=/lib/modules/$(uname -r)/build
    insmod esdm_cdev.ko

in this directory of the ESDM source tree, whose
`service-egd/esdm_egd_protocol.h` the module takes the EGD protocol from. The
module needs no kernel patches and builds on Linux 6.1 and later. The flake
of this repository packages it as `esdm_cdev` of its kernel package sets, and
builds it against every kernel it knows (`esdm_cdev_<version>`, with the
warnings of `W=1` as errors).

The module can be loaded before the ESDM runs, and the ESDM can be restarted at
any time: the module connects when it is first used and reconnects on its own.

### Parameters

| Parameter     | Default                | Meaning |
|---------------|------------------------|---------|
| `egd_socket`  | `/run/esdm-egd.socket` | Path of the ESDM's EGD socket, the default of the `esdm-server-egd-socket-path` build option |
| `connections` | 4                      | Connections to the ESDM, 1 to 64. Each serves one request at a time |
| `timeout_ms`  | 5000                   | Bound on connecting and on every transfer, 100 to 60000, writable at runtime |

## The Devices

Both devices are world readable and writable, as the kernel's are.

* `/dev/esdm_random` reads from the ESDM's DRNG once the ESDM is operational -
  its DRNG fully seeded - and waits for that before. A reader with `O_NONBLOCK`
  gets `EAGAIN` instead, and `poll()` reports the device readable once the ESDM
  is operational, writable before, as the kernel's `random_poll()` does.
* `/dev/esdm_urandom` reads from the ESDM's DRNG without waiting for it to be
  fully seeded. Like the kernel's `/dev/urandom`, it has no `poll()`: it is
  always readable and writable.
* Opened with `O_SYNC`, either device reads from the ESDM's prediction
  resistance DRNG, which hands out no more than its entropy sources just
  delivered, as the CUSE frontend does. Without `O_NONBLOCK` a read waits for
  the rest; with it, the read returns what was there, or `EAGAIN`.
* Data written to either device is mixed into the ESDM's auxiliary pool
  without being credited with entropy, as a write to the kernel's devices is.

`/dev/esdm_random` reads from the fully seeded DRNG rather than from the
prediction resistance one: that is what the kernel's `/dev/random` is since
Linux 5.6 - equivalent to `getrandom(0)` - and what the CUSE frontend's
`/dev/random` serves. Prediction resistance remains available through `O_SYNC`;
as the default it would make every read wait for the entropy sources, which
deliver a few hundred bytes per second at best.

Signals end reads and writes. A read that got data returns it, one that did
not returns `ERESTARTSYS`, so the caller sees `EINTR` or the read is restarted,
even a read of a single byte. That differs from the kernel's devices, whose
reads finish at least their first page whatever signal comes: they do not wait
for anything once the kernel's RNG is initialized, while the module waits for
the ESDM's answers, interruptibly. A write ended by a signal returns what was
written.

### ioctls

The ioctls of `drivers/char/random.c`, with its checks - and stricter ones
for the size of `RNDADDENTROPY`, see below:

| ioctl                            | Who                                  | Effect in the ESDM |
|----------------------------------|--------------------------------------|--------------------|
| `RNDGETENTCNT`                   | everybody                            | entropy of the auxiliary pool in bits |
| `RNDADDTOENTCNT`                 | `CAP_SYS_ADMIN`                      | credits the given bits to the auxiliary pool |
| `RNDADDENTROPY`                  | `CAP_SYS_ADMIN`                      | inserts the data, then credits the given bits, no more than the data has, as `RNDADDTOENTCNT` |
| `RNDZAPENTCNT`, `RNDCLEARPOOL`   | `CAP_SYS_ADMIN`                      | sets the entropy of the auxiliary pool to zero |
| `RNDRESEEDCRNG`                  | `CAP_SYS_ADMIN`                      | reseeds the DRNGs at their next use |

Every other command is answered with `EINVAL`, as by the kernel. As there, the
caller's capability is checked first and the arguments after it, a negative
entropy count is `EINVAL`, and `RNDADDENTROPY` inserts all of its data before
it credits the entropy, and credits nothing when not all of it went in.

With the size of the data of `RNDADDENTROPY`, the module is stricter than
`random.c`, deliberately:

* a negative size is `EINVAL` before any data is read, where `random.c` mixes
  in what it can read of that much memory and fails with `EFAULT`,
* a size of 0 credits nothing, where `random.c` credits the entropy count
  without any data,
* no more bits are credited than the data has, 8 per byte, where `random.c`
  credits the entropy count, up to the size of its pool.

The ioctls that change something in the ESDM are carried out by the ESDM once
their command went out, whether the module waits for the answer or not. So
from then on, the module waits for the answer despite signals - bounded by
`timeout_ms`, and a fatal signal still ends the wait - and never restarts the
ioctl.

## /proc/esdm

| File                      | Content |
|---------------------------|---------|
| `boot_id`                 | the kernel's `boot_id`, read once when the module is loaded |
| `uuid`                    | a random UUID (version 4), new on every open |
| `entropy_avail`           | entropy of the ESDM's auxiliary pool in bits |
| `poolsize`                | size of that pool in bits |
| `write_wakeup_threshold`  | the ESDM's write wakeup threshold in bits |
| `urandom_min_reseed_secs` | the ESDM's maximum time between reseeds of its DRNGs |
| `esdm_type`               | the status report of the ESDM, as `esdm-proc` serves it |
| `status`                  | the status report of the ESDM |
| `status.json`             | the status of the ESDM as JSON document |

`write_wakeup_threshold` and `urandom_min_reseed_secs` can be written by a
process with `CAP_SYS_ADMIN`, with a number in decimal, octal (leading `0`) or
hexadecimal (leading `0x`), optionally followed by a newline. A file is filled
when it is opened, so that all reads of one open see the same snapshot, which
is charged to the memory cgroup of the opener for as long as the file is open.
Every other file is read only.

## The ESDM Unreachable

While the ESDM cannot be reached - not running, its EGD interface not enabled,
or not answering within `timeout_ms` - the module behaves as the CUSE frontend
does, which falls back to the kernel's devices:

* reads are served by the kernel's RNG; `/dev/esdm_random` waits for the
  kernel's RNG to be initialized first (`EAGAIN` with `O_NONBLOCK`),
* writes are mixed into the kernel's RNG without entropy credit,
* the ioctls fail - the kernel's own entropy accounting cannot be changed from
  a module, and the kernel's devices are there for that - with `ENOTCONN`
  when the ESDM cannot be connected to, `ETIMEDOUT` when it does not answer
  within `timeout_ms`, `ECONNRESET` or `EPIPE` when it closes the connection,
  as an ESDM from before the extensions does, and `EPROTO` for an answer that
  does not fit the protocol. An ioctl changing something whose answer did not
  come may have been carried out all the same,
* the files of `/proc/esdm` other than `boot_id` are empty.

A request that finds no connection free within `timeout_ms` - all of them busy
with an ESDM that takes its time - fails as one the ESDM did not answer.

The module logs once when it cannot connect and once when it connected again.
A connection that could not be made, or whose ESDM did not answer, is not made
again for a moment, growing up to two seconds until a request on it succeeds,
so a missing or frozen ESDM costs a failed connect or a timeout now and then
rather than one per read; a reader may be served by the kernel's RNG for that
long after the ESDM came back.

## Security

* **Connecting in the context of init.** The path of a Unix domain socket is
  looked up in the file system context of the task calling `connect()`.
  Connecting in the context of the process reading a device would let a
  process in a container, with a mount namespace or root of its own, have the
  module talk to whatever it put at that path. The module connects from its
  workqueue only, whose kernel threads share the file system context of init
  and run with the initial credentials. Once connected, requests are carried
  out in the caller's context, which no path lookup is part of.
* **The module is root towards the ESDM.** The ESDM takes the credentials of
  its peer at connect time, so it honours the entropy claims and the
  privileged commands of the module. The module therefore checks the
  capability of its own caller, `CAP_SYS_ADMIN` as `random.c` does, before it
  sends any of those, and validates the arguments of the ioctls like
  `random.c`, stricter for the size of `RNDADDENTROPY`.
* **Untrusted answers.** The ESDM runs in user space. Every length in its
  answers is checked against what was asked for and the protocol's bounds
  before anything is read; a connection with an answer that does not fit is
  closed. The status report is bounded to 64 KiB.
* **Hygiene.** Every buffer of the module that held random data is wiped -
  the seq_file buffers of `/proc/esdm` included -, nothing random is logged,
  large buffers are allocated rather than on the stack, transfers are bounded
  by `timeout_ms`, and waits are interruptible - but for the answer of an
  ioctl changing something in the ESDM, see above.
  The socket buffers of the kernel that carry the random data from the ESDM
  are freed as those of any Unix domain socket, without being wiped.
* **No waiting for user memory with a connection.** A connection to the ESDM
  is held for its answers only: a write copies its data from user memory
  before it takes one, so a writer whose memory takes its time - a mapping of
  a FUSE daemon that does not answer - keeps nobody else from the ESDM.
* **Unloading.** An open device holds a reference to the module, so it cannot
  be unloaded while a reader is in it; the proc files are removed waiting for
  their readers.

## Testing

The checks of the module are the subcommands of `esdm-cdev-check`, built from
`tests/esdm_cdev` of the ESDM source tree with its test suite, each exiting with
0 when the module does what it promises and with a `FAIL` line otherwise:

    esdm-cdev-check <check> [args]

Those that hold next to the ESDM of an ordinary machine are tests of the meson
test suite as well, in its suite `esdm_cdev`: the reads, also with `O_SYNC`
and `O_NONBLOCK`, `poll()`, writes and the ioctls without `CAP_SYS_ADMIN`, and
as root `/proc/esdm` and writers stalled on their own memory. They skip where
the module is not loaded, as they do where they need root and do not run as
root:

    meson test -C build --suite esdm_cdev

The build option `esdm-cdev-check` installs the program, for a machine that
loads the module but has no build tree.

The NixOS VM test `checks.x86_64-linux.esdm_cdev` of the flake runs all of
them with the installed program. It loads the module next to a running ESDM
and exercises the devices, `poll()`, `O_NONBLOCK`, `O_SYNC`, writes, the ioctls
as root, as an unprivileged user and as root without `CAP_SYS_ADMIN`, writers
stalled on their own memory, every file of `/proc/esdm`, a restart of the ESDM
during reads, an ESDM that does not answer, an ESDM that is gone, loading the
module without an ESDM and unloading it. The fake EGD server of
`esdm-cdev-check fake-egd` stands in for what the ESDM cannot be made to do:
never answering, for the backoff; logging what the module sends, for the credit
of `RNDADDENTROPY` and `RNDADDTOENTCNT` interrupted by a signal; not being
operational, for `poll()`:

    nix build .#checks.x86_64-linux.esdm_cdev

# Author

Markus Theil <theil.markus@gmail.com>
