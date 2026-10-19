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

Reads are interrupted by signals like those of the kernel's devices: a read
that got data returns it, one that did not returns `ERESTARTSYS`, so the
caller sees `EINTR` or the read is restarted.

### ioctls

The ioctls of `drivers/char/random.c`, with its checks:

| ioctl                            | Who                                  | Effect in the ESDM |
|----------------------------------|--------------------------------------|--------------------|
| `RNDGETENTCNT`                   | everybody                            | entropy of the auxiliary pool in bits |
| `RNDADDTOENTCNT`                 | `CAP_SYS_ADMIN`                      | credits the given bits to the auxiliary pool |
| `RNDADDENTROPY`                  | `CAP_SYS_ADMIN`                      | inserts the data with the given entropy, no more than its bits |
| `RNDZAPENTCNT`, `RNDCLEARPOOL`   | `CAP_SYS_ADMIN`                      | sets the entropy of the auxiliary pool to zero |
| `RNDRESEEDCRNG`                  | `CAP_SYS_ADMIN`                      | reseeds the DRNGs at their next use |

Every other command is answered with `EINVAL`, as by the kernel. As there, the
caller's capability is checked first and the arguments after it; a negative
entropy count or size is `EINVAL`.

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
when it is opened, so that all reads of one open see the same snapshot. Every
other file is read only.

## The ESDM Unreachable

While the ESDM cannot be reached - not running, its EGD interface not enabled,
or not answering within `timeout_ms` - the module behaves as the CUSE frontend
does, which falls back to the kernel's devices:

* reads are served by the kernel's RNG; `/dev/esdm_random` waits for the
  kernel's RNG to be initialized first (`EAGAIN` with `O_NONBLOCK`),
* writes are mixed into the kernel's RNG without entropy credit,
* the ioctls fail with `ENOTCONN` - the kernel's own entropy accounting cannot
  be changed from a module, and the kernel's devices are there for that,
* the files of `/proc/esdm` other than `boot_id` are empty.

The module logs once when it cannot connect and once when it connected again.
A connection that failed is not tried again for a moment, up to two seconds, so
a missing ESDM costs a failed connect now and then rather than one per read; a
reader may be served by the kernel's RNG for that long after the ESDM came
back.

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
  `random.c`.
* **Untrusted answers.** The ESDM runs in user space. Every length in its
  answers is checked against what was asked for and the protocol's bounds
  before anything is read; a connection with an answer that does not fit is
  closed. The status report is bounded to 64 KiB.
* **Hygiene.** Every buffer that held random data is wiped, nothing random is
  logged, large buffers are allocated rather than on the stack, transfers are
  bounded by `timeout_ms`, and waits are interruptible.
* **Unloading.** An open device holds a reference to the module, so it cannot
  be unloaded while a reader is in it; the proc files are removed waiting for
  their readers.

## Testing

The NixOS VM test `checks.x86_64-linux.esdm_cdev` of the flake loads the
module next to a running ESDM and exercises the devices, `poll()`,
`O_NONBLOCK`, `O_SYNC`, writes, the ioctls as root, as an unprivileged user and
as root without `CAP_SYS_ADMIN`, every file of `/proc/esdm`, a restart of the
ESDM during reads, an ESDM that does not answer, an ESDM that is gone, loading
the module without an ESDM and unloading it:

    nix build .#checks.x86_64-linux.esdm_cdev

The checks it runs inside the VM are in `tests/esdm_cdev_check.py`.

# Author

Markus Theil <theil.markus@gmail.com>
