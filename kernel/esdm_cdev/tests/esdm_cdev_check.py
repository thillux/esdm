#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#
# Checks of the esdm_cdev module, run inside the NixOS VM test of flake.nix
# (checks.<system>.esdm_cdev). Each subcommand prints what it found and exits
# non-zero when that is not what the module promises.

import errno
import fcntl
import json
import os
import re
import select
import socket
import struct
import sys
import threading
import time

# linux/random.h
RNDGETENTCNT = 0x80045200
RNDADDTOENTCNT = 0x40045201
RNDADDENTROPY = 0x40085203
RNDZAPENTCNT = 0x5204
RNDCLEARPOOL = 0x5206
RNDRESEEDCRNG = 0x5207

DEVS = ["/dev/esdm_random", "/dev/esdm_urandom"]
PROC = "/proc/esdm"


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def read_exact(path, size, flags=0):
    fd = os.open(path, os.O_RDONLY | flags)
    try:
        out = bytearray()
        while len(out) < size:
            chunk = os.read(fd, size - len(out))
            if not chunk:
                fail(f"{path}: end of file after {len(out)} of {size} bytes")
            out += chunk
        return bytes(out)
    finally:
        os.close(fd)


def check_random(data, what):
    if len(data) >= 32:
        if data == bytes(len(data)):
            fail(f"{what}: all zeros")
        if len(set(data)) == 1:
            fail(f"{what}: constant byte")
    if len(data) >= 1 << 20:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        expect = len(data) / 256
        if min(counts) < expect * 0.8 or max(counts) > expect * 1.2:
            fail(f"{what}: byte distribution off ({min(counts)}..{max(counts)})")


def cmd_reads(args):
    flags = os.O_SYNC if "sync" in args else 0
    sizes = [1, 32, 4096, 1 << 20] if "sync" not in args else [1, 32, 64]
    for dev in DEVS:
        for size in sizes:
            first = read_exact(dev, size, flags)
            second = read_exact(dev, size, flags)
            if len(first) != size or len(second) != size:
                fail(f"{dev}: short read of {size}")
            check_random(first, f"{dev} {size}")
            if size >= 32 and first == second:
                fail(f"{dev}: two reads of {size} bytes are equal")
            print(f"{dev}: {size} bytes ok")
        # 1 byte reads must not all be equal
        ones = {read_exact(dev, 1, flags) for _ in range(64)}
        if len(ones) < 8:
            fail(f"{dev}: 64 single bytes take {len(ones)} values only")
    print("reads ok")


def cmd_nonblock(args):
    for dev in DEVS:
        fd = os.open(dev, os.O_RDONLY | os.O_NONBLOCK)
        try:
            data = os.read(fd, 64)
        finally:
            os.close(fd)
        if len(data) != 64:
            fail(f"{dev}: O_NONBLOCK read gave {len(data)} bytes")
        check_random(data, f"{dev} O_NONBLOCK")
    print("nonblock ok")


def cmd_poll(args):
    want = {"/dev/esdm_random": select.POLLIN | select.POLLRDNORM,
            "/dev/esdm_urandom": select.POLLIN | select.POLLOUT}
    for dev in DEVS:
        fd = os.open(dev, os.O_RDWR)
        try:
            p = select.poll()
            # Readable once the ESDM is operational: only that is waited for
            p.register(fd, want[dev])
            res = p.poll(10000)
        finally:
            os.close(fd)
        if not res:
            fail(f"{dev}: poll timed out")
        mask = res[0][1]
        if mask & want[dev] != want[dev]:
            fail(f"{dev}: poll mask {mask:#x}, want {want[dev]:#x}")
        print(f"{dev}: poll mask {mask:#x}")
    print("poll ok")


def cmd_writes(args):
    for dev in DEVS:
        fd = os.open(dev, os.O_WRONLY)
        try:
            for size in [0, 1, 255, 256, 1000, 300 * 1024]:
                n = os.write(fd, os.urandom(size))
                if n != size:
                    fail(f"{dev}: write of {size} returned {n}")
        finally:
            os.close(fd)
        print(f"{dev}: writes ok")
    print("writes ok")


def entcnt(fd):
    buf = bytearray(4)
    fcntl.ioctl(fd, RNDGETENTCNT, buf)
    return struct.unpack("i", buf)[0]


def ioctl_errno(fn):
    try:
        fn()
    except OSError as e:
        return e.errno
    return 0


def cmd_ioctl_priv(args):
    for dev in DEVS:
        fd = os.open(dev, os.O_RDWR)
        try:
            # Credited entropy makes the ESDM reseed at once, which takes
            # it from the pool again: what is left is at most what was
            # credited. A clear pool stays clear.
            fcntl.ioctl(fd, RNDCLEARPOOL)
            zero = entcnt(fd)
            if zero != 0:
                fail(f"{dev}: entropy count {zero} after RNDCLEARPOOL")
            fcntl.ioctl(fd, RNDADDTOENTCNT, struct.pack("i", 64))
            cnt = entcnt(fd)
            if not 0 <= cnt <= 64:
                fail(f"{dev}: entropy count {cnt} after crediting 64 bits")
            fcntl.ioctl(fd, RNDZAPENTCNT)
            if entcnt(fd) != 0:
                fail(f"{dev}: entropy count not 0 after RNDZAPENTCNT")
            data = os.urandom(32)
            fcntl.ioctl(fd, RNDADDENTROPY,
                        struct.pack("ii", 128, len(data)) + data)
            cnt = entcnt(fd)
            if not 0 <= cnt <= 128:
                fail(f"{dev}: entropy count {cnt} after RNDADDENTROPY of 128 bits")
            # More than the data has bits is credited as the bits it has
            fcntl.ioctl(fd, RNDZAPENTCNT)
            fcntl.ioctl(fd, RNDADDENTROPY,
                        struct.pack("ii", 4096, 4) + os.urandom(4))
            cnt = entcnt(fd)
            if not 0 <= cnt <= 32:
                fail(f"{dev}: entropy count {cnt} after crediting 4096 bits to 4 bytes")
            fcntl.ioctl(fd, RNDCLEARPOOL)
            # A larger buffer than one EGD transfer
            data = os.urandom(1000)
            fcntl.ioctl(fd, RNDADDENTROPY,
                        struct.pack("ii", 8000, len(data)) + data)

            fcntl.ioctl(fd, RNDRESEEDCRNG)
            # Argument checks of random.c
            if ioctl_errno(lambda: fcntl.ioctl(fd, RNDADDTOENTCNT,
                                               struct.pack("i", -1))) != errno.EINVAL:
                fail(f"{dev}: negative RNDADDTOENTCNT not refused")
            if ioctl_errno(lambda: fcntl.ioctl(fd, RNDADDENTROPY,
                                               struct.pack("ii", 8, -1))) != errno.EINVAL:
                fail(f"{dev}: negative RNDADDENTROPY size not refused")
            if ioctl_errno(lambda: fcntl.ioctl(fd, 0x5299)) != errno.EINVAL:
                fail(f"{dev}: unknown ioctl not answered with EINVAL")
        finally:
            os.close(fd)
        print(f"{dev}: privileged ioctls ok")
    print("ioctl-priv ok")


def cmd_ioctl_unpriv(args):
    for dev in DEVS:
        fd = os.open(dev, os.O_RDWR)
        try:
            cnt = entcnt(fd)
            print(f"{dev}: RNDGETENTCNT {cnt}")
            for name, fn in [
                ("RNDADDTOENTCNT",
                 lambda: fcntl.ioctl(fd, RNDADDTOENTCNT, struct.pack("i", 8))),
                ("RNDADDENTROPY",
                 lambda: fcntl.ioctl(fd, RNDADDENTROPY,
                                     struct.pack("ii", 8, 1) + b"x")),
                ("RNDZAPENTCNT", lambda: fcntl.ioctl(fd, RNDZAPENTCNT)),
                ("RNDCLEARPOOL", lambda: fcntl.ioctl(fd, RNDCLEARPOOL)),
                ("RNDRESEEDCRNG", lambda: fcntl.ioctl(fd, RNDRESEEDCRNG)),
            ]:
                err = ioctl_errno(fn)
                if err != errno.EPERM:
                    fail(f"{dev}: {name} gave errno {err}, want EPERM")
            if entcnt(fd) < 0:
                fail(f"{dev}: entropy count negative")
        finally:
            os.close(fd)
        print(f"{dev}: unprivileged ioctls ok")
    # The writable proc files are the ESDM's to change, with CAP_SYS_ADMIN
    try:
        with open(f"{PROC}/write_wakeup_threshold", "w") as f:
            f.write("512\n")
        fail("write_wakeup_threshold writable without CAP_SYS_ADMIN")
    except OSError as e:
        if e.errno not in (errno.EPERM, errno.EACCES):
            fail(f"write_wakeup_threshold: errno {e.errno}")
    print("ioctl-unpriv ok")


def cmd_ioctl_unreachable(args):
    for dev in DEVS:
        fd = os.open(dev, os.O_RDWR)
        try:
            err = ioctl_errno(lambda: entcnt(fd))
            if err != errno.ENOTCONN:
                fail(f"{dev}: RNDGETENTCNT gave errno {err}, want ENOTCONN")
            err = ioctl_errno(lambda: fcntl.ioctl(fd, RNDCLEARPOOL))
            if err != errno.ENOTCONN:
                fail(f"{dev}: RNDCLEARPOOL gave errno {err}, want ENOTCONN")
        finally:
            os.close(fd)
    print("ioctl-unreachable ok")


def proc(name):
    with open(f"{PROC}/{name}") as f:
        return f.read()


def write_proc(name, val):
    with open(f"{PROC}/{name}", "w") as f:
        f.write(val)


UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n$")
NUM = re.compile(r"^[0-9]+\n$")


def cmd_proc(args):
    names = sorted(os.listdir(PROC))
    want = sorted(["boot_id", "uuid", "entropy_avail", "poolsize",
                   "write_wakeup_threshold", "urandom_min_reseed_secs",
                   "esdm_type", "status", "status.json"])
    if names != want:
        fail(f"/proc/esdm holds {names}")

    with open("/proc/sys/kernel/random/boot_id") as f:
        if proc("boot_id") != f.read():
            fail("boot_id differs from the kernel's")
    u1, u2 = proc("uuid"), proc("uuid")
    if not UUID.match(u1) or not UUID.match(u2) or u1 == u2:
        fail(f"uuid {u1!r} {u2!r}")
    for name in ["entropy_avail", "poolsize", "write_wakeup_threshold",
                 "urandom_min_reseed_secs"]:
        val = proc(name)
        if not NUM.match(val):
            fail(f"{name}: {val!r}")
        print(f"{name}: {val.strip()}")

    old = proc("write_wakeup_threshold")
    write_proc("write_wakeup_threshold", "1234\n")
    if proc("write_wakeup_threshold") != "1234\n":
        fail("write_wakeup_threshold not set")
    write_proc("write_wakeup_threshold", old)
    old = proc("urandom_min_reseed_secs")
    write_proc("urandom_min_reseed_secs", "77")
    if proc("urandom_min_reseed_secs") != "77\n":
        fail("urandom_min_reseed_secs not set")
    write_proc("urandom_min_reseed_secs", old)
    for bad in ["abc", "-1", "4294967295", "1 2"]:
        try:
            write_proc("write_wakeup_threshold", bad)
            fail(f"write_wakeup_threshold took {bad!r}")
        except OSError as e:
            if e.errno not in (errno.EINVAL, errno.ERANGE):
                fail(f"write_wakeup_threshold {bad!r}: errno {e.errno}")
    try:
        write_proc("poolsize", "1")
        fail("poolsize writable")
    except OSError:
        pass

    status = proc("status")
    for section in ["ESDM library version", "Entropy Source", "DRNG instance"]:
        if section not in status:
            fail(f"status lacks {section!r}:\n{status}")
    if proc("esdm_type") == "":
        fail("esdm_type empty")
    doc = json.loads(proc("status.json"))
    for key in ["library_version", "entropy_sources", "drngs"]:
        if key not in doc:
            fail(f"status.json lacks {key!r}")

    # Read in pieces with seeks, as one snapshot per open
    with open(f"{PROC}/status", "rb") as f:
        head = f.read(10)
        f.seek(0)
        whole = f.read()
        if not whole.startswith(head):
            fail("status not one snapshot per open")
    print("proc ok")


def cmd_proc_empty(args):
    for name in ["uuid", "entropy_avail", "poolsize", "write_wakeup_threshold",
                 "urandom_min_reseed_secs", "esdm_type", "status",
                 "status.json"]:
        val = proc(name)
        if val != "":
            fail(f"{name} not empty while the ESDM is unreachable: {val!r}")
    if len(proc("boot_id")) != 37:
        fail("boot_id lost")
    print("proc-empty ok")


def cmd_loop(args):
    dev, seconds = args[0], float(args[1])
    end = time.monotonic() + seconds
    reads = errors = 0
    while time.monotonic() < end:
        try:
            data = read_exact(dev, 4096)
            check_random(data, dev)
            reads += 1
        except OSError as e:
            errors += 1
            print(f"read error {e}")
    print(f"loop reads={reads} errors={errors}")
    if errors or not reads:
        fail("loop")


def cmd_block(args):
    # A reader that stays in read() until it is killed or the read returns
    dev = args[0]
    fd = os.open(dev, os.O_RDONLY)
    print("blocking", flush=True)
    while True:
        os.read(fd, 1 << 20)


def cmd_throughput(args):
    # Informational: the module next to a user space EGD client
    size = 4 << 20
    for dev in DEVS:
        t = time.monotonic()
        read_exact(dev, size)
        dt = time.monotonic() - t
        print(f"{dev}: {size / dt / 1e6:.1f} MB/s")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(args[0] if args else "/run/esdm-egd.socket")
    for batch in (1, 16):
        total = 0
        t = time.monotonic()
        while total < size:
            s.sendall(bytes([0xe2, 255]) * batch)
            for _ in range(batch):
                n = s.recv(1, socket.MSG_WAITALL)[0]
                total += len(s.recv(n, socket.MSG_WAITALL))
        dt = time.monotonic() - t
        print(f"EGD socket, {batch} commands at a time: {total / dt / 1e6:.1f} MB/s")
    s.close()


def cmd_stalled_writers(args):
    # Writers whose data does not come: their buffer is in a userfaultfd
    # range nobody serves, so the module's copy from it waits for good. More
    # of them than the module has connections must not keep anybody else
    # from the ESDM.
    import ctypes
    import mmap

    nr_userfaultfd = {"x86_64": 323, "aarch64": 282}[os.uname().machine]
    UFFDIO_API = 0xC018AA3F
    UFFDIO_REGISTER = 0xC020AA00
    UFFDIO_REGISTER_MODE_MISSING = 1

    libc = ctypes.CDLL(None, use_errno=True)
    uffd = libc.syscall(nr_userfaultfd, os.O_CLOEXEC)
    if uffd < 0:
        fail(f"userfaultfd: errno {ctypes.get_errno()}")
    fcntl.ioctl(uffd, UFFDIO_API, bytearray(struct.pack("QQQ", 0xAA, 0, 0)))
    size = 1 << 20
    region = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(region))
    fcntl.ioctl(uffd, UFFDIO_REGISTER,
                bytearray(struct.pack("QQQQ", addr, size,
                                      UFFDIO_REGISTER_MODE_MISSING, 0)))

    def writer(dev):
        fd = os.open(dev, os.O_WRONLY)
        os.write(fd, region)

    writers = [threading.Thread(target=writer, args=(DEVS[i % 2],),
                                daemon=True) for i in range(16)]
    for w in writers:
        w.start()
    time.sleep(2)
    if not all(w.is_alive() for w in writers):
        fail("the writers did not stall in the copy of their data")

    def bounded(what, fn):
        t = time.monotonic()
        fn()
        took = time.monotonic() - t
        print(f"{what}: {took:.2f} s")
        if took > 2:
            fail(f"{what} took {took:.1f} s next to stalled writers")

    for dev in DEVS:
        bounded(f"{dev} read", lambda: read_exact(dev, 4096))
        fd = os.open(dev, os.O_RDONLY)
        bounded(f"{dev} RNDGETENTCNT", lambda: entcnt(fd))
        os.close(fd)
    bounded("/proc/esdm/status", lambda: proc("status"))
    print("stalled-writers ok", flush=True)
    # The writers are stuck in the page fault until the process goes
    os._exit(0)


def cmd_fake_egd(args):
    # An EGD server in place of the ESDM, for what the real one cannot be
    # made to do: answer like an ESDM that is not operational yet ("notop"),
    # or accept connections and never answer ("mute"). It logs every
    # connection and every command that changes something to args[1].
    path, log, mode = args[0], args[1], args[2]
    lock = threading.Lock()

    def note(line):
        with lock, open(log, "a") as f:
            f.write(line + "\n")

    def recv(c, n):
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def serve(c):
        try:
            while True:
                cmd = recv(c, 1)[0]
                if cmd == 0x00:
                    c.sendall(bytes(4))
                elif cmd in (0x01, 0xe0, 0xe2):
                    # Nothing before the ESDM is operational
                    recv(c, 1)
                    c.sendall(b"\0")
                elif cmd == 0x03:
                    hdr = recv(c, 3)
                    data = recv(c, hdr[2])
                    note(f"write {int.from_bytes(hdr[:2], 'big')} {len(data)}")
                elif cmd == 0xe3:
                    # Not operational, nothing in the pool
                    c.sendall(bytes([5]) + struct.pack(">5I", 0, 0, 256, 64, 60))
                elif cmd in (0xe4, 0xe5):
                    c.sendall(bytes(4))
                elif cmd in (0xe6, 0xe9, 0xea):
                    arg = int.from_bytes(recv(c, 4), "big")
                    note(f"{cmd:02x} {arg}")
                    # Time for a signal to arrive while the answer is due
                    if cmd == 0xe6:
                        time.sleep(1)
                    c.sendall(bytes(4))
                elif cmd in (0xe7, 0xe8):
                    note(f"{cmd:02x}")
                    c.sendall(bytes(4))
                else:
                    break
        except (EOFError, OSError):
            pass
        c.close()

    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(64)
    note("listening")
    mute = []
    while True:
        c, _ = srv.accept()
        note("connect")
        if mode == "mute":
            mute.append(c)
        else:
            threading.Thread(target=serve, args=(c,), daemon=True).start()


def fake_log(log):
    with open(log) as f:
        return [line.split() for line in f]


def cmd_addentropy(args):
    # Against a notop fake-egd: RNDADDENTROPY inserts all of the data
    # without entropy, and credits it after that in one go, with no more
    # than the data has bits
    log = args[0]
    fd = os.open("/dev/esdm_random", os.O_RDWR)
    try:
        for bits, size, credit in [(256, 1000, 256), (4096, 4, 32),
                                   (0, 300, 0)]:
            before = len(fake_log(log))
            fcntl.ioctl(fd, RNDADDENTROPY,
                        struct.pack("ii", bits, size) + os.urandom(size))
            cmds = [e for e in fake_log(log)[before:] if e != ["connect"]]
            print(f"RNDADDENTROPY of {bits} bits on {size} bytes: {cmds}")
            writes = [e for e in cmds if e[0] == "write"]
            if any(e[1] != "0" for e in writes):
                fail("insertions credited")
            if sum(int(e[2]) for e in writes) != size:
                fail("not all of the data inserted")
            want = [["e6", str(credit)]] if credit else []
            if [e for e in cmds if e[0] == "e6"] != want or \
               (credit and cmds[-1] != want[0]):
                fail(f"not credited with {credit} bits after the data")
    finally:
        os.close(fd)
    print("addentropy ok")


def cmd_addtoentcnt_signal(args):
    # Against a notop fake-egd, which answers 0xe6 after a second: a signal
    # while the module waits for that answer must not have the ioctl
    # restarted, with the command carried out once more
    import signal
    log = args[0]
    signal.signal(signal.SIGALRM, lambda *a: None)
    # SA_RESTART: the kernel restarts what returns ERESTARTSYS
    signal.siginterrupt(signal.SIGALRM, False)
    fd = os.open("/dev/esdm_random", os.O_RDWR)
    try:
        before = len(fake_log(log))
        signal.setitimer(signal.ITIMER_REAL, 0.3)
        fcntl.ioctl(fd, RNDADDTOENTCNT, struct.pack("i", 64))
    finally:
        os.close(fd)
    credits = [e for e in fake_log(log)[before:] if e[0] == "e6"]
    print(f"RNDADDTOENTCNT with a signal: {credits}")
    if credits != [["e6", "64"]]:
        fail(f"RNDADDTOENTCNT carried out {len(credits)} times")
    print("addtoentcnt-signal ok")


def cmd_backoff(args):
    # Against a mute fake-egd: every read waits for the timeout once its
    # connection is made, after that the reconnects back off up to 2 s
    log, seconds = args[0], float(args[1])
    before = sum(1 for e in fake_log(log) if e == ["connect"])
    end = time.monotonic() + seconds
    reads = 0
    while time.monotonic() < end:
        read_exact("/dev/esdm_urandom", 64)
        reads += 1
    connects = sum(1 for e in fake_log(log) if e == ["connect"]) - before
    print(f"backoff: {reads} reads, {connects} connects in {seconds} s")
    # Timeout and backoff from 50 ms to 2 s: about one connect per second
    if connects > seconds * 1.5 + 2:
        fail(f"{connects} connects to an ESDM that does not answer")
    print("backoff ok")


CMDS = {
    "throughput": cmd_throughput,
    "reads": cmd_reads,
    "nonblock": cmd_nonblock,
    "poll": cmd_poll,
    "writes": cmd_writes,
    "ioctl-priv": cmd_ioctl_priv,
    "ioctl-unpriv": cmd_ioctl_unpriv,
    "ioctl-unreachable": cmd_ioctl_unreachable,
    "proc": cmd_proc,
    "proc-empty": cmd_proc_empty,
    "loop": cmd_loop,
    "block": cmd_block,
    "stalled-writers": cmd_stalled_writers,
    "fake-egd": cmd_fake_egd,
    "backoff": cmd_backoff,
    "addentropy": cmd_addentropy,
    "addtoentcnt-signal": cmd_addtoentcnt_signal,
}

if __name__ == "__main__":
    CMDS[sys.argv[1]](sys.argv[2:])
