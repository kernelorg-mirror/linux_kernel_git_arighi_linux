#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exchange values between host and guest BPF through NUMA-backed RAM."""

# Dependencies: virtme-ng, busybox-static, qemu, util-linux (script).

import ctypes
import mmap
import os
from pathlib import Path
import pwd
import queue
import re
import shutil
import shlex
import struct
import subprocess
import sys
import threading
import time


PAGE_SIZE = 4096
NUM_PAGES = 512
ARENA_SIZE = PAGE_SIZE * NUM_PAGES
SLICE_SIZE = ARENA_SIZE // 2
GUEST_READY = 0x4152454E414B564D
HOST_FIRST = 0x123456789ABCDEF0
GUEST_FIRST = 0xFEDCBA9876543210
HOST_SECOND = 0x1020304050607080
GUEST_SECOND = 0x8070605040302010


def getq(arena, offset):
    return struct.unpack_from("<Q", arena, offset)[0]


def wait_for(arena, offset, expected, guest, lines):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if getq(arena, offset) == expected:
            return
        if guest.poll() is not None:
            raise RuntimeError("guest exited early:\n" + "".join(lines))
        time.sleep(0.001)
    raise TimeoutError(f"timed out waiting for offset {offset} = {expected}")


def read_lines(guest, messages, lines):
    for line in guest.stdout:
        lines.append(line)
        messages.put(line.strip())


def wait_message(messages, lines, expected, guest):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            line = messages.get(timeout=0.5)
        except queue.Empty:
            if guest.poll() is not None:
                break
            continue
        if expected in line:
            return line
        if "GUEST_BPF_FAILED" in line:
            break
    raise RuntimeError(f"guest did not print {expected}:\n" + "".join(lines))


def run_host_bpf(runner, obj, fd, offset, program="exchange"):
    output = subprocess.check_output(
        [str(runner), str(fd), str(obj), str(offset), program],
        pass_fds=(fd,), text=True)
    return int(output)


def resolve_vng(user):
    home = Path(pwd.getpwnam(user).pw_dir)
    executable = shutil.which("vng") or str(home / ".local/bin/vng")
    if not os.access(executable, os.X_OK):
        print("SKIP: virtme-ng (vng) is unavailable")
        return None, None
    env = os.environ.copy()
    if Path(executable).parent == home / ".local/bin":
        env["PATH"] = os.pathsep.join((str(home / ".local/bin"),
                                       env.get("PATH", "")))
        version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        site = home / ".local/lib" / version / "site-packages"
        if site.is_dir():
            env["PYTHONPATH"] = os.pathsep.join(
                filter(None, (str(site), env.get("PYTHONPATH"))))
    return executable, env


def start_guest(pin, build, index, vng, env):
    kernel = Path(__file__).resolve().parents[4]
    qemu_opts = (
        f"-object memory-backend-file,id=signal,size=1M,share=on,"
        f"offset={index * SLICE_SIZE},mem-path={pin} "
        "-numa node,nodeid=1,memdev=signal"
    )
    guest_command = [str(build / "guest-init"), str(build / "guest.bpf.o")]
    command = [
        vng, "--run", str(kernel), "--cpus", "1",
        "--memory", "512M", "--numa", "511M", "--exec",
        shlex.join(guest_command),
        f"--qemu-opts={qemu_opts}",
    ]
    guest = subprocess.Popen(["script", "-e", "-q", "-c", shlex.join(command),
                              "/dev/null"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, env=env)
    lines = []
    messages = queue.Queue()
    reader = threading.Thread(target=read_lines, args=(guest, messages, lines),
                              daemon=True)
    reader.start()
    return guest, messages, lines, reader


def stop_guest(guest):
    process, _, _, reader = guest
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    reader.join(timeout=1)


def exchange(pin, fd, arena, build, vng, env):
    guests = []
    try:
        for index in range(2):
            guests.append(start_guest(pin, build, index, vng, env))
        offsets = []
        for index, (process, messages, lines, _) in enumerate(guests):
            ready = wait_message(messages, lines, "GUEST_BPF_READY", process)
            match = re.fullmatch(r"GUEST_BPF_READY (\d+)", ready)
            if not match:
                raise RuntimeError(f"malformed guest page offset: {ready}")
            relative = int(match.group(1))
            offset = index * SLICE_SIZE + relative
            if relative >= SLICE_SIZE or relative % PAGE_SIZE or \
                    getq(arena, offset) != GUEST_READY:
                raise RuntimeError(f"invalid guest {index} page offset {relative}")
            offsets.append(offset)
        # The QEMU VMA and the open map FD retain the arena after unlink.
        os.unlink(pin)
        runner = build / "host-runner"
        obj = build / "host.bpf.o"
        for offset in offsets:
            if run_host_bpf(runner, obj, fd, offset, "probe_free") != 0 or \
                    getq(arena, offset) != GUEST_READY:
                raise RuntimeError("host BPF freed a shared RAM page")

        for index, offset in enumerate(offsets):
            result = run_host_bpf(runner, obj, fd, offset)
            if result != 0:
                raise RuntimeError(f"guest {index} first result={result}")
            other = offsets[1 - index]
            if index == 0 and getq(arena, other + 16) != 0:
                raise RuntimeError("guest 0 write modified guest 1 signal")

        for index, (process, messages, lines, _) in enumerate(guests):
            offset = offsets[index]
            wait_for(arena, offset + 32, 1, process, lines)
            if getq(arena, offset + 24) != GUEST_FIRST:
                raise RuntimeError(f"guest {index} first BPF value is wrong")

        # Guest 0 exits while guest 1 keeps its slice mapped and active.
        for index, (process, messages, lines, _) in enumerate(guests):
            offset = offsets[index]
            if run_host_bpf(runner, obj, fd, offset) != 0:
                raise RuntimeError(f"host BPF failed guest {index} second value")
            wait_for(arena, offset + 32, 2, process, lines)
            if getq(arena, offset + 24) != GUEST_SECOND:
                raise RuntimeError(f"guest {index} second BPF value is wrong")
            if run_host_bpf(runner, obj, fd, offset) != 2:
                raise RuntimeError(f"host BPF failed guest {index} reply")
            wait_message(messages, lines, "GUEST_BPF_EXCHANGED", process)
            process.wait(timeout=15)
            if process.returncode:
                raise RuntimeError(f"guest {index} failed:\n" + "".join(lines))
        print(f"two guests exchanged BPF values through arena slices {offsets}")
    finally:
        for guest in guests:
            stop_guest(guest)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("this test requires root")
    if os.sysconf("SC_PAGE_SIZE") != PAGE_SIZE:
        raise RuntimeError("this test requires 4 KiB pages")
    if not os.path.ismount("/sys/fs/bpf"):
        raise RuntimeError("mount bpffs first")
    if not os.path.exists("/dev/kvm"):
        raise RuntimeError("nested KVM is unavailable")
    kernel = Path(__file__).resolve().parents[4]
    user = os.environ.get("SUDO_USER")
    if not user:
        user = pwd.getpwuid(kernel.stat().st_uid).pw_name
    vng, env = resolve_vng(user)
    if not vng:
        return
    build = Path(__file__).with_name(".output") / "arena_kvm"
    for name in ("guest-init", "guest.bpf.o", "host-runner", "host.bpf.o"):
        if not (build / name).exists():
            raise RuntimeError(f"missing {build / name}; build Makefile.arena_kvm")
    pin = f"/sys/fs/bpf/arena_kvm_{os.getpid()}"
    subprocess.run([
        "bpftool", "map", "create", pin, "type", "arena", "key", "0",
        "value", "0", "entries", str(NUM_PAGES), "name", "arena_kvm",
        "flags", str(1024 | (1 << 20)),
    ], check=True)
    try:
        if os.stat(pin).st_size != ARENA_SIZE:
            raise RuntimeError("pinned arena has the wrong size")
        libbpf = ctypes.CDLL("libbpf.so.1", use_errno=True)
        libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
        libbpf.bpf_obj_get.restype = ctypes.c_int
        fd = libbpf.bpf_obj_get(os.fsencode(pin))
        if fd < 0:
            raise OSError(ctypes.get_errno(), "bpf_obj_get failed")
        try:
            with mmap.mmap(fd, ARENA_SIZE, flags=mmap.MAP_SHARED,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE) as arena:
                # Populate the file pages before QEMU uses them as RAM.
                for i in range(NUM_PAGES):
                    arena[i * PAGE_SIZE]
                exchange(pin, fd, arena, build, vng, env)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(pin):
            os.unlink(pin)


if __name__ == "__main__":
    main()
