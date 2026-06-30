#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com>
# Disable hardware prefetchers on every online CPU, best-effort and portable.
# Prints what it did and exits non-zero if it could not; the runner records that.
#
# AMD (Zen):  MSR 0xC0011022 bits 13 (DC prefetch) + 15 (stride prefetch)
# Intel:      MSR 0x1A4 bits 0-3 (the four core prefetchers)
#
# Needs root and the msr module (modprobe msr).
import glob
import os
import struct
import sys

AMD_MSR, AMD_BITS = 0xC0011022, (1 << 13) | (1 << 15)
INTEL_MSR, INTEL_BITS = 0x1A4, 0xF


def vendor():
    with open("/proc/cpuinfo") as f:
        for line in f:
            if line.startswith("vendor_id"):
                return line.split(":", 1)[1].strip()
    return ""


def set_msr(path, addr, bits):
    fd = os.open(path, os.O_RDWR)
    try:
        os.lseek(fd, addr, os.SEEK_SET)
        cur = struct.unpack("<Q", os.read(fd, 8))[0]
        os.lseek(fd, addr, os.SEEK_SET)
        os.write(fd, struct.pack("<Q", cur | bits))
    finally:
        os.close(fd)


def read_msr(path, addr):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, addr, os.SEEK_SET)
        return struct.unpack("<Q", os.read(fd, 8))[0]
    finally:
        os.close(fd)


def main():
    v = vendor()
    if v == "AuthenticAMD":
        addr, bits, label = AMD_MSR, AMD_BITS, "AMD 0xC0011022 bits 13,15"
    elif v == "GenuineIntel":
        addr, bits, label = INTEL_MSR, INTEL_BITS, "Intel 0x1A4 bits 0-3"
    else:
        print(f"unknown vendor {v!r}, prefetchers left as-is")
        return 1

    cpus = sorted(glob.glob("/dev/cpu/*/msr"))
    if not cpus:
        print("no /dev/cpu/*/msr (modprobe msr; run as root)")
        return 1

    done = 0
    for path in cpus:
        try:
            set_msr(path, addr, bits)
            done += 1
        except OSError as e:
            print(f"{path}: {e}")
    # read the MSR back and confirm the bits actually stuck before the test runs
    verified = 0
    for path in cpus:
        try:
            if (read_msr(path, addr) & bits) == bits:
                verified += 1
        except OSError:
            pass
    print(f"prefetchers: set {done}/{len(cpus)}, verified-off {verified}/{len(cpus)} via {label}")
    return 0 if verified and verified == len(cpus) else 1


if __name__ == "__main__":
    sys.exit(main())
