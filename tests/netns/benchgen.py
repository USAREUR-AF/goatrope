#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Traffic generator and sink for the `bench` phase of test_tap.py.

Batched system calls (sendmmsg, recvmmsg) through ctypes, so one Python process
offers and counts several hundred thousand datagrams a second.

  benchgen.py udp-send  <src> <dst> <port> <size> <rate> <seconds> <run> [<device> [<payload hex>]]
  benchgen.py udp-sink  <bind> <port> <seconds> <run> [<idle seconds> [<deadline seconds>]]
  benchgen.py raw-send  <ifname> <size> <rate> <seconds> <run> <dst_port> [<payload hex>]

A rate of 0 sends as fast as the socket takes them; a sink with run 0 counts every
datagram (a converter's output carries no header). Each message carries a magic,
the run number, a sequence number and the CLOCK_MONOTONIC time it was sent, so the
sink counts only its own run and measures one-way latency on the same host. Each
command prints one JSON line.
"""
from __future__ import annotations

import ctypes
import json
import socket
import struct
import sys
import time

MAGIC = b"GR"
HDR = struct.Struct("!2sHIQ")  # magic, run, sequence, sent at (ns, CLOCK_MONOTONIC): 16 bytes
MSG_WAITFORONE = 0x10000
SO_BINDTODEVICE = 25
SO_RCVBUFFORCE = 33
SO_SNDBUFFORCE = 32


def bigbuf(s: socket.socket, force: int, plain: int, size: int) -> None:
    """A large socket buffer: past the system maximum as root, up to it otherwise."""
    try:
        s.setsockopt(socket.SOL_SOCKET, force, size)
    except PermissionError:
        s.setsockopt(socket.SOL_SOCKET, plain, size)


class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class MsgHdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32), ("iov", ctypes.POINTER(IoVec)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]


class MMsgHdr(ctypes.Structure):
    _fields_ = [("hdr", MsgHdr), ("len", ctypes.c_uint)]


class TimeSpec(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("nsec", ctypes.c_long)]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_int]
LIBC.recvmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_int, ctypes.POINTER(TimeSpec)]


class Batch:
    """n buffers of size bytes each, wired into an mmsghdr array."""

    def __init__(self, n: int, size: int):
        self.n, self.size = n, size
        self.bufs = [ctypes.create_string_buffer(size) for _ in range(n)]
        self.iov = (IoVec * n)()
        self.msgs = (MMsgHdr * n)()
        for i, b in enumerate(self.bufs):
            self.iov[i].base = ctypes.addressof(b)
            self.iov[i].len = size
            self.msgs[i].hdr.iov = ctypes.pointer(self.iov[i])
            self.msgs[i].hdr.iovlen = 1


def pace(rate: float, start: float, sent: int) -> None:
    if rate <= 0:
        return
    due = start + sent / rate
    while True:
        wait = due - time.monotonic()
        if wait <= 0:
            return
        if wait > 0.0002:
            time.sleep(wait - 0.0001)


def send_loop(fd: int, size: int, rate: float, seconds: float, run: int, fill) -> dict:
    """Send for `seconds` at `rate` per second (0: unpaced). fill(buf, seq, now_ns) writes one message."""
    # small batches at a low rate, so a message is not held back behind the others of its batch
    n = 1 if 0 < rate <= 20000 else 32
    batch = Batch(n, size)
    sent, errors = 0, 0
    start = time.monotonic()
    end = start + seconds
    while True:
        pace(rate, start, sent)
        now = time.monotonic()
        if now >= end:
            break
        t = time.monotonic_ns()
        for i in range(n):
            fill(batch.bufs[i], sent + i, t)
        k = LIBC.sendmmsg(fd, batch.msgs, n, 0)
        if k < 0:
            errors += 1
            continue
        sent += k
    took = time.monotonic() - start
    return {"sent": sent, "seconds": round(took, 4), "offered_per_s": round(sent / took), "send_errors": errors,
            "run": run, "size": size}


def udp_send(src: str, dst: str, port: int, size: int, rate: float, seconds: float, run: int, dev: str = "",
             fixed: bytes = b"") -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if dev:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, dev.encode())
    bigbuf(s, SO_SNDBUFFORCE, socket.SO_SNDBUF, 4 << 20)
    s.bind((src, 0))
    s.connect((dst, port))
    if fixed:
        def fill_fixed(buf, seq, t):
            if seq < 32:
                ctypes.memmove(ctypes.addressof(buf), fixed, len(fixed))
        return send_loop(s.fileno(), len(fixed), rate, seconds, run, fill_fixed)
    pad = b"x" * (size - HDR.size)

    def fill(buf, seq, t):
        HDR.pack_into(buf, 0, MAGIC, run, seq, t)
        if seq < 32:  # the padding is written once per buffer
            ctypes.memmove(ctypes.addressof(buf) + HDR.size, pad, len(pad))

    return send_loop(s.fileno(), size, rate, seconds, run, fill)


def checksum(h: bytes) -> int:
    s = sum(struct.unpack(f"!{len(h) // 2}H", h))
    s = (s >> 16) + (s & 0xFFFF)
    return (~(s + (s >> 16))) & 0xFFFF


def raw_send(ifname: str, size: int, rate: float, seconds: float, run: int, dst_port: int, fixed: bytes = b"") -> dict:
    """Ethernet frames of `size` bytes (no FCS) carrying one IPv4 UDP datagram each, from a documentation address.
    With `fixed`, every datagram carries those bytes instead (a message a converter reads), and size is ignored."""
    if fixed:
        size = 14 + 20 + 8 + len(fixed)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    bigbuf(s, SO_SNDBUFFORCE, socket.SO_SNDBUF, 4 << 20)
    s.bind((ifname, 0))
    payload_len = size - 14 - 20 - 8
    if payload_len < HDR.size and not fixed:
        raise SystemExit(f"a frame of {size} bytes cannot hold the {HDR.size}-byte header")
    eth = b"\x02\x00\x00\x00\x00\x20" + b"\x02\x00\x00\x00\x00\x10" + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + payload_len, 0, 0, 64, 17, 0,
                     bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20]))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    udp = struct.pack("!HHHH", 40000, dst_port, 8 + payload_len, 0)
    head = eth + ip + udp
    pad = b"r" * (payload_len - HDR.size)
    off = len(head)

    if fixed:
        def fill(buf, seq, t):
            if seq < 32:
                ctypes.memmove(ctypes.addressof(buf), head + fixed, size)
        return send_loop(s.fileno(), size, rate, seconds, run, fill)

    def fill(buf, seq, t):
        if seq < 32:
            ctypes.memmove(ctypes.addressof(buf), head, off)
            ctypes.memmove(ctypes.addressof(buf) + off + HDR.size, pad, len(pad))
        HDR.pack_into(buf, off, MAGIC, run, seq, t)

    return send_loop(s.fileno(), size, rate, seconds, run, fill)


def udp_sink(bind: str, port: int, seconds: float, run: int, idle: float = 1.0, deadline: float = 0) -> dict:
    """Count this run's datagrams until `seconds` have passed and nothing has arrived for `idle` seconds,
    or until `deadline` seconds (0: none), whichever is first."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bigbuf(s, SO_RCVBUFFORCE, socket.SO_RCVBUF, 64 << 20)
    s.bind((bind, port))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 0, 200000))
    print(json.dumps({"ready": True}), flush=True)
    n = 64
    batch = Batch(n, 65536)
    got, other, first, last = 0, 0, None, None
    lat: list[int] = []
    max_seq = -1
    start = time.monotonic()
    while True:
        k = LIBC.recvmmsg(s.fileno(), batch.msgs, n, MSG_WAITFORONE, None)
        now = time.monotonic()
        if deadline and now - start > deadline:
            break
        if k <= 0:
            if now - start > seconds and (last is None or now - last > idle):
                break
            continue
        t = time.monotonic_ns()
        last = now
        if first is None:
            first = now
        if run == 0:  # a converter's output carries no header: count every datagram
            got += k
            continue
        for i in range(k):
            if batch.msgs[i].len < HDR.size:
                other += 1
                continue
            magic, r, seq, sent_at = HDR.unpack_from(batch.bufs[i], 0)
            if magic != MAGIC or r != run:
                other += 1
                continue
            got += 1
            if seq > max_seq:
                max_seq = seq
            if len(lat) < 2_000_000:
                lat.append(t - sent_at)
    lat.sort()

    def q(p):
        return round(lat[min(len(lat) - 1, int(p * len(lat)))] / 1000, 1) if lat else None

    return {"received": got, "other": other, "max_seq": max_seq, "p50_us": q(0.5), "p99_us": q(0.99),
            "span_s": round((last - first), 4) if first and last else 0}


def main() -> None:
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd == "udp-send":
        out = udp_send(a[0], a[1], int(a[2]), int(a[3]), float(a[4]), float(a[5]), int(a[6]), a[7] if len(a) > 7 else "",
                       bytes.fromhex(a[8]) if len(a) > 8 else b"")
    elif cmd == "udp-sink":
        out = udp_sink(a[0], int(a[1]), float(a[2]), int(a[3]), float(a[4]) if len(a) > 4 else 1.0,
                       float(a[5]) if len(a) > 5 else 0)
    elif cmd == "raw-send":
        out = raw_send(a[0], int(a[1]), float(a[2]), float(a[3]), int(a[4]), int(a[5]), bytes.fromhex(a[6]) if len(a) > 6 else b"")
    else:
        raise SystemExit(f"unknown command {cmd}")
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
