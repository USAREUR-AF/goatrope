// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The capture of a `[[send]]`: an AF_PACKET socket on one tap port, receive only, with a
//! TPACKET_V2 ring of fixed frame slots mapped into the process (docs/adr/0006-data-path.md).
//!
//! The kernel copies each frame into the next free slot as it arrives, so a send process that
//! is not running for a while (a busy machine, a stall) loses nothing until every slot is full.
//! The ring's size is declared (`capture_mb`); a slot holds one frame of the port's MTU, so 16
//! MiB holds 8,192 frames at an MTU of 1,500, about 4 s at 2,000 frames a second. A socket's
//! receive queue alone holds about 220 small frames, a tenth of a second at that rate. (A
//! TPACKET_V3 ring of blocks hands a part-filled block over on a timer, so at a low rate each
//! block holds a few frames and the ring covers far less time; slots do not.) What the kernel
//! still drops (a full ring) is counted (PACKET_STATISTICS) and reported; a frame longer than
//! a slot is counted as truncated and not used.

use std::io;
use std::sync::atomic::{fence, Ordering};

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_STATISTICS: libc::c_int = 6;
const PACKET_VERSION: libc::c_int = 10;
const TPACKET_V2: libc::c_int = 1;
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;
/// Bytes per ring block (the kernel allocates the ring in blocks of whole slots).
const BLOCK: usize = 1 << 20;

#[repr(C)]
struct Req {
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
}

/// The ring: the socket, its mapping, and the slot it reads next.
pub struct Capture {
    fd: libc::c_int,
    map: *mut u8,
    len: usize,
    slot: usize,
    slots: usize,
    next: usize,
    /// frames the kernel put in the ring, and frames it dropped because the ring was full, since start
    pub packets: u64,
    pub dropped: u64,
    /// frames longer than a slot, not used
    pub truncated: u64,
}

/// The slot size for a port's MTU: header room and the frame, a power of two, at least 2 KiB.
pub fn slot_for(mtu: usize) -> usize {
    (mtu + 14 + 8 + 96).next_power_of_two().max(2048)
}

fn err() -> String {
    crate::sys::strerror(&io::Error::last_os_error())
}

impl Capture {
    /// Open the ring on `ifname`: `mb` MiB of slots sized for the port's MTU.
    pub fn open(ifname: &str, mb: usize) -> Result<Capture, String> {
        let mtu: usize =
            std::fs::read_to_string(format!("/sys/class/net/{ifname}/mtu")).ok().and_then(|m| m.trim().parse().ok()).unwrap_or(1500);
        let slot = slot_for(mtu).min(BLOCK);
        // SAFETY: plain socket(2); the descriptor is owned by Capture and closed on drop.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, ETH_P_ALL.to_be() as libc::c_int) };
        if fd < 0 {
            return Err(err());
        }
        let blocks = mb.max(1);
        let mut c = Capture {
            fd,
            map: std::ptr::null_mut(),
            len: BLOCK * blocks,
            slot,
            slots: BLOCK / slot * blocks,
            next: 0,
            packets: 0,
            dropped: 0,
            truncated: 0,
        };
        let v: libc::c_int = TPACKET_V2;
        // SAFETY: the option value is a c_int of the size given.
        if unsafe { libc::setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v as *const _ as *const libc::c_void, 4) } != 0 {
            return Err(format!("TPACKET_V2: {}", err()));
        }
        let req = Req { block_size: BLOCK as u32, block_nr: blocks as u32, frame_size: slot as u32, frame_nr: c.slots as u32 };
        // SAFETY: req is a tpacket_req of the size given.
        let rc = unsafe {
            libc::setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req as *const Req as *const libc::c_void, std::mem::size_of::<Req>() as u32)
        };
        if rc != 0 {
            return Err(format!("a ring of {blocks} MiB: {}", err()));
        }
        // SAFETY: maps the ring the kernel just set up on this socket.
        let map = unsafe { libc::mmap(std::ptr::null_mut(), c.len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) };
        if map == libc::MAP_FAILED {
            return Err(format!("mapping the ring: {}", err()));
        }
        c.map = map as *mut u8;
        let name = std::ffi::CString::new(ifname).map_err(|_| "bad interface name".to_string())?;
        // SAFETY: name is a valid NUL-terminated string.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(format!("no interface {ifname}"));
        }
        // SAFETY: sockaddr_ll is plain data; zeroed is a valid starting value.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ALL.to_be();
        sll.sll_ifindex = index as i32;
        // SAFETY: sll is a fully initialised sockaddr_ll of the size passed.
        let rc = unsafe { libc::bind(fd, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) };
        if rc != 0 {
            return Err(err());
        }
        Ok(c)
    }

    /// Slots in the ring.
    pub fn slots(&self) -> usize {
        self.slots
    }

    /// Give every frame waiting in the ring (up to one ring's worth) to `f`, handing each slot back
    /// to the kernel; waits up to `timeout_ms` when none is waiting. The number of frames given.
    pub fn next_frames(&mut self, timeout_ms: i32, mut f: impl FnMut(&[u8])) -> usize {
        // tpacket2_hdr: tp_status 0, tp_len 4, tp_snaplen 8, tp_mac 12
        let status = |h: *mut u8| {
            // SAFETY: tp_status is a u32 at the start of the slot, written by the kernel.
            unsafe { std::ptr::read_volatile(h as *const u32) }
        };
        let mut h = self.frame(self.next);
        if status(h) & TP_STATUS_USER == 0 {
            let mut p = libc::pollfd { fd: self.fd, events: libc::POLLIN | libc::POLLERR, revents: 0 };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut p, 1, timeout_ms) };
        }
        let mut n = 0;
        while n < self.slots && status(h) & TP_STATUS_USER != 0 {
            fence(Ordering::Acquire);
            // SAFETY: the kernel has handed this slot to user space: its header and frame are ours to read.
            unsafe {
                let len = std::ptr::read(h.add(4) as *const u32) as usize;
                let snaplen = std::ptr::read(h.add(8) as *const u32) as usize;
                let mac = std::ptr::read(h.add(12) as *const u16) as usize;
                if snaplen < len {
                    self.truncated += 1;
                } else if mac + snaplen <= self.slot {
                    f(std::slice::from_raw_parts(h.add(mac), snaplen));
                }
                fence(Ordering::Release);
                std::ptr::write_volatile(h as *mut u32, TP_STATUS_KERNEL);
            }
            n += 1;
            self.next = (self.next + 1) % self.slots;
            h = self.frame(self.next);
        }
        n
    }

    fn frame(&self, i: usize) -> *mut u8 {
        // SAFETY: i < slots; slots are contiguous because a block holds a whole number of them.
        unsafe { self.map.add(i * self.slot) }
    }

    /// Add the kernel's counters since the last read (reading resets them).
    pub fn read_stats(&mut self) {
        let mut st = [0u32; 2]; // tpacket_stats: packets, drops
        let mut len = std::mem::size_of_val(&st) as libc::socklen_t;
        // SAFETY: st is a tpacket_stats of the size given.
        if unsafe { libc::getsockopt(self.fd, SOL_PACKET, PACKET_STATISTICS, st.as_mut_ptr() as *mut libc::c_void, &mut len) } == 0 {
            self.packets += st[0] as u64;
            self.dropped += st[1] as u64;
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: the mapping and the descriptor are owned by this value.
        unsafe {
            if !self.map.is_null() {
                libc::munmap(self.map as *mut libc::c_void, self.len);
            }
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_hold_a_frame_of_the_mtu() {
        assert_eq!(slot_for(1500), 2048);
        assert_eq!(slot_for(9000), 16384);
        assert_eq!(BLOCK / slot_for(1500) * 16, 8192);
    }
}
