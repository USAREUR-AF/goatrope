// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//
// THE REFERENCE PROTOTYPE, NOT SHIPPED. goatrope does not build, load or test this file. It is the
// C program ADR 0006 measured before the relay's kernel path was built; the program the relay
// loads is written as BPF instructions in src/kpath.rs, with the checks this prototype does not
// make (lengths, the IP header checksum, the link MTU, GSO, local addresses from a map).
//
// One relay rule (remote-to-link, UDP) in a tc program on the WireGuard interface's ingress: a
// datagram from REMOTE to LOCAL:LISTEN is rewritten to LINK:SPORT -> TARGET:TPORT and sent out of
// the link interface with bpf_redirect_neigh, which fills in the Ethernet header from the neighbor
// table (the program first pushes a placeholder header for it to replace). Everything else,
// fragments included, goes on to the relay's socket. The link interface's index was written in
// place of the placeholder 0x7e1f1d00 before loading it with tc.
//
//   clang -O2 -target bpf -c relay_tc.c -o relay_tc.o
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define SEC(n) __attribute__((section(n), used))
#define BE16(x) ((__u16)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#define BE32(a, b, c, d) ((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))

// the bench topology (tests/netns/test_tap.py, topo_relay): documentation addresses only
#define REMOTE BE32(10, 99, 0, 2)
#define LOCAL BE32(10, 99, 0, 1)
#define LINK BE32(192, 0, 2, 50)
#define TARGET BE32(192, 0, 2, 2)
#define LISTEN 7002
#define TPORT 7002
#define SPORT 47002
#define IFINDEX 0x7e1f1d00

static long (*store_bytes)(struct __sk_buff *, __u32, const void *, __u32, __u64) = (void *)BPF_FUNC_skb_store_bytes;
static long (*l3_csum_replace)(struct __sk_buff *, __u32, __u64, __u64, __u64) = (void *)BPF_FUNC_l3_csum_replace;
static long (*l4_csum_replace)(struct __sk_buff *, __u32, __u64, __u64, __u64) = (void *)BPF_FUNC_l4_csum_replace;
static long (*redirect_neigh)(__u32, void *, int, __u64) = (void *)BPF_FUNC_redirect_neigh;
static long (*change_head)(struct __sk_buff *, __u32, __u64) = (void *)BPF_FUNC_skb_change_head;

#define IP_CSUM 10
#define IP_SRC 12
#define IP_DST 16
#define UDP_SPORT 20
#define UDP_DPORT 22
#define UDP_CSUM 26

SEC("tc") int relay(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
    struct iphdr *ip = data; // a WireGuard interface has no link-layer header
    if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    if (ip->frag_off & BE16(0x3fff)) // a fragment: the socket path reassembles it
        return TC_ACT_OK;
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > end)
        return TC_ACT_OK;
    if (ip->saddr != REMOTE || ip->daddr != LOCAL || udp->dest != BE16(LISTEN))
        return TC_ACT_OK;
    __u32 osrc = ip->saddr, odst = ip->daddr, nsrc = LINK, ndst = TARGET;
    __u16 osport = udp->source, odport = udp->dest, nsport = BE16(SPORT), ndport = BE16(TPORT);
    __u64 l4 = BPF_F_MARK_MANGLED_0;
    l4_csum_replace(skb, UDP_CSUM, osrc, nsrc, l4 | BPF_F_PSEUDO_HDR | 4);
    l4_csum_replace(skb, UDP_CSUM, odst, ndst, l4 | BPF_F_PSEUDO_HDR | 4);
    l4_csum_replace(skb, UDP_CSUM, osport, nsport, l4 | 2);
    l4_csum_replace(skb, UDP_CSUM, odport, ndport, l4 | 2);
    l3_csum_replace(skb, IP_CSUM, osrc, nsrc, 4);
    l3_csum_replace(skb, IP_CSUM, odst, ndst, 4);
    store_bytes(skb, IP_SRC, &nsrc, 4, 0);
    store_bytes(skb, IP_DST, &ndst, 4, 0);
    store_bytes(skb, UDP_SPORT, &nsport, 2, 0);
    store_bytes(skb, UDP_DPORT, &ndport, 2, 0);
    // bpf_redirect_neigh expects an Ethernet header to replace; the WireGuard packet has none, so
    // push one (its addresses are overwritten from the neighbor table, its type says IPv4)
    if (change_head(skb, 14, 0))
        return TC_ACT_SHOT;
    __u8 eth[14] = {2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00};
    store_bytes(skb, 0, eth, 14, 0);
    return redirect_neigh(IFINDEX, 0, 0, 0);
}

char _license[] SEC("license") = "Apache-2.0";
