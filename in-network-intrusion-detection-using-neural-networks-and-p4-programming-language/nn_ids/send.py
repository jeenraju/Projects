#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse
import random
import socket
import sys

from scapy.all import Ether, IP, UDP, TCP, Raw, sendp, get_if_list, get_if_hwaddr

def pick_iface():
    # Mininet hosts usually expose "eth0"
    for i in get_if_list():
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    sys.exit(1)

def main():
    p = argparse.ArgumentParser(description="Simple traffic generator for P4 IDS testing")
    p.add_argument("dst", help="Destination IPv4 (e.g., 10.0.2.2)")
    p.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="L4 protocol")
    p.add_argument("--sport", type=int, default=None, help="Source port (default: random high for TCP/UDP)")
    p.add_argument("--dport", type=int, default=1234, help="Destination port")
    p.add_argument("--ttl", type=int, default=64, help="IP TTL (affects sttl feature)")
    p.add_argument("--count", type=int, default=5, help="Number of packets")
    p.add_argument("--inter", type=float, default=0.1, help="Inter-packet gap seconds")
    p.add_argument("--payload", default="hello", help="Payload bytes/string")
    # TCP extras
    p.add_argument("--flags", default="S", help="TCP flags (e.g., S, SA, PA)")
    p.add_argument("--win", type=int, default=64240, help="TCP window (affects swin)")
    p.add_argument("--seq", type=int, default=1000000, help="TCP seq (we also bucket >>20 in P4)")
    p.add_argument("--ack", type=int, default=0, help="TCP ack")
    p.add_argument("--iface", default=None, help="Interface (default: eth0)")
    args = p.parse_args()

    iface = args.iface or pick_iface()
    dst_ip = socket.gethostbyname(args.dst)
    src_mac = get_if_hwaddr(iface)

    # Choose a reasonable default sport if not provided
    if args.sport is None:
        if args.proto == "udp":
            # use DNS-like (53) as an easy “benign-ish” default
            sport = 53
        else:
            # random high port for TCP by default
            sport = random.randint(49152, 65535)
    else:
        sport = args.sport

    eth = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    ip  = IP(dst=dst_ip, ttl=args.ttl)

    if isinstance(args.payload, str):
        payload = Raw(load=args.payload.encode("utf-8"))
    else:
        payload = Raw(load=bytes(args.payload))

    if args.proto == "udp":
        l4 = UDP(sport=sport, dport=args.dport)
        pkt = eth / ip / l4 / payload
    else:
        l4 = TCP(sport=sport, dport=args.dport, flags=args.flags, window=args.win, seq=args.seq, ack=args.ack)
        pkt = eth / ip / l4 / payload

    print(f"Sending {args.count} {args.proto.upper()} packets on {iface} to {dst_ip}:{args.dport} (sport={sport}, ttl={args.ttl})")
    sendp(pkt, iface=iface, count=args.count, inter=args.inter, verbose=False)
    print("Done.")

if __name__ == "__main__":
    main()
