#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse
import socket
import sys
from scapy.all import sniff, get_if_list

def pick_iface():
    for i in get_if_list():
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    sys.exit(1)

def run_udp_server(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    print(f"UDP server on 0.0.0.0:{port} (Ctrl+C to stop)")
    try:
        while True:
            data, addr = s.recvfrom(65535)
            print(f"[UDP] {len(data)} bytes from {addr}")
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

def run_sniffer(iface: str, count: int, bpf: str):
    print(f"Sniffing on {iface} filter='{bpf}' (count={count or 'unlimited'})")
    sniff(iface=iface, filter=bpf if bpf else None,
          prn=lambda p: print(p.summary()), count=count if count > 0 else 0)

def main():
    p = argparse.ArgumentParser(description="Simple receiver/sniffer for P4 IDS testing")
    p.add_argument("--mode", choices=["udp_server", "sniff"], default="udp_server",
                   help="udp_server: listen on a UDP port; sniff: passive capture")
    p.add_argument("--port", type=int, default=1234, help="UDP server port (udp_server mode)")
    p.add_argument("--iface", default=None, help="Interface (default: eth0)")
    p.add_argument("--count", type=int, default=0, help="Packets to capture (sniff mode, 0=unlimited)")
    p.add_argument("--filter", default="udp or tcp", help="BPF filter (sniff mode)")
    args = p.parse_args()

    iface = args.iface or pick_iface()

    if args.mode == "udp_server":
        run_udp_server(args.port)
    else:
        run_sniffer(iface, args.count, args.filter)

if __name__ == "__main__":
    main()
