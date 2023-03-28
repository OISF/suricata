#!/usr/bin/env python3
# Simple script to parse a pcap file and output a CSV
# style line for each packet containing:
# * IP family (4/6)
# * 5 tuple
# * Direction (we assume the first IP is always the client)
# * Timestamp
# * Stream segment length
# * Stream segment data (base64 encoded)

import base64
import csv
import dpkt
import io
import ipaddress
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: pcap2stream.py <input.pcap>")
        sys.exit(-1)

    pcap_file = sys.argv[1]
    output = pcap_file.replace('.pcap', '.stream')

    with io.open(output, 'w', newline='\n') as ofd:
        writer = csv.writer(ofd, delimiter=',', quotechar='|', lineterminator='\n')

        with open(pcap_file, 'rb') as fd:
            pcap = dpkt.pcap.Reader(fd)
            clients = set()
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                if ip.get_proto(ip.p) != dpkt.tcp.TCP:
                    # Skip any non TCP packet.
                    continue

                tcp = ip.data
                if len(tcp.data) == 0:
                    # Skip any packet non carrying a payload (e.g ACKs)
                    continue

                version = ip.v
                if version == 4:
                    src = int(ipaddress.IPv4Address(ip.src))
                    dst = int(ipaddress.IPv4Address(ip.dst))
                else:
                    src = int(ipaddress.IPv6Address(ip.src))
                    dst = int(ipaddress.IPv6Address(ip.dst))
                if src not in clients and dst not in clients:
                    clients.add(src)
                    direction = 0
                elif src in clients:
                    direction = 0
                else:
                    direction = 1

                line = [ts, version, direction, src, dst, tcp.sport, tcp.dport, len(tcp.data),
                        base64.b64encode(tcp.data).decode()]
                writer.writerow(line)


if __name__ == "__main__":
    main()
