#!/usr/bin/env python3
"""Build a small synthetic pcap that should trigger every local rule once (requires: pip install scapy).

All addresses are lab-private. Used by tests/pcap/run_suricata_pcap.sh to prove the rules fire.
"""

import sys
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap

ATTACKER, TARGET, RESOLVER = "192.168.56.66", "192.168.56.10", "192.168.56.1"
packets, clock = [], [1_760_000_000.0]


def emit(packet, step=0.01):
    clock[0] += step
    packet.time = clock[0]
    packets.append(packet)


def session(src, sport, dst, dport, payload: bytes, gap=0.05):
    """Full three-way handshake, one client request, ACK, then FIN."""
    seq, ack = 1000, 5000
    emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq))
    emit(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1))
    emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
    emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=ack + 1) / Raw(payload))
    emit(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=ack + 1, ack=seq + 1 + len(payload)))
    emit(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq + 1 + len(payload), ack=ack + 1), gap)


def http(path="/", headers=""):
    return f"GET {path} HTTP/1.1\r\nHost: lab.local\r\n{headers}\r\n".encode()


for i in range(12):  # sid 9000003: ICMP echo burst
    emit(IP(src=ATTACKER, dst=TARGET) / ICMP(id=7, seq=i) / Raw(b"x" * 16), 0.1)
for port in range(1000, 1035):  # sid 9000002: SYN burst across ports
    emit(IP(src=ATTACKER, dst=TARGET) / TCP(sport=45000 + port, dport=port, flags="S"), 0.05)
for i in range(6):  # sid 9000001: repeated SSH connection attempts
    emit(IP(src="192.168.56.67", dst=TARGET) / TCP(sport=51000 + i, dport=22, flags="S"), 1.0)
session("192.168.56.77", 52001, TARGET, 80, http("/", "User-Agent: sqlmap/1.7\r\n"))  # sid 9000004
session("192.168.56.31", 52002, TARGET, 8080, http("/admin", "Authorization: Basic YWRtaW46cGFzcw==\r\n"))  # sid 9000005
session("192.168.56.77", 52003, TARGET, 80, http("/download?f=../../etc/passwd", "User-Agent: curl/8.0\r\n"))  # sid 9000007
session("192.168.56.32", 52004, TARGET, 23, b"login: ")  # sid 9000008
label = "a" * 45  # sid 9000006: DNS label of 45 characters
emit(IP(src="192.168.56.20", dst=RESOLVER) / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{label}.example.test")))
emit(IP(src="192.168.56.21", dst=RESOLVER) / UDP(sport=53001, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.test")))  # benign control

wrpcap(sys.argv[1] if len(sys.argv) > 1 else "lab-rules.pcap", packets)
print(f"wrote {len(packets)} packets")
