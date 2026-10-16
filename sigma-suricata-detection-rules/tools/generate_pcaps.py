#!/usr/bin/env python3
"""Generate non-exploitative HTTP/DNS synthetic fixtures on documentation IP ranges.
PCAPs are *offline* test inputs, never transmitted by this program.
"""
from pathlib import Path
import json
BASE=Path(__file__).resolve().parents[1]


def main():
    try:
        from scapy.all import Ether,IP,TCP,UDP,Raw,DNS,DNSQR,wrpcap
    except ImportError as ex:
        raise SystemExit('Install PCAP tooling: python3 -m pip install -r requirements-pcap.txt') from ex
    output=BASE/'outputs/pcaps'; output.mkdir(parents=True,exist_ok=True)
    cases=json.loads((BASE/'sample-data/suricata_cases.json').read_text())
    for index,case in enumerate(cases):
        if case['type']=='dns':
            pkt=Ether()/IP(src='192.168.1.20',dst='198.51.100.53')/UDP(sport=53000+index,dport=53)/DNS(id=1234+index,rd=1,qd=DNSQR(qname=case['qname']))
            packets=[pkt]
        else:
            client='198.51.100.10'; server='192.168.1.10'; cport=40000+index
            eth=Ether(); c=IP(src=client,dst=server); s=IP(src=server,dst=client)
            def cli(flags,seq,ack,payload=None):
                return eth/c/TCP(sport=cport,dport=80,flags=flags,seq=seq,ack=ack)/(Raw(payload) if payload else b'')
            def srv(flags,seq,ack,payload=None):
                return eth/s/TCP(sport=80,dport=cport,flags=flags,seq=seq,ack=ack)/(Raw(payload) if payload else b'')
            request=(f"GET {case['uri']} HTTP/1.1\r\nHost: app.example.org\r\nUser-Agent: {case.get('user_agent','Mozilla/5.0')}\r\nConnection: close\r\n\r\n").encode()
            response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
            packets=[cli('S',1000,0),srv('SA',5000,1001),cli('A',1001,5001),cli('PA',1001,5001,request),
                     srv('A',5001,1001+len(request)),srv('PA',5001,1001+len(request),response),cli('A',1001+len(request),5001+len(response))]
        wrpcap(str(output/(case['case_id']+'.pcap')),packets)
        print(case['case_id'],len(packets),'packets')
    print('Generated offline PCAPs:',output)

if __name__=='__main__':main()
