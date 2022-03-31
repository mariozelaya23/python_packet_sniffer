#!/usr/bin/env python

from scapy.all import *
from scapy.layers import http


def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.all.Raw):
            print(packet[scapy.all.Raw].load)


sniff("eth0")

