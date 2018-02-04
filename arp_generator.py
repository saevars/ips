from scapy.all import *
from scapy.layers.l2 import Ether, ARP

from arpparser import parse_arp

arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2)
arp1 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, hwsrc="ff:ff:ff:ff:ff:ff")
arp2 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, hwsrc="00:01:02:03:04:05")
wrpcap("test/resources/project_2.pcap", [arp, arp1])

