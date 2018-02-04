# !/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
from random import randint

from scapy.layers.l2 import Ether

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Import scapy
from scapy.all import *

# Print info header
print "[*] ACK-GET example -- Thijs 'Thice' Bosschert, 06-06-2011"

# Prepare GET statement
get = 'GET / HTTP/1.1\n\n'


def get_random_ip():
    return str(198) + "." + str(randint(0,255)) + "." + str(randint(0,255)) + "." + str(randint(0,255))
cnt = 0
syns = []
for i in range(20):
    ip_add = get_random_ip()
    # Set up target IP
    ip = IP(dst="10.10.0.200", src="10.10.0.100")

    # Generate random source port number
    port = RandNum(1024, 65535)

    # Create SYN packet
    SYN = ip / TCP(sport=port, dport=80, flags="S")
    # Send SYN and receive SYN,ACK
    print "\n[*] Sending SYN packet from ip ", ip_add,  " number ", cnt
    # syns.append(SYN)
    SYNACK = sr1(SYN)
    # syns.append(SYNACK)
    time.sleep(0.3)
    # # Create ACK with GET request
    ACK = ip / TCP(sport=SYNACK.dport, dport=80, flags="PA", seq=SYNACK.ack, ack=SYNACK.seq + 1) / get
    # syns.append(ACK)
    # #
    # # # SEND our ACK-GET request
    # # print "\n[*] Sending ACK-GET packet"
    reply  = sr1(ACK)
    # syns.append(reply)
    # cnt += 1
    # print reply from server
    # print "\n[*] Reply from server:"
    # print reply.show()

    # print '\n[*] Done!'
# wrpcap("test/resources/project_5_Eth.pcap", syns)