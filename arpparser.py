from struct import unpack
import socket
from myarp import arp_packet


# From https://tools.ietf.org/html/rfc826:
# To communicate mappings from <protocol, address> pairs to 48.bit
# Ethernet addresses, a packet format that embodies the Address
# Resolution protocol is needed.  The format of the packet follows.
#
#     Ethernet transmission layer (not necessarily accessible to
#          the user):
#         48.bit: Ethernet address of destination
#         48.bit: Ethernet address of sender
#         16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
#     Ethernet packet data:
#         16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
#                          Packet Radio Net.)
#         16.bit: (ar$pro) Protocol address space.  For Ethernet
#                          hardware, this is from the set of type
#                          fields ether_typ$<protocol>.
#          8.bit: (ar$hln) byte length of each hardware address
#          8.bit: (ar$pln) byte length of each protocol address
#         16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
#         nbytes: (ar$sha) Hardware address of sender of this
#                          packet, n from the ar$hln field.
#         mbytes: (ar$spa) Protocol address of sender of this
#                          packet, m from the ar$pln field.
#         nbytes: (ar$tha) Hardware address of target of this
#                          packet (if known).
#         mbytes: (ar$tpa) Protocol address of target.


def eth_addr(a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b


def parse_arp(packet):
    arp_popo = arp_packet()
    eth_length = 22
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sHHHBBH', eth_header)
    arp_popo.eth_addr_dest = eth_addr(eth[0])
    arp_popo.eth_addr_sender = eth_addr(eth[1])
    arp_popo.ptype = eth[2]
    arp_popo.hrd = eth[3]
    arp_popo.pro = eth[4]
    arp_popo.hln = eth[5]
    arp_popo.pln = eth[6]
    arp_popo.op = eth[7]
    end = eth_length + arp_popo.hln * 2 + arp_popo.pln * 2
    address_string = "!" + str(arp_popo.hln) + "s" + str(arp_popo.pln) + "s"+  str(arp_popo.hln) + "s" + str(arp_popo.pln) + "s"
    addresses = unpack(address_string, packet[eth_length:end])
    arp_popo.sha = eth_addr(addresses[0])
    arp_popo.spa = socket.inet_ntoa(addresses[1])
    arp_popo.tha = eth_addr(addresses[2])
    arp_popo.tpa = socket.inet_ntoa(addresses[3])

    return arp_popo
