import logging
from arpparser import parse_arp
from arpanalyser import *
from interface import ModuleInterface
from struct import unpack
import xml.etree.ElementTree as ET
from myarp import arp_packet


def is_arp(message):
    protocol = unpack('!12sH', message[0:14])[1]
    return protocol == 2054


def get_bindings(root):
    bindings = dict()
    for child in root.find('bindings'):
        ip = child.find('IP').text
        bindings[ip] = []
        macs = child.find('MACs')
        for mac in macs:
            bindings[ip].append(mac.text)
    return bindings


def update_arp_cache(popo, arp_cache):
    arp_cache[1:].append(popo)


class DAI(ModuleInterface):
    def __init__(self, config):
        tree = ET.parse(config)
        root = tree.getroot()
        self.bindings = get_bindings(root)
        self.arp_cache = [arp_packet(), arp_packet(), arp_packet(), arp_packet()]

    def analyse(self, packet):
        message = str(packet.pkt)
        if not is_arp(message):
            return
        arp = parse_arp(message)
        update_arp_cache(arp, self.arp_cache)
        if reply_is_a_response(arp, self.arp_cache):
            arp.label = PERMITTED
        if reply_is_brodcast(arp):
            arp.label = NOTICE
            logging.warning("Reply is a broadcast and might be dropped by some hosts. \n  ARP: " + str(arp) )
        if reply_is_not_a_responese(arp, self.arp_cache):
            arp.label = NOTICE
            logging.warning("Reply was not a response and might be dropped by some hosts. \n  ARP: " + str(arp))
        if destination_not_same_as_hardware(arp):
            arp.label = NOTICE
            logging.warning("Destinaiton address is not the same as hardware address and might be dropped by some hosts. \n  ARP: " + str(arp))
        if ip_to_mac_not_valid(arp, self.bindings):
            arp.label = NOTICE
            logging.warning("Invalid IP and MAC address allocation! Possible man in the middle attack. \n  ARP: " + str(arp))
        if is_sender_broadcasting_address(arp):
            arp.label = ERROR
            logging.error("Host can not claim the broadcasting address as its own. \n  ARP: " + str(arp))

