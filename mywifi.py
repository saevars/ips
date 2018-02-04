from scapy.layers.dot11 import Dot11, ARP
import xml.etree.ElementTree as ET
from interface import ModuleInterface
import logging

Association_Request= 0
Association_Response= 1
Re_association_Request= 2
Re_association_Response= 3
Probe_Request= 4
Probe_Response= 5
Beacon= 8
Announcement_traffic_indication_message= 9
Disassociation= 10
Authentication= 11
De_authentication = 12

# A wireless client should reject the following frames sent from a
# Rogue AP: Authentication Response, Association Response, De
# authentication Notification, Disassociation Notification, Beacon
# and Probe Response frames.


def get_source_from(config):
    wifi = get_wifi_parameters(config)
    return wifi.find('AP').text


def get_delta_time_from(config):
    wifi = get_wifi_parameters(config)
    return wifi.find('delta').text


def get_wifi_parameters(config):
    tree = ET.parse(config)
    root = tree.getroot()
    wifi = root.find('wifi')
    return wifi


class WiFi(ModuleInterface):
    def __init__(self, config):
        self.arp_threshold = get_delta_time_from(config)
        self.trusted_source = get_source_from(config)
        self.subtypes = [Association_Response, Authentication, Disassociation, De_authentication]
        self.last_trused = 0
        self.sn_threshold = 10
        self.last_arp = ARP
        self.state = 0

    def analyse(self, packet):
        message = packet.pkt
        # Check if it is a 802.11 frame
        if message.haslayer(Dot11):
            # Check if this is a management frame
            if message.type == 0 and message.addr2 == self.trusted_source:
                # Bitshift the Control Sequence by 4 to get the 12 bit Sequence Number
                sn = message.SC >> 4
                sn_gap = sn - self.last_trused
                # Always trust Beacons or Prope responses
                if message.subtype == Beacon or message.subtype == Probe_Response:
                    self.last_trused = sn
                # If the sequence is under a resonable threshold then it all good
                elif self.sn_threshold > sn_gap > 0:
                    self.last_trused = sn
                # Logg all out of sequence messages that are in subtypes
                elif message.subtype in self.subtypes:
                    logging.warning("Possible DeAuthentication Dos Attack!\n  - Sequence number = " +  str(sn) +  " and subtype = " + str(message.subtype))
        elif message.haslayer(ARP):
            # Check if the new ARP is the same as the last, if not then reset state to 0
            if message != self.last_arp:
                self.state = 0
            # Check if the new ARP came within the delta parmeter
            elif message.time - self.last_arp.time > self.arp_threshold:
                self.state = 0
            # Log warnings and the number of ARP replays in a row
            else:
                self.state += 1
                logging.warning("Possible ARP replay underway! There are " + str(self.state) + " replayed ARPs in a row!!")
            self.last_arp = message



