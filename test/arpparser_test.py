from __future__ import absolute_import
import unittest
import pcapy as pc
from arpparser import parse_arp


class TestARPParser(unittest.TestCase):

    def test_upper(self):
        ol = pc.open_offline("resources/arp_len_2.pcap")
        ol.setfilter('arp')
        hdr, pkt = ol.next()
        popo_r = parse_arp(pkt)
        self.assertEquals(popo_r.eth_addr_dest, "ff:ff:ff:ff:ff:ff")
        hdr, pkt = ol.next()
        popo_a = parse_arp(pkt)
        self.assertEquals(popo_a.eth_addr_dest, "68:5d:43:8b:4a:66")

    def test_sender(self):
        ol = pc.open_offline("resources/arp_len_2.pcap")
        ol.setfilter('arp')
        hdr, pkt = ol.next()
        popo_r = parse_arp(pkt)
        self.assertEquals(popo_r.eth_addr_sender, popo_r.sha)
        hdr, pkt = ol.next()
        popo_a = parse_arp(pkt)
        self.assertEquals(popo_a.eth_addr_sender, popo_a.sha)

    def test_pcap(self):
        ol = pc.open_offline("resources/testfile.pcap")
        hdr, pkt = ol.next()
        popo = parse_arp(pkt)
        self.assertEquals(popo.eth_addr_sender, "68:5d:43:8b:4a:66")


if __name__ == '__main__':
    unittest.main()