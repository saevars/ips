import unittest
from scapy.all import *
import pcapy as pc
from mywifi import WiFi


class TestWiFi(unittest.TestCase):

    def test_analyse(self):
        pkts = sniff(offline='resources/wifi.cap', count=55)
        for pkt in pkts:
            print "what : " + str(pkt.type)
            if pkt.subtype == 11 or pkt.subtype == 13:
                print pkt.subtype
            # if pkt.type != 0:
            #     print pkt.subtype

    def test_analyse_wrong_packets(self):
        # pkts = sniff(offline='resources/wifi.cap', count=1)
        ol = pc.open_offline("resources/wifi.cap")
        hdr, pkt = ol.next()
        print "what"
        while hdr is not None:
            wifi = WiFi()
            wifi.analyse(pkt)
            hdr, pkt = ol.next()

if __name__ == '__main__':
    unittest.main()