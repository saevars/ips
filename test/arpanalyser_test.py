import unittest
import pcapy as pc
from arpanalyser import reply_is_brodcast
from arpparser import parse_arp


class TestARPAnalyser(unittest.TestCase):
    def test_reply_is_brodcst(self):
        ol = pc.open_offline("resources/brodcast_reply.pcap")
        h,p = ol.next()
        popo = parse_arp(p)
        is_noticeable = reply_is_brodcast(popo)
        self.assertTrue(is_noticeable)

    def test_reply_is_a_responese(self):
        pass

if __name__ == '__main__':
    unittest.main()