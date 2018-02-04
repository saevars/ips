import unittest
import pcapy as pc
from dnsparser import parse_header


class TestDnsParser(unittest.TestCase):

    def test_upper(self):
        ol = pc.open_offline("../dnssample.pcap")
        hdr, pkt = ol.next()
        while hdr is not None:
            popo = parse_header(pkt)
            nanswers = popo.get_ancount()
            numansers = len(popo.get_answers())
            self.assertEqual(nanswers, numansers)
            hdr, pkt = ol.next()

if __name__ == '__main__':
    unittest.main()