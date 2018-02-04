import sys
import pcapy as pc
from mywifi import *
from dnsparser import parse_header


def parse_and_print_dns_from(pfile):
    ol = pc.open_offline(pfile)
    ol.setfilter('udp port 53')
    hdr, pkt = ol.next()
    while hdr is not None:
        print "\n \nParsing Package"
        popo = parse_header(pkt)
        print "\n \nPrinting DNS Attributes"
        for attribute, value in vars(popo).items():
            if attribute is "question":
                print "-question:"
                for attr, val in vars(popo.get_question()).items():
                    print " --" + attr + ": ", val
            elif attribute is "answers":
                for answer in popo.get_answers():
                    print "-answer:"
                    for attr, val in vars(answer).items():
                        print " --" + attr + ": ", val
            elif attribute is "nsrecords":
                for answer in popo.get_nsrecords():
                    print "-nsrecord:"
                    for attr, val in vars(answer).items():
                        print " --" + attr + ": ", val
            elif attribute is "arrecords":
                for answer in popo.get_arrecords():
                    print "-arrecord:"
                    for attr, val in vars(answer).items():
                        print " --" + attr + ": ", val
            else:
                print attribute + ": ", value
        hdr, pkt = ol.next()


def read_pcap( pcap_file):
    dev = 'wlp3s0'
    n_packages = 10
    reader = pc.open_live(dev, 65536, 1, 0)
    reader.setfilter('udp port 53')
    dumper = reader.dump_open(pcap_file)
    for ii in range(n_packages):
        hdr, pkt = reader.next()
        print hdr, pkt
        dumper.dump(hdr, pkt)
    dumper.close()

def main(argv):
    pcap_file = 'dnssample1.pcap'
    # read_pcap(pcap_file)
    parse_and_print_dns_from(pcap_file)


if __name__ == "__main__":

    wifi = WiFi()
    main(sys.argv)