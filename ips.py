import logging
import nfqueue
import os
import socket
import sys

from scapy.layers.inet import IP
from scapy.sendrecv import sniff, send, sendp
from scapy.utils import rdpcap
import mydai
from myddos import Ddos
from mywifi import WiFi
from inhouse import IpsPacket
from Queue import Queue
import xml.etree.ElementTree as ET

# Create a queue so that packages are stored when IPS is busy
message_queue = Queue()


# Small method to add all new packages to the message queue
def put_package_on_queue(p):
    if not message_queue.full() and p.haslayer(IP):
        message_queue.put(p)


def read_packages(iface):
    sniff(prn=put_package_on_queue)


# A simple observer pattern dispatcher
class IPS:
    def __init__(self):
        self.subscribers = set()

    def register(self, who):
        self.subscribers.add(who)

    def unregister(self, who):
        self.subscribers.discard(who)

    def dispatch(self, message):
        for subscriber in self.subscribers:
            subscriber.update(message)


# Get the interface from config file
def get_iface(config,name):
    tree = ET.parse(config)
    root = tree.getroot()
    ips = root.find('ips')
    return ips.find(name).text

# Send all traffic from server and host to the nfqueue
os.system('iptables -t nat -A  PREROUTING -s 10.10.0.200 -j NFQUEUE --queue-num 0')
os.system('iptables -t nat -A  PREROUTING -s 10.10.0.1 -j NFQUEUE --queue-num 0')

# Spawn a new instance of the IPS and other modules
ips = IPS()


def main(argv):
    logging.basicConfig(filename='ips.log', level=logging.DEBUG)
    logging.info("starting the IPS")
    # Get config file and instantiate modules with the configs
    if len(argv) > 1:
        dai = mydai.DAI(argv[1])
        wifi = WiFi(argv[1])
        ddos = Ddos(argv[1])
    else:
        print "Missing config file for IPS"
        return -1
    # Register the modules with the IPS so they get updates in new messages
    ips.register(dai)
    ips.register(wifi)
    ips.register(ddos)
    # Read a packet file from the commandline input
    if len(argv) > 2:
        packets = rdpcap(argv[2])
        offline = True
    else:
        print ("Missing offline pcap file. \nLive sniffing will be attempted")
        try:
            q.try_run()
            offline = False
        except:
            print("Error: unable to start thread")
            return -1

    # Loop through the packets
    if offline:
        for pkt in packets:
            put_package_on_queue(pkt)
            p = message_queue.get()
            packet = IpsPacket(p['IP'])
            ips.dispatch(packet)
            if packet.drop:
                print("Dropping packet")


def run_modules(nums, payload):
    # Get tha package from the payload
    data = payload.get_data()
    pkt = IP(data)
    # Wrap the packet in the inhouse wrapper
    packet = IpsPacket(pkt)
    # Send a packet through the ISP moduels
    ips.dispatch(packet)
    # If the packet has not been marked as drop then send it
    if not packet.drop:
        try:
            send(packet.pkt, verbose=0)
        except:
            print('failed to send packet')
    else:
        print("Dropping Packet")
    if packet.send_rst:
        pkt.payload.fields['flags'] = 4
        sendp(pkt, verbose=0)

# Setup the nf-queue
q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET)
q.set_callback(run_modules)
q.create_queue(0) #Same queue number of the rule


if __name__ == "__main__":
    try:
        # q.try_run()
        main(sys.argv)
    except KeyboardInterrupt, e:
        os.system('iptables -t -F')  # remove iptables rule
        print "interruption"
        q.unbind(socket.AF_INET)
        q.close()
    main(sys.argv)
