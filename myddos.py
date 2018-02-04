import string

from scapy.layers.inet import TCP, IP, random, sr1, send
import xml.etree.ElementTree as ET

from interface import ModuleInterface

TCP_IP_LAYER = 3
HTTP_LAYER = 7

def get_value_from_xml(config, name):
    tree = ET.parse(config)
    root = tree.getroot()
    ips = root.find('ddos')
    return ips.find(name).text


class TcpPackage(object):
    def __init__(self, src, time):
        self.whitelist = False
        self.src = src
        self.counter = 0
        self.state = 0
        self.time = time
        self.delta = 0
        self.rate_control = False

    def __eq__(self, other):
        return self.src == other

    def update_attributes(self, tcp):
        pass


class Ddos(ModuleInterface):
    def __init__(self, config):
        self.rate_limit = int(get_value_from_xml(config, 'rate-limit'))
        self.threshold = int(get_value_from_xml(config, 'threshold'))
        self.server = get_value_from_xml(config, 'server')
        self.layer = get_value_from_xml(config, 'layer')
        self.tcps = [TcpPackage("0", 0) for x in range(100)]

    def analyse(self, packet):
        message = packet.pkt
        # Check if it is Transport Layer, else don't care
        if message.haslayer(TCP):
            flags = message.sprintf('%TCP.flags%')
            # Check the defence layer if it is 3 and 4
            if self.layer == TCP_IP_LAYER:
                # Check if it comes from the server
                if message.src == self.server:
                    # Get tcp POPO based on the destination of the packet
                    tcp = self.get_tcp(message.dst, message.time)
                    # Check if Syn+Ack and update
                    if flags == 'SA':
                        tcp.state = 2
                    # Check if FYN or RST in packet and then start anew
                    elif 'F' in flags or 'R' in flags:
                        tcp.state = 0
                        tcp.counter = 0
                    self.tcps.append(tcp)
                # Check if the sever is the destination
                elif message.dst == self.server:
                    tcp = self.get_tcp(message.src, message.time)
                    if not tcp.rate_control or (tcp.rate_control and tcp.delta > self.rate_limit):
                        # Since it was not limited then update time
                        tcp.time = message.time
                        # Check if RST or FYN flags set
                        if 'R' in flags or 'F' in flags:
                            tcp.state = 0
                            tcp.counter = 0
                        # If it is a SYN then increment the counter
                        elif 'S' in flags and tcp.state != 3:
                            tcp.state = 1
                            tcp.counter += 1
                        # Handshake completed so counter is reset to zero
                        elif 'A' in flags and tcp.state == 2:
                            tcp.state = 3
                            tcp.counter = 0
                        # Activate the rate-control if counter above threshold
                        if tcp.counter > self.threshold and tcp.state != 3:
                            packet.drop = True
                            packet.send_rst = True
                            tcp.rate_control = True
                            tcp.counter = 0
                    else:
                        packet.drop = True
                    self.tcps.append(tcp)
            # Else if it is a layer 7 defence
            elif self.layer == HTTP_LAYER:
                if message.src != self.server:
                    # Get tcp POPO based on the destination of the packet
                    tcp = self.get_tcp(message.dst, message.time)
                    if 'S' in flags and not tcp.whitelist:
                        # Stage 1 of the handshake
                        ip = IP(dst=message.src, src=self.server)
                        SYNACK = ip / TCP(sport=80, dport=message.sport, flags="SA", ack=1)
                        send(SYNACK)
                    elif 'A' in flags and not tcp.whitelist:
                        random_string = ''.join(random.sample(string.lowercase + string.digits, 10))
                        # Get a HTTP get, reply with 302, check the new HTTP get, if it fits then send the syn and ack
                        # Packs to the server. Time is over so it will not be implemented tonight

    def get_tcp(self, src, t):
        # Get source from cache and update delta
        if src in self.tcps:
            tcp = self.tcps.pop(self.tcps.index(src))
            tcp.delta = t - tcp.time
            return tcp
        # Else create new tcp to be stored later
        else:
            tcp = TcpPackage(src,t)
            self.tcps.pop(0)
            return tcp



