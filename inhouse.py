class IpsPacket:
    def __init__(self, p):
        self.pkt = p
        self.drop = False
        self.send_rst = False