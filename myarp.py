class arp_packet(object):
    def __init__(self):
        self.eth_addr_dest = ""
        self.eth_addr_sender = ""
        self.ptype = None
        self.hrd = None
        self.pro = None
        self.hln = None
        self.pln = None
        self.op  = None
        self.sha =  None
        self.spa =  None
        self.tha =  None
        self.tpa =  None
        self.label =  None

    def __str__(self):
        return "eth_addr_dest: " + self.eth_addr_dest + "; " \
               + "eth_addr_sender: " + self.eth_addr_sender + "; " \
               + "ptype: " + str(self.ptype) + "; " \
               + "hrd: " + str(self.hrd) + "; "\
               + "pro: " + str(self.pro) + "; "\
               + "hln: " + str(self.hln) + "; "\
               + "pln: " + str(self.pln) + "; "\
               + "op: " + str(self.op ) + "; "\
               + "sha: " + str(self.sha) + "; "\
               + "spa: " + str(self.spa) + "; "\
               + "tha: " + str(self.tha) + "; "\
               + "tpa: " + str(self.tpa) + "; "\
               + "label: " + str(self.label) + "; "
