class dns_packet(object):
    def __init__(self, id):
        self.set_id(id)
        self.answers = []
        self.nsrecords = []
        self.arrecords = []

    def __str__(self):
        return "DNS header with id " + str(self.id)

    def set_id(self, id):
        self.id = id

    def get_id(self):
        return self.id

    def set_qr(self, qr):
        self.qr = qr

    def set_opcode(self, param):
        self.opcode = param

    def set_aa(self, param):
        self.aa = param

    def set_tc(self, param):
        self.tc = param

    def set_rd(self, param):
        self.rd = param

    def set_ra(self, param):
        self.ra = param

    def set_z(self, param):
        self.z = param

    def set_rcode(self, param):
        self.rcode = param

    def set_qdcount(self, param):
        self.qdcount = param

    def set_ancount(self, param):
        self.ancount = param

    def set_nscount(self, param):
        self.nscount = param

    def set_arcount(self, param):
        self.arcount = param

    def get_ancount(self):
        return self.ancount

    def add_answer(self, answer):
        self.answers.append(answer)

    def get_answers(self):
        return self.answers

    def set_question(self, question):
        self.question = question

    def get_question(self):
        return self.question

    def set_flags(self, flags):
        self.qr = flags[0]
        self.opcode = flags[1:4]
        self.aa = flags[4]
        self.tc = flags[5]
        self.rd = flags[6]
        self.ra = flags[7]
        self.z = flags[8:11]
        self.rcode = flags[11:]

    def get_nscount(self):
        return self.nscount

    def add_nsrecord(self, answer):
        self.nsrecords.append(answer)

    def get_nsrecords(self):
        return self.nsrecords

    def get_arcount(self):
        return self.arcount

    def add_arrecord(self, answer):
        self.arrecords.append(answer)

    def get_arrecords(self):
        return self.arrecords


class dns_question:
    def __init__(self):
        pass

    def set_name(self, name):
        self.name = name

    def set_qclass(self, qclass):
        self.qclass = {1:'IN', 2:'CS', 3:'CH', 4:'HS', 255:'*'}[ord(qclass)]

    def get_qclass(self):
        return self.qclass

    def set_qtype(self, qtype):
        t = ord(qtype)
        try:
            self.qtype = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 14:'PTR', 15:'MX', 16:'TXT', 255:'*'}[t]
        except KeyError as e:
            raise KeyError("Type number: " + str(t)  + " is not supported!")

    def get_qtype(self):
        return self.qtype


class dns_answer:
    def set_name(self, name):
        self.name = name

    def __init__(self):
        self.name = ""
        self.aclass = ""
        self.type = ""
        self.ttl = 0
        self.rdata = None

    def set_type(self, type):
        t = ord(type)
        try:
            self.type = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 14:'PTR', 15:'MX', 16:'TXT', 255:'*'}[t]
        except KeyError as e:
            raise KeyError("Type number: " + str(t)  + " is not supported!")

    def get_type(self):
        return self.type

    def set_aclass(self, aclass):
        self.aclass = {1:'IN', 2:'CS', 3:'CH', 4:'HS', 255:'*'}[ord(aclass)]

    def set_ttl(self, ttl):
        self.ttl = ttl

    def set_rdlength(self, rdlength):
        self.rdlength = rdlength

    def set_rdata(self, rdata):
        self.rdata = rdata