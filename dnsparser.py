#!/usr/bin/env python
import socket
from struct import unpack
from mydns import dns_packet, dns_answer, dns_question


def parse_name(ptr, data):
    name = ""
    ptr = check_pointer(ptr, data)
    length = ord(data[ptr])
    while length > 0:
        ptr += 1
        end = ptr + length
        name += data[ptr:end]
        ptr = end
        ptr = check_pointer(ptr, data)
        length = ord(data[ptr])
        if length > 0:
            name += "."
    return name


def check_pointer(ptr, data):
    offset_octs = data[ptr:ptr + 2]
    is_pointer = bin(ord(offset_octs[0])).zfill(8)[2:4] == '11'
    while is_pointer:
        ptr = unpack('!H', offset_octs)[0] - 0xc000
        offset_octs = data[ptr:ptr + 2]
        is_pointer = bin(ord(offset_octs[0])).zfill(8)[2:4] == '11'
    return ptr


def correct_pointer(ptr, data):
    is_pointer = check_if_pointer(ptr, data)
    if is_pointer:
        index = ptr + 2
    else:
        index = ptr + ord((data[ptr])) + 1
        nextw = ord(data[index])
        while nextw is not 0:
            if nextw is 0xc0:
                return index + 2
            index += nextw +1
            nextw = ord(data[index])
    return index


def parse_mx_rdata(rdl_index, data_string):
    pref = unpack('!H',data_string[rdl_index:rdl_index+2])[0]
    exchange = parse_name(rdl_index + 2, data_string)
    return ("prefernece", pref), ("exchange", exchange)


def parse_soa_rdata(rdl_index, data_string):
    mname = parse_name(rdl_index, data_string)
    rname_index = correct_pointer(rdl_index, data_string)
    rname = parse_name(rname_index, data_string)
    serial_index = correct_pointer(rname_index, data_string)
    last_five = unpack('!IIIII', data_string[serial_index:serial_index+20])
    serial = last_five[0]
    refresh = last_five[1]
    retry = last_five[2]
    expire = last_five[3]
    minimum = last_five[4]
    return ("mname", mname), ("rname", rname), ("serial", serial), ("refresh", refresh), ("retry", retry), ("expire", expire), ("minimum", minimum)


def check_if_pointer(ptr, data):
    return bin(ord(data[ptr])).zfill(8)[2:4] == '11'


def parse_header(packet):
    # Find length ip header and add to length of eth and udp headers
    eth_length = 14
    iph_length = (unpack('!B', packet[eth_length])[0]& 0xF) * 4
    udph_length = 8
    h_size = eth_length + iph_length + udph_length
    dns_size = str(len(packet) - h_size)

    # Start working with data from the dns header
    data = packet[h_size:]
    header_length = 12
    header = data[:header_length]
    raw_header = unpack('!HHHHHH', header)
    flags = bin(raw_header[1])[2:].zfill(16)
    popo = dns_packet(raw_header[0])
    popo.set_flags(flags)
    popo.set_qdcount(raw_header[2])
    popo.set_ancount(raw_header[3])
    popo.set_nscount(raw_header[4])
    popo.set_arcount(raw_header[5])

    data_string = unpack('!' + dns_size + 's',data)[0]
    question = dns_question()
    name = parse_name(header_length, data_string)
    question.set_name(name)
    type_index = header_length + len(name) + 3
    try:
        question.set_qtype(data_string[type_index])
        question.set_qclass(data_string[type_index+2])
    except KeyError as e:
        print "Question not supported"
        question = None
    if question is not None:
        popo.set_question(question)
    answer_start = type_index + 3
    for i in range(popo.get_ancount()):
        answer, answer_start = parse_resource(answer_start, data_string)
        if answer is not None:
            popo.add_answer(answer)
    for i in range(popo.get_nscount()):
        answer, answer_start = parse_resource(answer_start, data_string)
        if answer is not None:
            popo.add_nsrecord(answer)
    for i in range(popo.get_arcount()):
        answer, answer_start = parse_resource(answer_start, data_string)
        if answer is not None:
            popo.add_arrecord(answer)
    return popo

def parse_resource(answer_start, data_string):
    type_index = correct_pointer(answer_start, data_string) + 1
    ttl_index = type_index + 3
    rdl_length_index = ttl_index + 4
    rdl_index = rdl_length_index + 2
    type = data_string[type_index]
    try:
        answer = dns_answer()
        answer.set_type(type)
        name = parse_name(answer_start, data_string)
        answer.set_name(name)
        answer.set_aclass(data_string[type_index + 2])
        ttl = unpack('!L', data_string[ttl_index:ttl_index + 4])[0]
        answer.set_ttl(ttl)
        if answer.get_type() == 'A':
            address = socket.inet_ntoa(data_string[rdl_index:rdl_index + 4])
            answer.set_rdata(("address", address))
        elif answer.get_type() == 'NS':
            nsdname = parse_name(rdl_index, data_string)
            answer.set_rdata(("nsdmane", nsdname))
        elif answer.get_type() == 'CNAME':
            cname = parse_name(rdl_index, data_string)
            answer.set_rdata(("cname",cname))
        elif answer.get_type() == 'SOA':
            rdata = parse_soa_rdata(rdl_index, data_string)
            answer.set_rdata(rdata)
        elif answer.get_type() == 'PTR':
            ptrname = parse_name(rdl_index, data_string)
            answer.set_rdata(("ptrname", ptrname))
        elif answer.get_type() == 'MX':
            p, e = parse_mx_rdata(rdl_index, data_string)
            answer.set_rdata((p, e))
        elif answer.get_type() == 'TXT':
            txt = parse_name(rdl_index, data_string)
            answer.set_rdata(("txt", txt))
    except KeyError as e:
        answer = None
        print "Type ", ord(type), " not supported and answer is dropped"
    rd_length = unpack('!H', data_string[rdl_length_index:rdl_length_index + 2])[0]
    answer_start = rdl_index + rd_length
    return answer, answer_start
