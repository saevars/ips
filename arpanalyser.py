ERROR = "error"
NOTICE = "notice"
BRODCAST = "ff:ff:ff:ff:ff:ff"
REQUEST = 1
REPLY = 2
PERMITTED = "permitted"

#    * An incorrect ARP implementation may expect that ARP Replies are
#      only sent via unicast.  RFC 826 does not say this, but an incorrect
#      implementation may assume it; the "principle of least surprise"
#      dictates that where there are two or more ways to solve a
#      networking problem that are otherwise equally good, the one with
#      the fewest unusual properties is the one likely to have the fewest
#      interoperability problems with existing implementations.  An ARP
#      Announcement needs to broadcast information to all hosts on the
#      link.  Since ARP Request packets are always broadcast, and ARP
#      Reply packets are not, receiving an ARP Request packet via
#      broadcast is less surprising than receiving an ARP Reply packet via
#      broadcast
def reply_is_brodcast( popo):
    if popo.op is REPLY and popo.eth_addr_dest != BRODCAST:
        return False
    return True


#    * An incorrect ARP implementation may expect that ARP Replies are
#      only received in response to ARP Requests that have been issued"ff:ff:ff:ff:ff:ff"
#      recently by that implementation.  Unexpected unsolicited Replies
#      may be ignored.
def reply_is_not_a_responese(popo, arp_cache):
    for arp in arp_cache:
        if arp.op is REQUEST and arp.tpa is popo.spa and arp.eth_addr_dest is BRODCAST:
            return False
    return True

# Check if reply is a resonse to a request

def reply_is_a_response(popo, arp_cache):
    return not reply_is_not_a_responese(popo, arp_cache)


#    * An incorrect ARP implementation may ignore ARP Replies where
#      'ar$tha' doesn't match its hardware address.
def destination_not_same_as_hardware(popo):
    if popo.op is REPLY and popo.eth_addr_dest is not popo.tha:
        return True
    return False


#    * An incorrect ARP implementation may ignore ARP Replies where
#      'ar$tpa' doesn't match its IP address.
def destination_matces_ip(popo, ip):
    if popo.op is REPLY and popo.tpa is not ip:
        return False
    return True

#   * It is also noticeable if someone tries to change the Ethernet
#     address of the gate or some dedicated servers on the network.
def ip_to_mac_not_valid(popo, bindings):
    ip = popo.spa
    mac = popo.sha
    if ip in bindings:
        return mac not in bindings[ip]
    return False

#   * A reply can not claim the broadcastin address as it's own ethernet address
def is_sender_broadcasting_address(popo):
    return popo.op == REPLY and popo.sha == BRODCAST