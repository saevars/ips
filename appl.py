import nfqueue, socket
from scapy.all import *
import os

#add iptables rule
os.system('iptables -A INPUT -j NFQUEUE --queue-num 0')
#since you are sending packets from your machine you can get them in the OUPUT hook or even in the POSTROUTING hook.

#Set the callback for received packets. The callback should expect the payload:
def cbs(stuff, payload):
    data = payload.get_data()
    p = IP(data)
    send(p)
    # print(p.show())


q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET)
q.set_callback(cbs)
q.create_queue(0) #Same queue number of the rule

try:
    q.try_run()
except KeyboardInterrupt, e:
    os.system('iptables -t -F') #remove iptables rule
    print "interruption"
    q.unbind(socket.AF_INET)
    q.close()