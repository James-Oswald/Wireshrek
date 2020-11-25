
from scapy.all import sniff #, IFACES
from scapy.layers.inet import IP

def onPacket(pkt):
    pkt.summary()

#IFACES.show()
#sniff(iface="Intel(R) Wireless-AC 9462", prn=onPacket)
pkts = sniff(prn=lambda p: p.summary(), count=1)
print(len(pkts))