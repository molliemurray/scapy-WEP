import sys
import scapy
import pyDot11
import binascii
from scapy.layers.dot11 import Dot11, Dot11WEP, RadioTap, Dot11Beacon, Dot11Elt
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.layers.inet import IP, ICMP
from scapy.all import hexdump
from scapy.utils import rdpcap
from pyDot11.__init__ import wepEncrypt
from pyDot11.lib.utils import Pcap
from pyDot11.lib.wep import Wep

#Sending from a pcap
wepPkts = rdpcap('PCAPs/ICMPs/wep_pings.pcap')
wepPkts.summary()
input = wepPkts.__class__(str(wepPkts)[0:-4])
#print(input.summary())
sendp(wepPkts)

# Sending a simple packet
sender='08:00:27:c6:e4:20'
dest='08:00:27:1b:8b:a3'
packet=Dot11(addr1=dest,addr2=sender,addr3=sender)/LLC()/SNAP()/IP(src="192.168.3.7",dst="192.168.3.5")/ICMP()/"Hello!"
print(packet.summary())
#print(packet.show())
sendp(packet)
encPkt = wepEncrypt(packet,'0123456789')
print(encPkt.summary())
#print(encPkt.show())
sendp(encPkt)


#Sending a Dot11 Beacon packet
SSID = 'Test SSID'
iface = 'eth0'
dot11 = Dot11(type=0, subtype=8, 
        addr1='ff:ff:ff:ff:ff:ff',
        addr2=sender,
        addr3=sender)
beacon = Dot11Beacon()
essid = Dot11Elt(ID='SSID',info=SSID, len=len(SSID))
frame = RadioTap()/dot11/beacon/essid
print(frame.summary())
sendp(frame, iface=iface)

