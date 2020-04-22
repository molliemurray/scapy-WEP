import sys
import scapy
import pyDot11
import binascii
from scapy.layers.dot11 import Dot11, Dot11WEP, RadioTap
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.layers.inet import IP, ICMP
from pyDot11.__init__ import wepEncrypt
from pyDot11.lib.utils import Pcap
from pyDot11.lib.wep import Wep

#packet=IP(src="192.168.3.5",dst="192.168.3.4")/ICMP()
packet=Dot11()/LLC()/SNAP()/IP(src="192.168.3.7",dst="192.168.3.5")/ICMP()
print(packet.summary())
print(packet.show())
encPkt = wepEncrypt(packet,'0123456789')
print(encPkt.summary())
print(encPkt.show())
sendp(encPkt)
