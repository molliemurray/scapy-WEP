import scapy.all as scapy
from scapy.layers.inet import TCP, ICMP
from scapy.layers.dot11 import Dot11WEP, Dot11Encrypted, Dot11
from scapy.utils import rdpcap
from pyDot11 import *



'''dot11 = Dot11WEP()
data = b'Welcome to New York City.'
destination = '10.10.10.2'
packet1 = scapy.IP(dst=destination)
print(dot11.show())
scapy.wrpcap("transmit.pcap", packet1)
packet = rdpcap("transmit.pcap")
print("Read Packet: " + str(packet[0])[0:-4])'''


'''packet = Dot11(addr1="00:a0:57:12:34:56", addr2="00:a0:57:98:76:54", addr3="00:a0:57:98:76:54", type=2, subtype=4)
enc = wepEncrypt(packet.__class__(str(packet)[0:-4]), '1234567')
print(enc.show())'''


'''
p= scapy.IP(dst="www.slashdot.org")/ICMP()/"XXXXXXXXXXX"

packet = scapy.ARP() / Dot11(addr1="00:a0:57:12:34:56", addr2="00:a0:57:98:76:54", addr3="00:a0:57:98:76:54", type=2, subtype=4) / TCP() / str("1")
print(packet.show())
dot11enc = Dot11Encrypted(packet)
print(packet.show())'''

'''from scapy.all import *
from scapy.layers.dot11 import *
from scapy.utils import rdpcap


packets = rdpcap("fil.pcap")
print(packets[53].show())
class Dot11EltRates(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Rates Information Element"
    # Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1),
                                     rate))

packet /= Dot11EltRates()
#sendp(packet, iface="wlp0s29u1u7")
print(packet.show())'''



'''packet = Dot11(addr1="00:a0:57:98:76:54", addr2="00:a0:57:12:34:56", ID=64519, type=1, subtype=11) 0
packet = Dot11(addr1="00:a0:57:98:76:54", ID=0, type=1, subtype=13) 46
53'''



# This line works.
packet = Dot11(addr1="00:a0:57:98:76:54", addr2="00:a0:57:12:34:56", addr3="00:a0:57:98:76:54") / Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / Dot11Elt(ID=0, info="MY_BSSID")
# Try opening it up in wireshark
