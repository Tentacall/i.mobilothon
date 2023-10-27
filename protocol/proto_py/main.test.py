import scapy.all as scapy
from proto import CProto

if __name__ == "__main__":
    a = scapy.IP()/ scapy.TCP() / CProto()/ "Hello World"
    a.show()