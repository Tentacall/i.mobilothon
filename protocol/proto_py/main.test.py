import scapy.all as scapy
from proto import CProto

if __name__ == "__main__":
    proto = CProto()
    proto.show()
    proto.send()
    # proto.recv()