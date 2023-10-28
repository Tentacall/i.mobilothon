import scapy.all as scapy
from proto import CProto

if __name__ == "__main__":
    proto = CProto()
    # proto.show()
    while True:
        token = input(">>> ").split()
        if len(token) == 0:
            break
        
        method = int(token[0])
        retain = bool(int(token[1]))
        auth = bool(int(token[2]))
        dtype = int(token[3])
        topic = int(token[4])
        msg = " ".join(token[5:])

        proto.send(method, retain, auth, dtype, topic, msg)
        
    proto.send()
    # proto.recv()