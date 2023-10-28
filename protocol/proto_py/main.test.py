import scapy.all as scapy
from proto import CProto

if __name__ == "__main__":
    proto = CProto()
    # proto.show()
    print(">>> [method] [retain] [auth] [dtype] [topic] [...msg]")
    while True:
        token = input(">>> ").split()
        # example: 
        if len(token) == 0:
            break
        
        method = int(token[0])
        retain = bool(int(token[1]))
        auth = bool(int(token[2]))
        dtype = int(token[3])
        topic = int(token[4])
        msg = " ".join(token[5:]) if len(token) > 5  else None

        proto.send(method, retain, auth, dtype, topic, msg)
        
    proto.send()
    # proto.recv()