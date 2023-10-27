import scapy.all as scapy

class PearsonHashing:
    def __init__(self) -> None:
        self.T = [i for i in range(2**8)]
        self.length = 8
        random.shuffle(self.T)
        self.hash = 0
        
    def hash(self, msg):
        try:
            data = ''.join(format(byte, '08b') for byte in msg.encode())
        except:
            data = "{0:08b}".format(int(msg))

        hash = self.T[int(data[:self.length], 2)]
        blocks = len(data)//self.length

        for i in range(1, blocks):
            hash = self.T[hash ^ int(data[i*self.length:(i+1)*self.length], 2)]
        return hash


class CProtoLayer(scapy.Packet):
    name = "CProto"
    fields_desc = [
        scapy.BitField("method", 0, 6),
        scapy.BitField("retain", 0, 1),
        scapy.BitField("auth", 0, 1),
        scapy.ByteField("dtype", 0),
        scapy.ByteField("topic", 0),
        scapy.ByteField("hash", 0),
    ]


class CProto:
    def __init__(self) -> None:
        
        self.methods = {
            0x00: "PUBALL"
            0x01: "PUB"
            0x02: "SUB",
            0x03: "UNSUB",
            0x04: "INSUB",
            0x05: "CONNECT",
            0x06: "DISCONNECT",
            0x07: "PING",
            0x08: "SUBALL",
            0x09: "UNSUBALL",
            0x0A: "INSUBALL",
            0x0B: "",
        }
        self.topics = {
            0x00: "TOPIC0",
            0x01: "TOPIC1",
            0x02: "TOPIC2",
            0x03: "TOPIC3",
            0x04: "TOPIC4",
            0x05: "TOPIC5",
            0x06: "TOPIC6",
            0x07: "TOPIC7",
            0x08: "TOPIC8",
        }
        
        self.hashing = PearsonHashing()
        self.packet = scapy.IP(
            dst="10.38.2.248",
            src="10.38.1.156",
            ttl=64,
        ) / scapy.TCP(
            sport=7997,
            dport=9779,
            options=[],
        ) / CProtoLayer(
            method=0x01,
            retain=0x1,
            auth=0x0,
            dtype=0x10,
            topic=0x11,
            hash=0x01,
        ) / "Hello World"
        
    def run(self):
        method = self.methods.get(self.packet[CProtoLayer].method)
        topic = self.topics.get(self.packet[CProtoLayer].topic)
        print(f"Method: {method}, Topic: {topic}")
        if method == "PUB" or method == "PUBALL":
            self.send()
        if method == "SUB" or method == "SUBALL":
            self.recv()
        if method == "CONNECT":
            print("Connected")
            msg = "connected"
            self.send(msg)
        if method == "DISCONNECT":
            print("Disconnected")
            msg = "disconnected"
            self.send(msg)
        if method == "UNSUB":
            print("Unsubscribed")
            msg = {"method": "UNSUB", "topic": topic}
            self.send(msg)
        if method == "INSUB":
            print("Subscribed")
            msg = {"method": "INSUB", "topic": topic}
            self.send(msg)

    def show(self):
        self.packet.show()
    
    def send(self, msg=None):
        if msg is not None:
            hash = self.hashing.hash(msg)
            self.packet[CProtoLayer].hash = hash
            self.packet = self.packet / msg
        scapy.send(self.packet)

    def callback(self, pkt):
        if scapy.IP in pkt and pkt[scapy.IP].src == "10.38.1.156" and pkt[scapy.TCP].sport == 7997:
            rcv_pkt = CProtoLayer(pkt[scapy.Raw].load)
            rcv_pkt.show()  
    
    def recv(self):
        scapy.sniff(filter="tcp", prn=self.callback)
