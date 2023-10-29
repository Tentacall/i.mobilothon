import scapy.all as scapy
import random

class PearsonHashing:
    def __init__(self) -> None:
        self.T = [i for i in range(2**8)]
        self.length = 8
        random.shuffle(self.T)
        self.hash = 0
        
    def __call__(self, msg):
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
    def __init__(self, src = "10.38.1.156", dst = "10.35.0.93") -> None:
        
        self.topics = {}
        self.data = None
        self.hashing = PearsonHashing()
        self.packet = scapy.IP(
            dst=dst,
            src=src,
            ttl=64,
        ) / scapy.TCP(
            sport=7997,
            dport=9779,
            options=[],
        ) / CProtoLayer(
            method=0x01,
            retain=0x0,
            auth=0x0,
            dtype=0x00,
            topic=0x00,
            hash=0x00,
        )
        
    def show(self):
        self.packet.show()
    
    def send(self, method = 0x00, retain = 0x0, auth = 0x0, dtype = 0x00, topic = 0x00, msg = None):
        packet = self.packet
        if msg is not None:
            _hash = self.hashing(msg)
            packet[CProtoLayer].hash = _hash
            packet = packet / msg

        # validate
        if  0 <= method <= 0x40 and \
            0 <= retain <= 0x1 and \
            0 <= auth <= 0x1 and \
            0 <= dtype <= 0xFF and \
            0 <= topic <= 0xFF:
            packet[CProtoLayer].method = method
            packet[CProtoLayer].retain = retain
            packet[CProtoLayer].auth = auth
            packet[CProtoLayer].dtype = dtype
            packet[CProtoLayer].topic = topic
        else:
            packet[CProtoLayer].method = 0x00

        # self.packet[CProtoLayer].show()
        scapy.send(packet)

        # packet.show()

    def callback(self, pkt):
        if scapy.IP in pkt and pkt[scapy.TCP].sport == 7997 and pkt[scapy.TCP].dport == 9779:
            rcv_pkt = CProtoLayer(pkt[scapy.Raw].load)
            rcv_pkt.show()  
    
    def recv(self):
        scapy.sniff(filter="tcp", prn=self.callback)
