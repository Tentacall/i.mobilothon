import scapy.all as scapy


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
        self.packet = scapy.IP(
            dst="10.38.2.248",
            src="10.38.1.156",
            proto=0x06,
            flags=0x02,
            ttl=64,
        ) / scapy.TCP(
            sport=7997,
            dport=9779,
            seq=12345,
            ack=12345,
            flags=0x02,
            window=0x10,
            options=[],
        ) / CProtoLayer(
            method=0x01,
            retain=0x1,
            auth=0x0,
            dtype=0x10,
            topic=0x11,
            hash=0x01,
        ) / "Hello World"

    def show(self):
        self.packet.show()
    
    def send(self):
        scapy.send(self.packet)

    def callback(self, pkt):
        if pkt.haslayer(CProtoLayer):
            pkt.show()
    
    def recv(self):
        scapy.sniff(filter="tcp", prn=self.callback)
