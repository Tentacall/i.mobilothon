import scapy.all as scapy
import random
from protocol.proto_py.utils import DtypeParser


class PearsonHashing:
    def __init__(self) -> None:
        self.T = [i for i in range(2**8)]
        self.length = 8
        random.shuffle(self.T)
        self.hash = 0

    def __call__(self, msg):
        if type(msg) == bytes:
            return self._hash_bytes(msg)
        elif type(msg) == str:
            return self._hash_bytes(msg.encode())
        else:
            return self._hash_bytes(str(msg).encode())

    def _hash_bytes(self, msg):
        # if the data type of bytes
        hash = self.T[msg[0]]
        for i in range(1, len(msg)):
            hash = self.T[hash ^ msg[i]]
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
    def __init__(
        self, src="10.35.0.93", dst="10.35.0.93", sport=9779, dport=9779, verbose=True
    ) -> None:
        self.topics = {}
        self.data = None
        self.hashing = PearsonHashing()
        self.packet = (
            scapy.IP(
                dst=dst,
                # src=src,
                ttl=64,
            )
            / scapy.TCP(
                sport=sport,
                dport=dport,
                options=[],
            )
            / CProtoLayer(
                method=0x01,
                retain=0x0,
                auth=0x0,
                dtype=0x00,
                topic=0x00,
                hash=0x00,
            )
        )
        self.dtype_parser = DtypeParser()
        self.verbose = verbose

    def show(self):
        self.packet.show()

    def set_dst(self, dst_ip, dst_port=9779):
        self.packet[scapy.IP].dst = dst_ip
        self.packet[scapy.TCP].dport = dst_port

    def send(self, method=0x00, retain=0x0, auth=0x0, dtype=0x00, topic=0x00, msg=None):
        packet = self.packet
        if msg is not None:
            msg = self.dtype_parser.encode(dtype, msg)
            _hash = self.hashing(msg)
            packet[CProtoLayer].hash = _hash
            packet = packet / msg

        # validate
        if (
            0 <= method <= 0x40
            and 0 <= retain <= 0x1
            and 0 <= auth <= 0x1
            and 0 <= dtype <= 0xFF
            and 0 <= topic <= 0xFF
        ):
            packet[CProtoLayer].method = method
            packet[CProtoLayer].retain = retain
            packet[CProtoLayer].auth = auth
            packet[CProtoLayer].dtype = dtype
            packet[CProtoLayer].topic = topic
        else:
            packet[CProtoLayer].method = 0x00

        scapy.send(packet, verbose=False)
        if self.verbose:
            packet.show()

    def callback(self, pkt):
        if (
            scapy.IP in pkt
            and pkt[scapy.TCP].sport == 7997
            and pkt[scapy.TCP].dport == 9779
        ):
            rcv_pkt = CProtoLayer(pkt[scapy.Raw].load)
            print("\nReceived packet: ")
            rcv_pkt.show()

    def recv(self):
        scapy.sniff(filter="tcp", prn=self.callback)


if __name__ == "__main__":
    # test
    hashing = PearsonHashing()
    print(hashing("Hello"))
    print(hashing(8368643))
    print(hashing(0x0074657465745))
