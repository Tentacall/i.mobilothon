import scapy.all as scapy
import argparse
from loggings import logger
from proto import CProtoLayer, PearsonHashing
from utils import DtypeParser, MethodHandler

class Broker:
    def __init__(self, port = 9779):
        self.port = port
        self.proto = CProtoLayer()
        self.topics = [None]*256
        self.method_handlers = MethodHandler()
        self.dtype_parser = [None]*256
        self.hashing = PearsonHashing()
        self.method_handlers._set_permutation(self.hashing.T)

    def callback(self, pkt):
        if pkt[scapy.TCP].dport == self.port or pkt[scapy.TCP].sport == self.port:
            # TODO: handle edge case
            rcv_pkt = CProtoLayer(pkt[scapy.Raw].load)
            self.cprotoHandler(rcv_pkt)
    
    def cprotoHandler(self, pkt):
        # check hash for corrupted message
        pkt.show()
        if pkt.hash != self.hashing.hash(pkt.load):
            logger.error("Corrupted message")
            return
        
        # save packet to `{topic}{time}.pcap` file
        if self.topics[pkt.topic] is None:
            self.topics[pkt.topic] = scapy.PcapWriter(f"{pkt.topic}{pkt.time}.pcap", append=True)
        
        self.method_handlers(pkt.method, pkt.auth, pkt.dtype, pkt.topic, pkt.load)
    
    def start(self):
        logger.info(f"Listening on port {self.port}")
        scapy.sniff(filter="tcp", prn=self.callback)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Broker')  
    parser.add_argument('--port', type=int, help='Port to listen', default=9779)
    args = parser.parse_args()

    bro = Broker(args.port)
    bro.start()
