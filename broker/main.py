from scapy.all import *
import argparse
from loggings import logger
from protocol.proto_py.proto import CProtoLayer, PearsonHashing
from utils import MethodHandler

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
        # TODO : should listen to port self.port only [ dst_port == self.port ]
        # if pkt[TCP].dport == self.port or pkt[TCP].sport == self.port:
        if pkt[TCP].dport == self.port :
            # TODO: handle edge case
            # pkt.show()
            try:
                d_ip, d_port = pkt[IP].src, pkt[TCP].sport
                rcv_pkt = CProtoLayer(pkt[Raw].load,)
                x = self.cprotoHandler(rcv_pkt,  d_ip, d_port)
            except Exception as e:
                # pkt.show()
                logger.error(e)
        
    
    def cprotoHandler(self, pkt, dst_ip, dst_port):
        # pkt.show()
        data = pkt.load if hasattr(pkt, 'load') else None
        ### check hash for corrupted message : TODO
        if data:
            if pkt.hash != self.hashing(data):
                logger.error(f"Corrupted message ({pkt.hash} != {self.hashing(data)})")
                return
        # elif pkt.hash != 0:
        #     logger.error("Corrupted message")
        #     return
        
        # save packet to `{topic}{time}.pcap` file : TODO
        # if self.topics[pkt.topic] is None:
        #     self.topics[pkt.topic] = scapy.PcapWriter(f"{pkt.topic}{pkt.time}.pcap", append=True)        


        # TODO: optimize this  
        self.method_handlers(pkt.method, pkt.auth, pkt.dtype, pkt.topic, data, dst_ip, dst_port)
    
    def start(self):
        logger.info(f"Listening on port {self.port}")
        sniff(filter="tcp", prn=self.callback)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Broker')  
    parser.add_argument('--port', type=int, help='Port to listen', default=9779)
    args = parser.parse_args()

    bro = Broker(args.port)
    bro.start()
