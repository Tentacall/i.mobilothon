from scapy.all import *
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
        # TODO : should listen to port self.port only [ dst_port == self.port ]
        if pkt[TCP].dport == self.port or pkt[TCP].sport == self.port:
            # TODO: handle edge case
            # pkt.show()
            try:
                rcv_pkt = CProtoLayer(pkt[Raw].load)
                x = self.cprotoHandler(rcv_pkt)
            except Exception as e:
                logger.error(e)
        
    
    def cprotoHandler(self, pkt):
        # check hash for corrupted message
        # print(self.hashing(pkt.load))
        

        
        # if pkt.hash != self.hashing(pkt.load):
        #     logger.error("Corrupted message")
        #     return
        
        # save packet to `{topic}{time}.pcap` file
        # if self.topics[pkt.topic] is None:
        #     self.topics[pkt.topic] = scapy.PcapWriter(f"{pkt.topic}{pkt.time}.pcap", append=True)
        
        # print("Handling packet")
        
        # check if pkt have load

        # TODO: optimize this
        try:
            data = pkt.load
        except:
            data = None
        
        self.method_handlers(pkt.method, pkt.auth, pkt.dtype, pkt.topic, data)
    
    def start(self):
        logger.info(f"Listening on port {self.port}")
        sniff(filter="tcp", prn=self.callback)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Broker')  
    parser.add_argument('--port', type=int, help='Port to listen', default=9779)
    args = parser.parse_args()

    bro = Broker(args.port)
    bro.start()
