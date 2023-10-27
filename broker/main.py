import scapy.all as scapy
from loggings import logger
from proto import CProtoLayer


class Broker:
    def __init__(self, port = 9779):
        self.port = port
        self.proto = CProtoLayer()

    def callback(self, pkt):
        if pkt[scapy.TCP].dport == self.port:
            rcv_pkt = CProtoLayer(pkt[scapy.Raw].load)
            rcv_pkt.show()
    
    def start(self):
        scapy.sniff(filter="tcp", prn=self.callback)

if __name__ == '__main__':
    bro = Broker()
    bro.start()
