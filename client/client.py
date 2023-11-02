import argparse
import threading
from scapy.all import *

from broker.loggings import logger
from protocol.proto_py.utils import DtypeParser
from protocol.proto_py.standards import Method, DType
from protocol.proto_py.proto import CProto, PearsonHashing
from broker.loggings import logger


class Client:
    def __init__(self, src, dst, sport, dport, client_id = 0) -> None:
        self.sport = sport
        self.dst_ip = dst
        self.dst_port = dport
        self.client_id = client_id
        self.proto = CProto(src, dst, sport, dport)
        self.proto.hashing.T = [i for i in range(2**8)]
        self.method_handlers = MethodHandler(self.proto)

    def cli(self):
        print(f"[ Client {self.client_id} ]: Starting at port {self.sport}")
        print(">>> [method] [retain] [auth] [dtype] [topic] [...msg]")

        while True:
            try:
                token = input(">>> ").split()
            except :
                logger.error("Exiting client")
                break
            # example: 
            if len(token) == 0:
                break
            
            method = int(token[0])
            retain = bool(int(token[1]))
            auth = bool(int(token[2]))
            dtype = int(token[3])
            topic = int(token[4])
            msg = " ".join(token[5:]) if len(token) > 5  else None

            self.proto.send(method, retain, auth, dtype, topic, msg)

    def callback(self, pkt):
        if pkt[IP].src != self.dst_ip or pkt[TCP].sport != self.dst_port:
            return # from someone else
        
        if pkt[TCP].dport == self.sport:
            return # not for me
        
        try:
            d_ip, d_port = pkt[IP].src, pkt[TCP].sport
            rcv_pkt = CProto(pkt[Raw].load)
            x = self.cprotoHandler(rcv_pkt,  d_ip, d_port)
        except Exception as e:
            logger.error(e)

    def cprotoHandler(self, pkt, dst_ip, dst_port):
        data = pkt.load if hasattr(pkt, 'load') else None
        if data:
            if pkt.hash != self.hashing(data):
                logger.error(f"Corrupted message ({pkt.hash} != {self.hashing(data)})")
                return
        elif pkt.hash != 0:
            logger.error("Corrupted message")
            return
        
        # clients not necessarily need to save packet 

        self.method_handlers(pkt.method, pkt.auth, pkt.dtype, pkt.topic, data, dst_ip, dst_port)
        

    def start_listener(self):
        def listener_thread_func():
            print(f"Listening on port {self.sport}")
            sniff(filter="tcp", prn=self.callback)

        self.listener_thread = threading.Thread(target=listener_thread_func)
        self.listener_thread.daemon = True
        self.listener_thread.start()


class MethodHandler:
    def __init__(self, sender: CProto):
        self.method_handlers = [None] * 256
        self.dtype_parser = DtypeParser()
        self.hashing = PearsonHashing()
        self.subscribed_topics = {}

        self.sender = sender
        self.__init__basic_method()

    def __call__(self, method, auth, dtype, topic, data, dst_ip, dst_port):
        data = self.dtype_parser.decode(dtype, data)
        self.sender.set_dst(dst_ip, dst_port)
        return self.method_handlers[method](data, auth, dtype, topic, dst_ip, dst_port)

    def _set_permutation(self, T):
        self.hashing.T = T

    def __init__basic_method(self):
        # 0x00
        def ping(*args):
            logger.info(f"Ping from {args[4]}:{args[5]}")
            # send a pong message
            self.sender.send(Method.Pong.value, 0x0, 0x0, DType.Null.value, 0x00)

        self.method_handlers[Method.Ping.value] = ping

        # 0x01
        self.method_handlers[Method.Pong.value] = lambda *args: logger.info(f"Pong from {args[4]}:{args[5]}")
        
        # 0x02
        self.method_handlers[Method.Publish.value] = lambda *args: logger.info(f"Publish from {args[4]}:{args[5]} | topic: {args[3]}")   
        
        # 0x03
        self.method_handlers[Method.Subscribe.value] = lambda *args: logger.info(f"Subscribe from {args[4]}:{args[5]} | topic: {args[3]}") 
        
        # 0x04
        def unsubscribe(*args):
            pass
        
        self.method_handlers[Method.Unsubscribe.value] = lambda *args: logger.info(f"Unsubscribe from {args[4]}:{args[5]} | topic: {args[3]}") 
        
        # 0x05
        def approve_published_topic(*args):
            pass
        
        self.method_handlers[Method.ApprovePublishedTopic.value] = approve_published_topic
        
        # 0x06
        def reject_published_topic(*args):
            pass
        
        self.method_handlers[Method.RejectPublishedTopic.value] = reject_published_topic
        
        # 0x07
        def approve_subscribed_topic(*args):
            self.subscribed_topics[args[3]] = args[0]
        
        self.method_handlers[Method.ApproveSubscribedTopic.value] = approve_subscribed_topic
        
        # 0x08
        def reject_subscribed_topic(*args):
            pass
        
        self.method_handlers[Method.RejectSubscribedTopic.value] = reject_subscribed_topic
        
        # 0x09
        def get_all_topics(*args):
            pass
        
        self.method_handlers[Method.GetAllTopics.value] = get_all_topics
        
        # 0x0A
        def subscribe_all_topics(*args):
            pass
        
        self.method_handlers[Method.SubscribeAllTopics.value] = subscribe_all_topics
        
        # 0x0B
        def connect(*args):
            pass
        
        self.method_handlers[Method.Connect.value] = connect
        
        # 0x0C
        def disconnect(*args):
            pass
        
        self.method_handlers[Method.Disconnect.value] = disconnect
        
        # 0x0D
        def connect_acknowledgement(*args):
            pass
        
        self.method_handlers[Method.ConnectAcknowledgement.value] = connect_acknowledgement
        
        # 0x0E
        def disconnect_acknowledgement(*args):
            pass
        
        self.method_handlers[Method.DisconnectAcknowledgement.value] = disconnect_acknowledgement       
            


if __name__ == "__main__":
    client = Client("10.35.0.93", "10.38.2.88", 9779, 9779)
    client.start_listener()
    client.cli()
