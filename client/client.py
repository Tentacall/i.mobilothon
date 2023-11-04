import argparse
import threading
from scapy.all import *

from broker.loggings import logger
from protocol.proto_py.utils import DtypeParser
from protocol.proto_py.standards import Method, DType
from protocol.proto_py.proto import CProto, PearsonHashing, CProtoLayer
from broker.loggings import logger


class Client:
    def __init__(self, src, dst, sport, dport, client_id=0) -> None:
        self.sport = sport
        self.dst_ip = dst
        self.dst_port = dport
        self.client_id = client_id
        self.proto = CProto(src, dst, sport, dport, verbose=False)
        self.proto.hashing.T = [i for i in range(2**8)]
        self.method_handlers = MethodHandler(self.proto)

    def cli(self):
        # connect to broker
        self.proto.send(Method.Connect.value, 0x0, 0x0, DType.Null.value, 0x00)

        # self.proto.send(Method.Ping.value, 0, 0, DType.Json.value, 0, {"hello": 1})
        # topic publishing >>> 2 0 0 12 0 topic1
        # topic subscribing >>> 3 0 0 0 1
        # topic unsubscribing >>> 4 0 0 0 1
        # topic get_all_topics >>> 9 0 0 0 0

        # while (
        #     topic in self.method_handlers.topics
        #     and self.method_handlers.topics[topic] is None
        # ):
        #     # waiting for approval or rejection
        #     time.sleep(0.5)

        print(f"[ Client {self.client_id} ]: Starting at port {self.sport}")
        print(">>> [method] [retain] [auth] [dtype] [topic] [...msg]")

        while True:
            try:
                token = input(">>> ").split()
            except:
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
            msg = " ".join(token[5:]) if len(token) > 5 else None
            self.proto.send(method, retain, auth, dtype, topic, msg)

    def callback(self, pkt):
        # if pkt[IP].src != self.dst_ip or pkt[TCP].sport != self.dst_port:
        #     print("From someone else")
        #     return # from someone else

        # if pkt[TCP].dport == self.sport:
        #     print("Not for me")
        #     return # not for me

        if pkt[TCP].dport == self.sport and pkt[TCP].sport == self.dst_port:
            try:
                d_ip, d_port = pkt[IP].src, pkt[TCP].sport
                rcv_pkt = CProtoLayer(pkt[Raw].load)
                x = self.cprotoHandler(rcv_pkt, d_ip, d_port)
            except Exception as e:
                # pkt.show()
                logger.error(e)

    def cprotoHandler(self, pkt, dst_ip, dst_port):
        data = pkt.load if hasattr(pkt, "load") else None
        # if data:
        #     if pkt.hash != self.hashing(data):
        #         logger.error(f"Corrupted message ({pkt.hash} != {self.hashing(data)})")
        #         return
        # elif pkt.hash != 0:
        #     logger.error("Corrupted message")
        #     return

        # clients not necessarily need to save packet
        self.method_handlers(
            pkt.method, pkt.auth, pkt.dtype, pkt.topic, data, dst_ip, dst_port
        )

    def start_listener(self):
        def listener_thread_func():
            print(f"Listening on port {self.sport}")
            sniff(filter="tcp", iface="docker0", prn=self.callback)

        self.listener_thread = threading.Thread(target=listener_thread_func)
        self.listener_thread.daemon = True
        self.listener_thread.start()


class MethodHandler:
    def __init__(self, sender: CProto):
        self.method_handlers = [None] * 256
        self.dtype_parser = DtypeParser()
        self.hashing = PearsonHashing()
        self.subscribed_topics = {}
        self.topics = {}
        self.sender = sender
        self.__init__basic_method()

    def __call__(self, method, auth, dtype, topic, data, dst_ip, dst_port):
        data = self.dtype_parser.decode(dtype, data)
        self.sender.set_dst(dst_ip, dst_port)
        # print(f"{dst_ip}:{dst_port}")
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
        self.method_handlers[Method.Pong.value] = lambda *args: logger.info(
            f"Pong from {args[4]}:{args[5]}"
        )

        # 0x02 | client shouldn't handle this
        self.method_handlers[Method.Publish.value] = lambda *args: logger.info(
            f"Publish request from {args[4]}:{args[5]} | topic: {args[3]}"
        )

        # 0x03 | client shouldn't handle this
        self.method_handlers[Method.Subscribe.value] = lambda *args: logger.info(
            f"Subscribe request from {args[4]}:{args[5]} | topic: {args[3]}"
        )

        # 0x04 | client shouldn't handle this
        self.method_handlers[Method.Unsubscribe.value] = lambda *args: logger.info(
            f"Unsubscribe from {args[4]}:{args[5]} | topic: {args[3]}"
        )

        # 0x05
        def approved_published_topic(*args):
            self.topics[args[0]] = args[3]
            logger.info(f"Topic {args[0]} : {args[3]} approved")

        self.method_handlers[
            Method.AprrovePublishedTopic.value
        ] = approved_published_topic

        # 0x06
        def reject_published_topic(*args):
            if args[0] in self.topics and self.topics[args[0]] is None:
                self.topics.pop(args[0])
            logger.info(f"Topic {args[0]} Rejected")

        self.method_handlers[Method.RejectPublishedTopic.value] = reject_published_topic

        # 0x07
        def approve_subscribed_topic(*args):
            logger.info(f"Subscribed to topic id: {args[3]}")

        self.method_handlers[
            Method.AprroveSubscribedTopic.value
        ] = approve_subscribed_topic

        # 0x08
        def reject_subscribed_topic(*args):
            logger.error(f"Rejected to subscribe to topic id: {args[3]}")

        self.method_handlers[
            Method.RejectSubscribedTopic.value
        ] = reject_subscribed_topic

        # 0x09 : Client shouldn't handle this
        self.method_handlers[Method.GetAllTopics.value] = lambda *args: logger.info(
            f"Get all topics request from {args[4]}:{args[5]}"
        )

        # 0x0A
        def all_topics(*args):
            logger.info(f"Topics :")
            for id, topic in args[0].items():
                logger.info(f"\t{id} - {topic}")

        self.method_handlers[Method.AllTopics.value] = all_topics

        self.method_handlers[Method.Connect.value] = lambda *args: logger.warning("Clinet shouldn't handle this")

        # 0x0C
        def disconnect(*args):
            pass

        self.method_handlers[Method.Disconnect.value] = disconnect

        # 0x0D
        def connect_acknowledgement(*args):
            logger.info(f"Connected to {args[4]}:{args[5]}")
            self.sender.hashing.T = args[0]

        self.method_handlers[
            Method.ConnectAcknowledgement.value
        ] = connect_acknowledgement

        # 0x0E
        def disconnect_acknowledgement(*args):
            logger.info(f"Disconnected from {args[4]}:{args[5]}")
            self.sender.hashing.T = [i for i in range(2**8)]

        self.method_handlers[
            Method.DisconnectAcknowledgement.value
        ] = disconnect_acknowledgement


if __name__ == "__main__":
    client = Client("172.17.0.1", "172.17.0.2", 9779, 9779)
    client.start_listener()
    client.cli()

    # connect message : 11 0 0 0 0
