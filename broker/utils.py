from broker.loggings import logger
from protocol.proto_py.proto import CProto, PearsonHashing
from protocol.proto_py.utils import DtypeParser
from typing import Callable, Optional, List
from queue import PriorityQueue
from protocol.proto_py.standards import DType, Method


class Device:
    def __init__(self, ip, mac):
        self.id = None
        self.ip = ip
        self.mac = mac


class AutherizedDevices:
    def __init__(self):
        # TODO : Use some more efficient data structure for this
        # self._load()
        self.autherize_macs = []
        self.autherized_ips = []

    def __add_ip(self, ip) -> None:
        self.autherized_ips.append(ip)

    def __add_mac(self, mac) -> None:
        self.autherize_macs.append(mac)

    def __remove_ip(self, ip) -> None:
        self.autherized_ips.remove(ip)

    def __remove_mac(self, mac) -> None:
        self.autherize_macs.remove(mac)

    def __contains__(self, ip) -> bool:
        return ip in self.autherized_ips or ip in self.autherize_macs

    def _load(self):
        raise NotImplementedError


class MethodHandler:
    def __init__(self):
        self.method_handlers: List[Optional[Callable]] = [None] * 64
        self.sender = CProto(src="10.35.0.93", dst="10.38.1.156")
        self.dtype_parser = DtypeParser()
        self.autherized_devices = AutherizedDevices()

        self.avilable_topics = PriorityQueue()
        for i in range(256):
            self.avilable_topics.put(i)
        self.topics = {}

        self.__init__basic_method()
        self.__init__root_method()
        self.__init__data_method()
        self.__init__control_method()

    def _set_permutation(self, t):
        self.sender.hashing.T = t

    def __call__(self, method, auth, dtype, topic, data, dst_ip, dst_port):
        data = self.dtype_parser.decode(dtype, data)
        self.sender.set_dst(dst_ip, dst_port)
        return self.method_handlers[method](data, auth, dtype, topic, dst_ip, dst_port)

    def __init__basic_method(self):
        # 0x00
        def ping(*args):
            logger.info("Ping")
            # send a pong message
            self.sender.send(Method.Pong.value, 0x0, 0x0, DType.Null, 0x00)

        self.method_handlers[Method.Ping.value] = ping

        # 0x01
        self.method_handlers[Method.Pong.value] = lambda *args: logger.info("Pong")

        # 0x0B -> Connect Method  send Acknowledgement or Disconnect
        def connect(*args):
            # send permutation table
            logger.info(f"Connect request from : {args[5]}:{args[6]}")
            self.autherized_devices.__add_ip(args[5])
            p_table = self.sender.hashing.T
            self._set_permutation([i for i in range(256)])
            self.sender.send(
                0x0D, 0x0, 0x0, 0x12, 0x00, self.dtype_parser.encode(0x12, p_table)
            )
            self._set_permutation(p_table)

        self.method_handlers[0x0B] = connect

        self.method_handlers[0x0C] = lambda *args: logger.info(
            f"[{args[5]}:{args[6]}] Disconnect"
        )
        self.method_handlers[0x0D] = lambda *args: logger.info(
            f"[{args[5]}:{args[6]}] Connect Acknowledgement"
        )

        # 0x02 -> Publish topic
        def topic_publish(*args):
            logger.info(f"[{args[5]}:{args[6]}] Publish topic : {args[3]}")
            if self.avilable_topics.empty():
                logger.error(f"[{args[5]}:{args[6]}] No avilable topic")
                self.sender.send(0x07, 0x0, 0x0, 0x00, 0x00)
                return

            elif args[3] in self.topics:
                logger.error(f"[{args[5]}:{args[6]}] Topic already published")
                self.sender.send(
                    Method.RejectPublishedTopic,
                    0x0,
                    0x0,
                    DType.String.value,
                    self.dtype_parser.encode(DType.String.value, "Topic already published"),
                )
                return
            topic = self.avilable_topics.get()
            self.topics[topic] = {
                "name": args[0],
                "source": [args[5]],
                "subscribers": [],
            }
            logger.info(f"[{args[5]}:{args[6]}] Topic {args[0]} published on {topic}")
            self.sender.send(
                Method.AprrovePublishedTopic.value,
                0x0,
                0x0,
                DType.Byte,
                0x00,
                self.dtype_parser.encode(DType.Byte.value, topic),
            )
        self.method_handlers[Method.Publish.value] = topic_publish

    def __init__root_method(self):
        pass

    def __init__data_method(self):
        pass

    def __init__control_method(self):
        pass
