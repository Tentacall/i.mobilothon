from broker.loggings import logger
from protocol.proto_py.proto import CProto, PearsonHashing
from protocol.proto_py.utils import DtypeParser
from typing import Callable, Optional, List
from queue import PriorityQueue
from protocol.proto_py.standards import DType, Method
from enum import Enum


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

    def _add_ip(self, ip) -> None:
        self.autherized_ips.append(ip)

    def _add_mac(self, mac) -> None:
        self.autherize_macs.append(mac)

    def _remove_ip(self, ip) -> None:
        self.autherized_ips.remove(ip)

    def _remove_mac(self, mac) -> None:
        self.autherize_macs.remove(mac)

    def __contains__(self, ip) -> bool:
        return ip in self.autherized_ips or ip in self.autherize_macs

    def _load(self):
        raise NotImplementedError


class MethodHandler:
    def __init__(self):
        self.method_handlers: List[Optional[Callable]] = [None] * 64
        self.sender = CProto(src="10.38.2.88", verbose=False)
        self.dtype_parser = DtypeParser()
        self.autherized_devices = AutherizedDevices()

        self.avilable_topics = PriorityQueue()
        for i in range(1, 256):
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
            logger.info(f"Ping from {args[4]}:{args[5]}")
            # send a pong message
            self.sender.send(Method.Pong.value, 0x0, 0x0, DType.Null.value, 0x00)

        self.method_handlers[Method.Ping.value] = ping

        # 0x01
        self.method_handlers[Method.Pong.value] = lambda *args: logger.info(
            f"Pong from {args[4]}:{args[5]}"
        )

        # 0x0B -> Connect Method  send Acknowledgement or Disconnect
        def connect(*args):
            # send permutation table
            logger.info(f"Connect request from : {args[4]}:{args[5]}")
            self.autherized_devices._add_ip(args[4])
            p_table = self.sender.hashing.T
            self._set_permutation([i for i in range(256)])
            self.sender.send(
                0x0D, 0x0, 0x0, 0x12, 0x00, self.dtype_parser.encode(0x12, p_table)
            )
            self._set_permutation(p_table)

        self.method_handlers[0x0B] = connect

        self.method_handlers[0x0C] = lambda *args: logger.info(
            f"[{args[4]}:{args[5]}] Disconnect"
        )
        self.method_handlers[0x0D] = lambda *args: logger.info(
            f"[{args[4]}:{args[5]}] Connect Acknowledgement"
        )

        # 0x02 -> Publish topic
        def topic_publish(*args):
            logger.info(f"[{args[4]}:{args[5]}] Publish topic : {args[3]}")
            if self.avilable_topics.empty():
                logger.error(f"[{args[4]}:{args[5]}] No avilable topic")
                self.sender.send(
                    Method.RejectPublishedTopic.value, 0x0, 0x0, 0x00, 0x00
                )
                return

            for key, value in self.topics.items():
                if value["name"] == args[0]:
                    logger.error(f"[{args[4]}:{args[5]}] Topic already published")
                    self.sender.send(
                        Method.RejectPublishedTopic.value,
                        0x0,
                        0x0,
                        args[2],
                        0x00,
                        args[0],
                    )
                    return
            topic = self.avilable_topics.get()
            self.topics[topic] = {
                "name": args[0],
                "source": [args[5]],
                "subscribers": [],
            }
            logger.info(f"[{args[4]}:{args[5]}] Topic {args[0]} published on {topic}")
            self.sender.send(
                Method.AprrovePublishedTopic.value,
                0x0,
                0x0,
                args[2],
                self.dtype_parser.encode(DType.Byte.value, topic),
                args[0],
            )

        self.method_handlers[Method.Publish.value] = topic_publish

        self.method_handlers[
            Method.AprrovePublishedTopic.value
        ] = lambda *args: logger.info(f"[{args[4]}:{args[5]}] Topic {args[0]} Approved")
        self.method_handlers[
            Method.RejectPublishedTopic.value
        ] = lambda *args: logger.info(f"[{args[4]}:{args[5]}] Topic {args[0]} Rejected")

        # 0x03 -> Subscribe topic
        def subsribe(*args):
            logger.info(
                f"[{args[4]}:{args[5]}] Subscription request on topic : {args[3]}"
            )
            # check if the topic exists
            if args[3] not in self.topics:
                logger.error(f"[{args[4]}:{args[5]}] Topic {args[3]} does not exists")
                self.sender.send(
                    Method.RejectSubscribedTopic.value,
                    0x0,
                    0x0,
                    DType.Byte.value,
                    self.dtype_parser.encode(
                        DType.Byte.value, Rejection.NO_TOPIC_FOUND.value
                    ),
                )
                return

            # check if the device is autherized : TODO

            self.topics[args[3]]["subscribers"].append(f"{args[4]}:{args[5]}")
            logger.info(f"[{args[4]}:{args[5]}] Subscribed to topic {args[3]}")
            self.sender.send(
                Method.AprroveSubscribedTopic.value,
                0x0,
                0x0,
                DType.Null.value,
                args[3],
            )

        self.method_handlers[Method.Subscribe.value] = subsribe

        self.method_handlers[
            Method.AprroveSubscribedTopic.value
        ] = lambda *args: logger.info(
            f"[{args[4]}:{args[5]}] Subscribed to topic {args[3]}"
        )
        self.method_handlers[
            Method.RejectSubscribedTopic.value
        ] = lambda *args: logger.info(
            f"[{args[4]}:{args[5]}] Subscription to topic {args[3]} rejected"
        )

        def get_all_topic(*args):

            all_topics = {}
            for key, value in self.topics.items():
                all_topics[value["name"]] = int(key)

            self.sender.send(
                Method.AllTopics.value,
                0x0,
                0x0,
                DType.Json.value,
                0x00,
                all_topics
            )

        self.method_handlers[Method.GetAllTopics.value] = get_all_topic

        self.method_handlers[Method.AllTopics.value] = lambda *args: logger.info(
            f"[{args[4]}:{args[5]}] All topic send."
        )
        # need to send in map or json format or may be array of string  ?

    def __init__root_method(self):
        pass

    def __init__data_method(self):
        pass

    def __init__control_method(self):
        pass


class Rejection(Enum):
    NO_TOPIC_FOUND = 0x01
