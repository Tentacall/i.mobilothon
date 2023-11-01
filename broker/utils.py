from broker.loggings import logger
from protocol.proto_py.proto import CProto, PearsonHashing
from protocol.proto_py.utils import DtypeParser
from typing import Callable, Optional, List


class AutherizedDevices:
    def __init__(self):
        self._load()
        self.autherize_macs = []

    def _load(self):
        pass

class MethodHandler:
    def __init__(self):
        self.method_handlers: List[Optional[Callable]]= [None]*64
        self.sender = CProto(src = "10.35.0.93", dst = "10.38.1.156")
        self.dtype_parser = DtypeParser()

        self.__init__basic_method()
        self.__init__root_method()
        self.__init__data_method()
        self.__init__control_method()

    def _set_permutation(self, t):
        self.sender.hashing.T = t

    def __call__(self, method, auth, dtype, topic, data, dst_ip, dst_port):
        # data = self.dtype_parser(dtype, data)
        self.sender.set_dst(dst_ip, dst_port)
        return self.method_handlers[method](data, auth, dtype, topic)

    def __init__basic_method(self):
        # 0x00
        def ping(*args):
            logger.info("Ping")
            # send a pong message
            self.sender.send(0x01, 0x0, 0x0, 0x00, 0x00)
        self.method_handlers[0x00] = ping

        # 0x01
        self.method_handlers[0x01] = lambda *args: logger.info("Pong")

        # 0x0B -> Connect Methdo
        def connect(*args):
            # send permutation table
            self.sender.send(0x0D, 0x0, 0x0, 0x12, 0x00,  )


    def __init__root_method(self):
        pass

    def __init__data_method(self):
        pass

    def __init__control_method(self):
        pass
