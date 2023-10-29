from loggings import logger
from proto import CProto, PearsonHashing

class DtypeParser:
    def __init__(self):
        self.dtype_parser = [None]*256

    def __call__(self, dtype, data):
        return self.dtype_parser[dtype](data)

    def helperParser(self, type, data):
        pass

    def initSimpleDtypeParser(self):
        self.dtype_parser[0x00] = lambda data: None
        self.dtype_parser[0x01] = lambda data: struct.unpack('?', data)[0]

class MethodHandler:
    def __init__(self):
        self.method_handlers = [None]*64
        self.sender = CProto(src = "10.35.0.93", dst = "10.38.1.156")

        self.__init__basic_method()
        self.__init__root_method()
        self.__init__data_method()
        self.__init__control_method()

    def _set_permutation(self, t):
        self.sender.hashing.T = t

    def __call__(self, method, auth, dtype, topic, data):
        # print(method, type(method), self.method_handlers)
        return self.method_handlers[method](data)

    def __init__basic_method(self):
        # 0x00
        def ping(_data):
            logger.info("Ping")
            # senf a pong message
            self.sender.send(0x01, 0x0, 0x0, 0x00, 0x00)
        self.method_handlers[0x00] = ping

        # 0x01
        self.method_handlers[0x01] = lambda data: logger.info("Pong")


    def __init__root_method(self):
        pass

    def __init__data_method(self):
        pass

    def __init__control_method(self):
        pass