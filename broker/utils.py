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

    def __call__(self, method, auth, dtype, topic, data):
        return self.method_handlers[method](data)