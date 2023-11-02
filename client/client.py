from protocol.proto_py.proto import CProto, PearsonHashing
from protocol.proto_py.utils import DtypeParser

class Client:
    def __init__(self, src, dst, sport, dport) -> None:
        self.proto = CProto(src, dst, sport, dport)
        self.dtype_parser = DtypeParser()
        self.hashing = PearsonHashing()

    def connect(self, ip, port):
        pass
    
    def cli(self):
        pass
