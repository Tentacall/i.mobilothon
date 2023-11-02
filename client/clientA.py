from client import Client
from protocol.proto_py.standards import Method, DType

class ClientA(Client):
    def __init__(self, src, dst, sport, dport) -> None:
        self.sport = sport
        super().__init__(src, dst, sport, dport)

    # def connect(self, ip, port):
    #     self.proto.set_dst(ip, port)
    #     self.proto.send(Method.CONNECT, False, False, DType.INT, 0, self.sport)
    
    # def cli(self):
    #     print(f"[ Client A ]: Starting at port {self.sport}")
    #     print(">>> [method] [retain] [auth] [dtype] [topic] [...msg]")

    #     while True:
    #         token = input(">>> ").split()
    #         # example: 
    #         if len(token) == 0:
    #             break
            
    #         method = int(token[0])
    #         retain = bool(int(token[1]))
    #         auth = bool(int(token[2]))
    #         dtype = int(token[3])
    #         topic = int(token[4])
    #         msg = " ".join(token[5:]) if len(token) > 5  else None

    #         self.proto.send(method, retain, auth, dtype, topic, msg)



if __name__ == '__main__':
    client = ClientA("10.38.2.88", "10.35.0.93", 9000, 9779)
    client.cli()