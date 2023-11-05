import time
from scapy.all import *
from client import Client, MethodHandler
from broker.loggings import logger
from protocol.proto_py.standards import Method, DType

class ClientA(Client):
    def __init__(self, src, dst, sport, dport, client_id=0) -> None:
        super().__init__(src, dst, sport, dport, client_id)

    def sender(self):
        # connect to broker
        self.proto.send(Method.Connect.value, 0x0, 0x0, DType.Null.value, 0x00)
        time.sleep(2)
        # publish topic
        self.proto.send(Method.Publish.value, 0x0, 0x0, DType.String.value, 0x00, "time")
        # : TODO : retry n times if rejected then exit
        time.sleep(2)
        try:
            topic_id = self.method_handlers.topics["time"]
        except:
            topic_id = 1
        logger.info(f"Topic id : {topic_id}")
        count = 100
        while count > 0:
            try:
                count -= 1
                t = time.strftime("%H:%M:%S")
                self.proto.set_dst(self.dst_ip, self.dst_port)
                self.proto.send(Method.DataTransfer.value, 0x0, 0x0, DType.String.value, topic_id, t)
                logger.info(f"Data sent : {t}")
                time.sleep(2)
            except:
                logger.error("Exiting client")
                break
    def listener_thread_func(self):
        print(f"Listening on port {self.sport}")
        sniff(filter="tcp", prn=self.callback)


if __name__ == "__main__":
    clientA = ClientA("172.17.0.1", "172.17.0.2", 9779, 9779, 1)
    clientA.start_listener()
    clientA.sender()

    # client = Client("172.17.0.1", "172.17.0.2", 9779, 9779)
    # client.start_listener()
    # client.cli()