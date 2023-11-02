import queue
import threading
from scapy.all import *

from broker.loggings import logger
from protocol.proto_py.utils import DtypeParser
from protocol.proto_py.standards import Method, DType
from protocol.proto_py.proto import CProto, PearsonHashing


class Client:
    def __init__(self, src, dst, sport, dport, client_id = 0) -> None:
        self.sport = sport
        self.client_id = client_id
        self.proto = CProto(src, dst, sport, dport)
        self.dtype_parser = DtypeParser()
        self.hashing = PearsonHashing()
        self.send_queue = queue.Queue()
        self.stop_threads = True

    def connect(self, ip, port):
        self.proto.set_dst(ip, port)
        self.proto.send(method=Method.Connect, retain=0x0, auth=0x0, dtype=DType.Null, topic=0x00, msg=None)
        if(self.recv_conn_ack()):
            print(f"[ Client {self.client_id} ]: Connected to {ip}:{port}")
            self.stop_threads = False 
            self.send_recv()
        else:
            print(f"[ Client {self.client_id} ]: Connection failed")
            
    def recv_conn_ack(self):
        # Create a packet filter to capture packets with the acknowledgment method
        acknowledgment_filter = (
            f"ip dst {dst_ip} and ip src {src_ip} "
            f"and tcp dst port {dst_port} and tcp src port {src_port} "
            f"and CProtoLayer.method == {Method.ConnectAcknowledgement.value}"
        )

        # Use Scapy's sniff function to capture the acknowledgment packet
        acknowledgment_packet = sniff(filter=acknowledgment_filter, count=1)[0]
        
        if(acknowledgment_packet):
            dtype = acknowledgment_packet[CProtoLayer].dtype
            encoded_msg = acknowledgment_packet[Raw].load
            self.hashing.T = self.dtype_parser.decode(dtype, encoded_msg)
            acknowledgment_packet[CProtoLayer].show()
            print(self.hashing.T)
            print("connecting...")
            return True
        
        return False
    
    def recv_disconn_ack(self):
        # Create a packet filter to capture packets with the acknowledgment method
        acknowledgment_filter = (
            f"ip dst {dst_ip} and ip src {src_ip} "
            f"and tcp dst port {dst_port} and tcp src port {src_port} "
            f"and CProtoLayer.method == {Method.DisconnectAcknowledgement.value}"
        )

        # Use Scapy's sniff function to capture the acknowledgment packet
        acknowledgment_packet = sniff(filter=acknowledgment_filter, count=1)[0]
        
        if(acknowledgment_packet):
            self.hashing.T = [i for i in range(2**8)]
            acknowledgment_packet[CProtoLayer].show()
            print(self.hashing.T)
            print("Disconnecting...")
            return True
        
        return False

        
    def disconnect(self):
        self.proto.send(method=Method.Disconnect, retain=0x0, auth=0x0, dtype=DType.Null, topic=0x00, msg=null)
        if(self.recv_disconn_ack()):
            print(f"[ Client {self.client_id} ]: Disconnected from {ip}:{port}")
            self.stop_threads = True
            self.send_thread.join()
            self.recv_thread.join()
        else:
            print(f"[ Client {self.client_id} ]: Disconnection failed")
            
        
    def send_recv(self):
        self.send_thread = threading.Thread(target=self.send_thread_func)
        self.recv_thread = threading.Thread(target=self.recv_thread_func)
        
        self.send_thread.start()
        self.recv_thread.start()
        
    def send_thread_func(self):
        i = 0
        while not self.stop_threads:
            send_queue.put([Method.Ping, 0x0, 0x0, DType.String, 0x00, f"hello{i}"])
            if not self.send_queue.empty():
                msg = self.send_queue.get()
                self.proto.send(method=msg[0], retain=msg[1], auth=msg[2], dtype=msg[3], topic=msg[4], msg=msg[5])
                self.send_queue.task_done()
                i += 1
    
    def recv_thread_func(self):
        while not self.stop_threads:
            self.proto.recv()
    
    def cli(self):
        print(f"[ Client {self.client_id} ]: Starting at port {self.sport}")
        print(">>> [method] [retain] [auth] [dtype] [topic] [...msg]")

        while True:
            token = input(">>> ").split()
            # example: 
            if len(token) == 0:
                break
            
            method = int(token[0])
            retain = bool(int(token[1]))
            auth = bool(int(token[2]))
            dtype = int(token[3])
            topic = int(token[4])
            msg = " ".join(token[5:]) if len(token) > 5  else None

    def callback(self, pkt):
        pass

    def start_listener(self):
        def listener_thread_func():
            print(f"Listening on port {self.sport}")
            sniff(filter="tcp", prn=self.callback)

        self.listener_thread = threading.Thread(target=listener_thread_func)
        self.listener_thread.daemon = True
        self.listener_thread.start()


class MethodHandler:
    def __init__(self):
        self.method_handlers = [None] * 256
        self.dtype_parser = DtypeParser()
        self.hashing = PearsonHashing()

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


if __name__ == "__main__":
    client = Client("10.35.0.93", "10.38.0.242", 9779, 9779)
    client.start_listener()
    client.cli()
