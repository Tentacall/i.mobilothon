import struct
import json
from typing import Callable, Optional, List
from protocol.proto_py.standards import DType

class DtypeParser:
    def __init__(self):
        self.encoder: List[Optional[Callable]] = [None]*256
        self.decoder: List[Optional[Callable]] = [None]*256

        self.initSimpleDtypeParser()

    def encode(self, dtype, data):
        return self.encoder[dtype](data)

    def decode(self, dtype, data):
        return self.decoder[dtype](data)

    def helperParser(self, type, data):
        pass

    def initSimpleDtypeParser(self):
        self.encoder[0] = lambda _data: None
        self.decoder[0] = lambda _data: None

        # boolean
        self.encoder[1] = lambda _data: 0x01 if _data else 0x00
        self.decoder[1] = lambda _data: True if _data == 0x01 else False

        # byte
        self.encoder[2] = lambda _data: _data
        self.decoder[2] = lambda _data: _data

        # char
        self.encoder[3] = lambda _data: _data.encode('utf-8')
        self.decoder[3] = lambda _data: _data.decode('utf-8')

        # int16
        self.encoder[4] = lambda _data: _data.to_bytes(2, byteorder='big', signed=True)
        self.decoder[4] = lambda _data: int.from_bytes(_data, byteorder='big', signed=True)

        # int32
        self.encoder[5] = lambda _data: _data.to_bytes(4, byteorder='big', signed=True)
        self.decoder[5] = lambda _data: int.from_bytes(_data, byteorder='big', signed=True)

        # int64
        self.encoder[6] = lambda _data: _data.to_bytes(8, byteorder='big', signed=True)
        self.decoder[6] = lambda _data: int.from_bytes(_data, byteorder='big', signed=True)

        # int128
        self.encoder[7] = lambda _data: _data.to_bytes(16, byteorder='big', signed=True)
        self.decoder[7] = lambda _data: int.from_bytes(_data, byteorder='big', signed=True)

        # array_byte [strictly 8-bit]
        self.encoder[0x12] = lambda _data: bytes(_data)
        self.decoder[0x12] = lambda _data: list(_data)

        # float32
        self.encoder[DType.Float32.value] = lambda _data: struct.pack('f', _data)
        self.decoder[DType.Float32.value] = lambda _data: struct.unpack('f', _data)[0]

        # float64
        self.encoder[DType.Float64.value] = lambda _data: struct.pack('d', _data)
        self.decoder[DType.Float64.value] = lambda _data: struct.unpack('d', _data)[0]
        
        # String
        self.encoder[DType.String.value] = lambda _data: _data.encode('utf-8')
        self.decoder[DType.String.value] = lambda _data: _data.decode('utf-8')

        # json
        def json_decoded(_data):
            try:
                return json.loads(_data.decode('utf-8'))
            except Exception as e:
                print(e)
                return {}

        self.encoder[DType.Json.value] = lambda _data: json.dumps(_data).encode('utf-8')
        self.decoder[DType.Json.value] = json_decoded