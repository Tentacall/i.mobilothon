import unittest
from protocol.proto_py.utils import DtypeParser

class TestDtypeParser(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dtype_parser = DtypeParser()

    def generate_test(self, dtype, data):
        self.assertEqual(self.dtype_parser.decode(dtype, self.dtype_parser.encode(dtype, data)), data)

    def test_nonetype(self):
        self.generate_test(0, None)
    
    def test_bool(self):
        self.generate_test(1, False)
        self.assertEqual(self.dtype_parser.encode(1, True), 0x01)
    
    def test_byte(self):
        self.generate_test(2, 0x01)

    def test_char(self):
        self.generate_test(3, 'a')
        b = self.dtype_parser.encode(2, 'a')
        self.assertEqual(len(b), 1)

    def test_int16(self):
        self.generate_test(4, 0x01)
        b = self.dtype_parser.encode(4, 0x01)
        self.assertEqual(len(b), 2)
    
    def test_int32(self):
        self.generate_test(5, 0x01)
        b = self.dtype_parser.encode(5, 0x01)
        self.assertEqual(len(b), 4)
    
    def test_int64(self):
        self.generate_test(6, 0x01)
        b = self.dtype_parser.encode(6, 0x01)
        self.assertEqual(len(b), 8)
    
    def test_int128(self):
        self.generate_test(7, 0x01)
        b = self.dtype_parser.encode(7, 0x01)
        self.assertEqual(len(b), 16)
    
    def test_array_byte(self):
        self.generate_test(0x12, [0x01, 0x02, 0x03])

if __name__ == '__main__':
    unittest.main() 