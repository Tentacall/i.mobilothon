import unittest
from broker.utils import DtypeParser

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

if __name__ == '__main__':
    unittest.main() 