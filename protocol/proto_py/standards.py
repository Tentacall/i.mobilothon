from enum import Enum


class DType(Enum):
    Null = 0
    Bool = 1
    Byte = 2
    Char = 3
    Int16 = 4
    Int32 = 5
    Int64 = 6
    Int128 = 7
    Float16 = 8
    Float32 = 9
    Float64 = 0x0A
    Float128 = 0x0B
    String = 0x0C
    Text = 0x0D

    ArrayBool = 0x11
    ArrayByte = 0x12
    ArrayChar = 0x13
    ArrayInt16 = 0x14
    ArrayInt32 = 0x15
    ArrayInt64 = 0x16
    ArrayInt128 = 0x17
    ArrayFloat16 = 0x18
    ArrayFloat32 = 0x19
    ArrayFloat64 = 0x1A
    ArrayFloat128 = 0x1B


class Method(Enum):
    # basic methods
    Ping = 0x00
    Pong = 0x01
    Publish = 0x02
    Subscribe = 0x03
    Unsubscribe = 0x04
    AprrovePublishedTopic = 0x05
    RejectPublishedTopic = 0x06
    AprroveSubscribedTopic = 0x07
    RejectSubscribedTopic = 0x08
    GetAllTopics = 0x09
    SubscribeAllTopics = 0x0A
    Connect = 0x0B
    Disconnect = 0x0C
    ConnectAcknowledgement = 0x0D
    DisconnectAcknowledgement = 0x0E

    # Root methods
