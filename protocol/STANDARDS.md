## Self Defined Standard Method
- Connection method
    - 0x00 Ping
    - 0x01 Pong
    - 0x02 Publish Topic
    - 0x03 Subscribe Topic
    - 0x04 Unsubscribe Topic
    - 0x05 Approve Published Topic
    - 0x06 Approve Subscribed Topic
    - 0x07 Reject Published Topic
    - 0x08 Reject Subscribed Topic
    - 0x09 Get All Topics
    - 0x0A Subscribe All Topics
- Root Methods
    - 0x10 Key Exchange Init [Auth required]
    - 0x11 Key Exchange Response
    - 0x12 Get All Connected Clients
    - 0x13 Send All Connected Clients
    - 0x14 Cloude Sync
    - 0x15 Remove Topic
    - 0x16 Remove Client
    - 0x17 Acknowledge
    - 0x18 Reject
- Data transfer Methods
    - 0x20 Key Exchange Init
    - 0x21 Key Exchange Response
    - 0x22 Data Transfer Raw
    - 0x23 Data Transfer Encrypted
    - 0x24 Data Transfer Compressed
    - 0x25 Continuous Data Transfer Raw
- Control Methods
    - Upcomming ... 


## Self Defined Standard Data type
- 0x00 null ( not data )
- 0x01 boolean
- 0x02 int8
- 0x03 int32
- 0x04 int64
- 0x05 float32
- 0x06 float64
- 0x07 string
- 0x08 bytes
- 0x09 dictionary
- 0x0A map
- 0x0B csv
- 0x0C json
- 0x0D xml
- 0x0E yaml
- 0x0F bson
- 0x10 protobuf
- 0x11 msgpack

## Topic is flexible 
- it is managed by broker onflight