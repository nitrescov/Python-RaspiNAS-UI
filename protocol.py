import os
import struct
import socket
import hashlib

# Protocol constants for communication with the RaspiNAS socket interface
BUFFER = 2**27  # Max packet or file buffer size to be cached in RAM (128 MB)
RETRY_COUNT = 5  # Max number of loop passes before an error is raised (must be a positive integer)
SEPARATOR = "\n"

# Communication Protocol:
# SERVER        CLIENT
#       <------- [CMD]
# [RSP] ------->
#       <------- [CDT]      | Optional command data
# [RDT] ------->            | Optional response data
#
# To indicate an invalid checksum, a check response is received after each packet sent:
# SENDING DATA                  RECEIVING DATA              SIZE
# Send header                   Receive header              58 Bytes                    |
# Send data                     Receive data                Length specified in header  |
# Receive check response        Send check response         2 Bytes                     V
#
# Header structure:         [ 8 Bytes packet length | 1 Byte packet command | 1 Byte content type | 48 Bytes SHA384 checksum ]
# Check response structure: [ 1 Byte packet command | 1 Byte validity indicator ]
#
# Packet command structure: [ 1 Bit additional data indicator | 1 Bit response indicator | 6 Bits command type ]

# List of commands and related data (CMDs are expandable up to 0x3f (63), the other command types are calculated depending on them)
CMD_LOGIN = 0x00
CMD_GET_DIRECTORIES = 0x01
CMD_UPLOAD_FILE = 0x02
CMD_DOWNLOAD_FILE = 0x03
CMD_DOWNLOAD_FOLDER = 0x04

CDT_UPLOAD_FILE = CMD_UPLOAD_FILE | (1 << 7)

# List of responses and related data
RSP_LOGIN = CMD_LOGIN | (1 << 6)
RSP_GET_DIRECTORIES = CMD_GET_DIRECTORIES | (1 << 6)
RSP_UPLOAD_FILE = CMD_UPLOAD_FILE | (1 << 6)
RSP_DOWNLOAD_FILE = CMD_DOWNLOAD_FILE | (1 << 6)
RSP_DOWNLOAD_FOLDER = CMD_DOWNLOAD_FOLDER | (1 << 6)

RDT_UPLOAD_FILE = CMD_UPLOAD_FILE | (1 << 6) | (1 << 7)

# List of content types
TYPE_NONE = 0x00
TYPE_DATA = 0x01
TYPE_FILE = 0x02
TYPE_FAILURE = 0x03
TYPE_SUCCESS = 0x04

# List of validity indicator states
CHECK_INVALID = 0x00
CHECK_VALID = 0x01


def recvall(sock: socket.socket, data_len: int) -> bytes:
    data = bytearray()
    while len(data) < data_len:
        packet = sock.recv(min(BUFFER, data_len - len(data)))
        if not packet:
            raise ConnectionError("Connection closed during transfer")
        data.extend(packet)
    return bytes(data)


def send_header(sock: socket.socket, msg_len: int, msg_cmd: int, msg_type: int, msg_checksum: bytes) -> None:
    assert len(msg_checksum) == 48  # SHA384 hash length
    sock.sendall(struct.pack("!Q", msg_len) + struct.pack("!B", msg_cmd) + struct.pack("!B", msg_type) + msg_checksum)


def receive_header(sock: socket.socket) -> tuple[int, int, int, bytes]:
    raw_header = recvall(sock, 58)
    return struct.unpack("!Q", raw_header[:8])[0], raw_header[8], raw_header[9], raw_header[10:]


def send_check_response(sock: socket.socket, msg_cmd: int, validity_indicator: int) -> None:
    sock.sendall(struct.pack("!B", msg_cmd) + struct.pack("!B", validity_indicator))


def receive_check_response(sock: socket.socket, msg_cmd: int) -> bool:
    raw_response = recvall(sock, 2)
    if raw_response[0] != msg_cmd:
        raise ValueError("Received check response does not match the associated command type")
    return True if raw_response[1] == CHECK_VALID else False


def calc_hash(obj) -> bytes:
    hash_object = hashlib.sha384()
    if isinstance(obj, bytes):
        hash_object.update(obj)
        return hash_object.digest()
    elif isinstance(obj, str):
        if not os.path.isfile(obj):
            raise ValueError("The file to be hashed does not exist")
        with open(obj, "rb") as f:
            while True:
                data = f.read(BUFFER)
                if not data:
                    break
                hash_object.update(data)
        return hash_object.digest()
    else:
        raise Exception("The object to be hashed must be of type bytes or a path string")
