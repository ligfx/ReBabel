# port 1337
# server https://gameserver.albianwarp.com

import socket
import struct

HOST = '127.0.0.1'
#HOST = "gameserver.albianwarp.com"
PORT = 1337
USERNAME = "ligfx"
PASSWORD = "iauDE5dNGu99gYH"

def write_uint32le(i):
    if i < 0:
        raise Exception(i)
    if i > 0xFFFFFFFF:
        raise Exception(i)
    return struct.pack('<I', i)

def read_uint16le(buf):
    return struct.unpack('<H', buf)[0]

def read_uint32le(buf):
    return struct.unpack('<I', buf)[0]


def warn_matches(name, actual, desired):
    if actual != desired:
        print(f"Warning: Bad {name}: expected {repr(desired)} but got {repr(actual)}")

def check_matches(name, actual, desired):
    if actual != desired:
        raise Exception(f"Bad {name}: expected {repr(desired)} but got {repr(actual)}")
    

def read_cstring(buf):
    s = b''
    for c in buf:
        if c == 0:
            break
        s += bytes([c])
    return s

# server communication stuff

__nonce = 0
def next_nonce():
    global __nonce
    result = __nonce
    __nonce += 1
    return result

server_echo_load = b'\x00\x00\x00\x00\x00\x00\x00\x00'
server_user_id = 0

# NET: LINE request package
# magic: \x25\x00\x00\x00
# 8 bytes echo load if was previously logged in, otherwise zeroes
# 8 bytes user_id - zero here since we're not logged in
# uint32_le message nonce
# 20 bytes unknown
# uint32_le username length
# uint32_le password length
# username - latin1/cp1252? or utf8? - including trailing \0
# password - including trailing \0

def make_net_line_request(username, password):
    if isinstance(username, str):
        username = username.encode('cp1252')
    if isinstance(password, str):
        password = password.encode('cp1252')
    
    magic = b'\x25\x00\x00\x00'
    return (
        magic
        + server_echo_load
        + write_uint32le(server_user_id)
        + b'\x00' * 4
        + write_uint32le(next_nonce())
        + b'\x00' * 20
        + write_uint32le(len(username) + 1)
        + write_uint32le(len(password) + 1)
        + username + b'\x00'
        + password + b'\x00'
    )

# NET: LINE response package
# magic: \x0a\x00\x00\x00
# "echo load": 8 bytes
#   - zeroes when failed
#   - \x40\x52\x4b\x28\xeb\x00\x00\x00 when successful - note \xeb\x00\x00\x00 is 235
# uint32 user id
# uint16 user hid
# 2 bytes \x0a\x00 when successful, \x00\x00 when not
# uint32 nonce from request
# unknown 12 bytes
# uint32 the number 1
# unknown 4 bytes
# uint32 length of remaining data in response (constants, server port, constant, strings)
# uint32 the number 1
# uint32 the number 1
# uint32 the number 1
# uint32 server port
# uint32 server id
# host address - with null byte
# host friendly name - with null byte
# multiple servers can be returned supposedly

def parse_net_line_response(buf):
    check_matches("magic", buf[0:4], b'\x0a\x00\x00\x00')
    
    echo_load = buf[4:12]
    if echo_load != b'\x00\x00\x00\x00\x00\x00\x00\x00':
        server_echo_load = echo_load
    user_id = read_uint32le(buf[12:16])
    if user_id != 0:
        server_user_id = user_id
    user_hid = read_uint16le(buf[16:18]) # always one?
    
    warn_matches("tiny magic", buf[18:20], b'\x0a\x00' if server_user_id else b'\x00' * 2)
    nonce = read_uint32le(buf[20:24])
    warn_matches("padding", buf[24:36], b'\x00' * 12)
    warn_matches("constant", buf[36:40], b'\x01\x00\x00\x00' if server_user_id else b'\x00' * 4)
    warn_matches("padding", buf[40:44], b'\x00' * 4)
    
    if server_user_id == 0:
        warn_matches("length of remaining data", buf[44:48], b'\x00' * 4)
        len_remaining_data = 0
        server_port = 0
        server_id = 0
        host_addr = b''
        host_friendly_name = b''
    else:
        len_remaining_data = read_uint32le(buf[44:48])
        warn_matches("constant", buf[48:60], b'\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00')
        server_port = read_uint32le(buf[60:64])
        server_id = read_uint32le(buf[64:68])
        host_addr = read_cstring(buf[68:])
        host_friendly_name = read_cstring(buf[68+len(host_addr)+1:])

    print(f"echo_load: {echo_load}")
    print(f"user id: {user_id}")
    print(f"user hid: {user_hid}")
    print(f"nonce: {nonce}")
    print(f"len_remaining_data: {len_remaining_data}")
    print(f"server_port: {server_port}")
    print(f"server_id: {server_id}")
    print(f"host_addr: {host_addr}")
    print(f"host_friendly_name: {host_friendly_name}")

# NET: STAT request
# magic \x18\x00\x00\x00
# 8 bytes echo load
# uint32 user id
# 4 bytes unknown
# uint32 nonce

def make_net_stat_request():
    magic = b'\x18\x00\x00\x00'
    return (
        magic
        + server_echo_load
        + write_uint32le(server_user_id)
        + b'\x00' * 4
        + write_uint32le(next_nonce())
    )

# NET: STAT response
# magic \x18\x00\x00\x00
def parse_net_stat_response(buf):
    check_matches("magic", buf[0:4], b'\x18\x00\x00\x00')
    echo_load = buf[4:12] # rebabel has this as zero, probably wrong
    if echo_load != b'\x00\x00\x00\x00\x00\x00\x00\x00':
        server_echo_load = echo_load
    user_id = read_uint32le(buf[12:16]) # rebabel has this as zero, probably wrong
    if user_id != 0:
        server_user_id = user_id
    warn_matches("padding", buf[16:20], b'\x00' * 4)
    nonce = read_uint32le(buf[20:24])
    warn_matches("padding", buf[24:32], b'\x00' * 8)
    milliseconds_online = read_uint32le(buf[32:36])
    users_online = read_uint32le(buf[36:40])
    bytes_received = read_uint32le(buf[40:44])
    bytes_sent = read_uint32le(buf[44:48])
    
    print(f"echo_load: {echo_load}")
    print(f"user id: {user_id}")
    print(f"nonce: {nonce}")
    print(f"milliseconds_online: {milliseconds_online}")
    print(f"users_online: {users_online}")
    print(f"bytes_received: {bytes_received}")
    print(f"bytes_sent: {bytes_sent}")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    s.sendall(make_net_line_request(USERNAME, PASSWORD))
    data = s.recv(1024)
    parse_net_line_response(data)
    print("")
    
    s.sendall(make_net_stat_request())
    data = s.recv(1024)
    print(repr(data))
    parse_net_stat_response(data)
    
