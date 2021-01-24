import logging
import datetime
import struct
import sys
import itertools
import zlib


class AutoRepr:
    def __repr__(self):
        s = "<"
        s += type(self).__name__
        s += " "
        for i, (k, v) in enumerate(vars(self).items()):
            if i != 0:
                s += " "
            s += k
            s += "="
            s += repr(v)
        s += ">"
        return s


class NotEnoughData(BaseException):
    pass


class bufreader:
    def __init__(self, buf):
        self._buf = buf
        self._p = 0

    def read(self, n=None):
        result = self.peek(n)
        self._p += len(result)
        return result

    def peek(self, n=None):
        if n == None:
            return self._buf[self._p :]
        else:
            return self._buf[self._p : self._p + n]

    def seek(self, n):
        assert n >= 0
        self._p = n

    def tell(self):
        return self._p


def read_or_fail(r, n):
    buf = r.read(n)
    if len(buf) != n:
        raise NotEnoughData(f"Expected {n} bytes but only got {len(buf)} bytes: {buf}")
    return buf


def read_uint8(r):
    buf = read_or_fail(r, 1)
    return struct.unpack("B", buf)[0]


def read_uint16le(r):
    buf = read_or_fail(r, 2)
    return struct.unpack("<H", buf)[0]


def read_uint16be(r):
    buf = read_or_fail(r, 2)
    return struct.unpack(">H", buf)[0]


def read_uint32le(r):
    buf = read_or_fail(r, 4)
    return struct.unpack("<I", buf)[0]


def read_sint32le(r):
    buf = read_or_fail(r, 4)
    return struct.unpack("<i", buf)[0]


def read_uint32be(r):
    buf = read_or_fail(r, 4)
    return struct.unpack(">I", buf)[0]


def read_ipaddr_be(r):
    buf = read_or_fail(r, 4)
    return f"{buf[0]}.{buf[1]}.{buf[2]}.{buf[3]}"


def peek_exact(f, n):
    p = f.tell()
    buf = f.read(n)
    f.seek(p)
    return buf


def warn_matches(name, actual, desired):
    if actual != desired:
        logging.warning(
            f"Warning: {name}: expected {repr(desired)} but got {repr(actual)}"
        )


def check_matches(name, actual, desired):
    if actual != desired:
        raise Exception(f"Bad {name}: expected {repr(desired)} but got {repr(actual)}")


def read_cstring(r):
    s = b""
    while True:
        buf = read_or_fail(r, 1)
        if buf[0] == 0:
            break
        s += buf
    return s


# NET: LINE request package
# header:
# magic: \x25\x00\x00\x00
# 8 bytes echo load if was previously logged in, otherwise zeroes
# 8 bytes user_id - zero here since we're not logged in
# 4 bytes unknown
# uint32_le message nonce
# 8 bytes unknown
# body:
# 4 bytes unknown1
# 4 bytes unknown2
# 4 bytes unknown3
# uint32_le username length
# uint32_le password length
# username - latin1/cp1252? or utf8? - including trailing \0
# password - including trailing \0


def parse_net_line_request(f, header):
    class NetLineRequest(AutoRepr):
        pass

    try:

        request = NetLineRequest()
        request.unknown1 = read_uint32le(f)
        warn_matches("NetLineRequest.unknown1", request.unknown1, 0)
        request.unknown2 = read_uint32le(f)
        warn_matches("NetLineRequest.unknown2", request.unknown2, 0)
        request.unknown3 = read_uint32le(f)
        warn_matches("NetLineRequest.unknown3", request.unknown3, 0)
        request.username_length = read_uint32le(f)
        request.password_length = read_uint32le(f)
        request.username = read_or_fail(f, request.username_length)
        request.password = read_or_fail(f, request.password_length)

        check_matches("rest of data", f.read(), b"")
        return request

    finally:
        logging.debug(request)


# def make_net_line_request(username, password):
#     if isinstance(username, str):
#         username = username.encode('cp1252')
#     if isinstance(password, str):
#         password = password.encode('cp1252')
#
#     magic = b'\x25\x00\x00\x00'
#     return (
#         magic
#         + server_echo_load
#         + write_uint32le(server_user_id)
#         + b'\x00' * 4
#         + write_uint32le(next_nonce())
#         + b'\x00' * 20
#         + write_uint32le(len(username) + 1)
#         + write_uint32le(len(password) + 1)
#         + username + b'\x00'
#         + password + b'\x00'
#     )

# NET: LINE response package
# header:
# magic: \x0a\x00\x00\x00
# "echo load": 8 bytes
#   - zeroes when failed
#   - \x40\x52\x4b\x28\xeb\x00\x00\x00 when successful - note \xeb\x00\x00\x00 is 235
# uint32 user id
# uint16 user hid
# 2 bytes \x0a\x00 when successful, \x00\x00 when not
# uint32 sequence id from request
# unknown 4 bytes
# body:
# unknown 8 bytes
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


def parse_net_line_response(f, header):
    class NetLineResponse(AutoRepr):
        pass

    class NetLineResponseServer(AutoRepr):
        pass

    header = NetLineResponse()

    try:
        header.unknown1 = read_uint32le(f)
        warn_matches("NetLineResponse.unknown1", header.unknown1, 0)
        header.unknown2 = read_uint32le(f)
        warn_matches("NetLineResponse.unknown1", header.unknown2, 0)
        header.unknown3 = read_uint32le(f)
        warn_matches("NetLineResponse.unknown3", header.unknown3, 1)

        header.length_of_remaining_data = read_uint32le(f)
        header.unknown4 = read_uint32le(f)
        warn_matches("NetLineResponse.unknown4", header.unknown4, 1)
        header.unknown5 = read_uint32le(f)
        warn_matches("NetLineResponse.unknown5", header.unknown5, 1)
        header.number_servers = read_uint32le(f)
        data_consumed = 16

        header.servers = []
        for _ in range(header.number_servers):
            server = NetLineResponseServer()
            header.servers.append(server)
            server.port = read_uint32le(f)
            server.id = read_uint32le(f)
            server.address = read_cstring(f)
            server.friendly_name = read_cstring(f)
            data_consumed += 8 + len(server.address) + len(server.friendly_name)

        check_matches("length of data", header.length_of_remaining_data, data_consumed)

        check_matches("rest of data", f.read(), b"")
        return header
    finally:
        logging.debug(f"{header}")


# NET: STAT request
# magic \x18\x00\x00\x00
# 8 bytes echo load
# uint32 user id
# 4 bytes unknown
# uint32 nonce


def make_net_stat_request():
    magic = b"\x18\x00\x00\x00"
    return (
        magic
        + server_echo_load
        + write_uint32le(server_user_id)
        + b"\x00" * 4
        + write_uint32le(next_nonce())
    )


# NET: STAT response
# magic \x18\x00\x00\x00
# def parse_net_stat_response(buf):
#     check_matches("magic", buf[0:4], b"\x18\x00\x00\x00")
#     echo_load = buf[4:12]  # rebabel has this as zero, probably wrong
#     if echo_load != b"\x00\x00\x00\x00\x00\x00\x00\x00":
#         server_echo_load = echo_load
#     user_id = read_uint32le(buf[12:16])  # rebabel has this as zero, probably wrong
#     if user_id != 0:
#         server_user_id = user_id
#     warn_matches("padding", buf[16:20], b"\x00" * 4)
#     nonce = read_uint32le(buf[20:24])
#     warn_matches("padding", buf[24:32], b"\x00" * 8)
#     milliseconds_online = read_uint32le(buf[32:36])
#     users_online = read_uint32le(buf[36:40])
#     bytes_received = read_uint32le(buf[40:44])
#     bytes_sent = read_uint32le(buf[44:48])
#
#     print(f"echo_load: {echo_load}")
#     print(f"user id: {user_id}")
#     print(f"nonce: {nonce}")
#     print(f"milliseconds_online: {milliseconds_online}")
#     print(f"users_online: {users_online}")
#     print(f"bytes_received: {bytes_received}")
#     print(f"bytes_sent: {bytes_sent}")


# NET: UNIK
# header:
# body:


def parse_net_unik_request(f, header):
    class NetBabelUnikRequest(AutoRepr):
        pass

    request = NetBabelUnikRequest()
    # check_matches("rest of data", f.read(), b"")
    logging.debug(request)
    return request


def parse_net_unik_response(f, header):
    class NetBabelUnikResponse(AutoRepr):
        pass

    try:

        response = NetBabelUnikResponse()
        response.payload_length = read_uint32le(f)
        response.unknown2 = read_uint32le(f)
        response.unknown3 = read_uint16le(f)
        response.unknown4 = read_uint16le(f)
        response.firstname_length = read_uint32le(f)
        response.lastname_length = read_uint32le(f)
        response.nickname_length = read_uint32le(f)

        response.firstname = read_or_fail(f, response.firstname_length)
        response.lastname = read_or_fail(f, response.lastname_length)
        response.nickname = read_or_fail(f, response.nickname_length)

        # check_matches("rest of data", f.read(), b"")
        return response
    finally:
        logging.debug(response)


# NetBabel message type 0x10
# sent by client
# guess it's just empty?

# sent twice after NetLineResponse
# sent once after NetBabelPrayMessageServer (with user_id read from message)


def parse_netbabel_0x10_request(f, header):
    class NetBabel0x10Request(AutoRepr):
        pass

    request = NetBabel0x10Request()
    # check_matches("rest of data", f.read(), b"")
    logging.debug(request)
    return request


# NetBabel message type 0xD
# sent by server


def parse_netbabel_0xd_server(f, header):
    class NetBabel0xDMessage(AutoRepr):
        pass

    try:
        request = NetBabel0xDMessage()
        request.payload_length = read_uint32le(f)
        request.user_id = read_uint32le(f)
        request.user_hid = read_uint16le(f)
        request.unknown4 = read_uint16le(f)
        warn_matches("0xd unknown4", request.unknown4, 52428)
        request.firstname_length = read_uint32le(f)
        request.lastname_length = read_uint32le(f)
        request.nickname_length = read_uint32le(f)
        request.firstname = read_or_fail(f, request.firstname_length)
        request.lastname = read_or_fail(f, request.lastname_length)
        request.nickname = read_or_fail(f, request.nickname_length)

        # check_matches("rest of data", f.read(), b"")
        return request
    finally:
        logging.debug(request)


# NetBabel message type 0xE
# sent by server


def parse_netbabel_0xe_server(f, header):
    class NetBabel0xEMessage(AutoRepr):
        pass

    try:
        request = NetBabel0xEMessage()
        p = f.tell()
        request.payload_length = read_uint32le(f)
        request.user_id = read_uint32le(f)
        request.user_hid = read_uint16le(f)
        request.unknown4 = read_uint16le(f)
        warn_matches("0xe unknown4", request.unknown4, 52428)
        request.firstname_length = read_uint32le(f)
        request.lastname_length = read_uint32le(f)
        request.nickname_length = read_uint32le(f)
        request.firstname = read_or_fail(f, request.firstname_length)
        request.lastname = read_or_fail(f, request.lastname_length)
        request.nickname = read_or_fail(f, request.nickname_length)
        assert f.tell() - p == request.payload_length

        return request
    finally:
        logging.debug(request)


# NetBabel 0x321


def parse_netbabel_0x321_server(f, header):
    class NetBabel0x321Response(AutoRepr):
        pass

    try:
        response = NetBabel0x321Response()
    finally:
        logging.info(response)


def parse_netbabel_0x321_client(f, header):
    class NetBabel0x321Message(AutoRepr):
        pass

    try:
        message = NetBabel0x321Message()

        data = read_or_fail(f, header.sometimes_payload_length)
        r = bufreader(data)

        def timestamp_or_zero(s):
            if s == 0:
                return 0
            else:
                return datetime.datetime.fromtimestamp(s)

        def parse_pascalstring(r):
            length = read_uint32le(r)
            return read_or_fail(r, length)

        message.moniker = parse_pascalstring(r)
        message.flags = read_uint8(r)
        warn_matches("flags", message.flags, 1)
        # TODO: maybe not genus...
        # if it's 0 then sometimes the data is way different
        # - moniker (pascalstring)
        # - single byte - genus? flag?
        # - uint32le = 0x1
        # - uint32le = 0x10 = 16
        # - uint32le - big number
        # - uint32le - big number
        # - uint32le - very big number
        # - uint32le = 0x4
        # - uint32le = 0
        # - uint32le = 0
        # - world name (pascalstring)
        # - world id (pascalstring)
        # - user id (pascalstring)
        # - uint32le = \r = 13
        # - uint32le = 0
        # - uint32le = 0

        # b'!\x00\x00\x007226-kiwi-lljjr-u75mu-eg2t2-38h3k\x00\x01\x00\x00\x00\x10\x00\x00\x00\xc1l\x00\x004\xb3\x00\x00.\xcd\x89>\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00ds3\x1c\x00\x00\x00dock-cs6uz-e24b5-fnbw3-jqadk\x04\x00\x00\x0027+1\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        assert message.flags in (0, 1)
        if message.flags == 1:
            message.gender = read_uint32le(r)
            assert message.gender in (1, 2)
            message.genus = read_uint32le(r)
            assert message.genus == 0
            message.species = read_uint32le(r)
            assert message.species in range(0, 26)
            message.unknown1 = read_uint32le(r)
            assert message.unknown1 in (0, 3, 4, 5, 6, 7, 11, 14)
            message.unknown2 = read_uint32le(r)
            assert message.unknown2 in (0, 10, 12, 13, 14, 15, 17)

        # if message.flags == 0:
        #     print(f"payload: {data}")
        #
        #     message.num_events = read_uint32le(r)
        #     assert message.num_events == 1
        #     message.event_type = read_uint32le(r)
        #     message.maybe_exported_at_world_time = read_uint32le(r)
        #     message.creature_age_in_ticks = read_uint32le(r)
        #     message.exported_timestamp = timestamp_or_zero(read_uint32le(r))
        #     message.creature_lifestage = read_uint32le(r)
        #     message.parent1 = parse_pascalstring(r)
        #     message.parent2 = parse_pascalstring(r)
        #     message.world_time_in_ticks = parse_pascalstring(r)
        #     message.world_uid = parse_pascalstring(r)
        #     message.user_id = parse_pascalstring(r)
        #     message.index = read_uint32le(r)
        #     message.creature_name = parse_pascalstring(r)
        #     assert message.creature_name == b""
        #     message.unknown11 = read_uint32le(r)
        #     assert message.unknown11 == 0
        #
        #     check_matches("rest of payload", r.read(), b"")
        #     assert False
        #     return
        # assert message.flags == 1

        message.number_of_events = read_uint32le(r)

        class NetEvent(AutoRepr):
            pass

        message.events = []
        for i in range(message.number_of_events):  # first event is just there
            event = NetEvent()
            message.events.append(event)
            # if i != 0:

            # like GLST, without user text or photo block name, or final two unknown bytes

            event.type = read_uint32le(r)
            event.world_time_in_ticks = read_uint32le(r)
            event.creature_age_in_ticks = read_sint32le(r)
            event.timestamp = timestamp_or_zero(read_uint32le(r))
            event.creature_lifestage = read_sint32le(r)
            event.parent1 = parse_pascalstring(r)
            event.parent2 = parse_pascalstring(r)
            event.world_name = parse_pascalstring(r)
            event.world_uid = parse_pascalstring(r)
            event.user_id = parse_pascalstring(r)

            event.index = read_uint32le(r)
            # check_matches("event index", event.index, i)

        message.creature_name = parse_pascalstring(r)

        message.num_notes = read_uint32le(r)
        message.notes = []
        for _ in range(message.num_notes):
            message.notes.append(parse_pascalstring(r))
        if message.num_notes:
            message.unknown3 = read_uint32le(r)
            check_matches("unknown3", message.unknown3, 0)

        check_matches("rest of payload", r.read(), b"")

        return message
    finally:
        logging.info(message)


# NET: STAT 0x18
# sent by client
# responded by server


def parse_net_stat_request(f, header):
    class NetBabelStatRequest(AutoRepr):
        pass

    request = NetBabelStatRequest()
    try:
        check_matches("rest of data", f.read(), b"")
        return request
    finally:
        logging.info(request)


def parse_net_stat_response(f, header):
    class NetBabelStatResponse(AutoRepr):
        pass

    response = NetBabelStatResponse()
    try:
        response.milliseconds_online = read_uint32le(f)
        response.users_online = read_uint32le(f)
        response.bytes_sent = read_uint32le(f)
        response.bytes_received = read_uint32le(f)
        # check_matches("rest of data", f.read(), b"")
        return response
    finally:
        logging.info(response)


# NET: RUSO 0x221
# sent by client and server


def parse_net_ruso_request(r, header):
    class NetBabelRusoRequest(AutoRepr):
        pass

    request = NetBabelRusoRequest()
    try:
        # empty
        return request
    finally:
        logging.info(request)


def parse_net_ruso_response(r, header):
    class NetBabelRusoResponse(AutoRepr):
        pass

    response = NetBabelRusoResponse()
    try:
        # empty?
        # assert False
        return response
    finally:
        logging.info(response)


# NET: ULIN 0x13
# sent by client
# guess it's empty?


def parse_net_ulin_request(f, header):
    class NetBabelUlinRequest(AutoRepr):
        pass

    request = NetBabelUlinRequest()
    request.user_id = header.user_id
    # check_matches("rest of data", f.read(), b"")
    logging.debug(request)
    return request


def parse_net_ulin_response(f, header):
    # if the header is zeroes, user is offline

    class NetBabelUlinResponse(AutoRepr):
        pass

    response = NetBabelUlinResponse()
    response.user_id = header.user_id
    # check_matches("rest of data", f.read(), b"")
    logging.debug(response)
    return response


# NetBabel PRAY message 0x9


class PrettyBuffer:
    def __init__(self, buf):
        self._buf = buf

    def __repr__(self):
        return repr(self._buf[0:32]) + "..."


def parse_pray(f):
    class Pray(AutoRepr):
        pass

    class PrayBlock(AutoRepr):
        pass

    pray = Pray()
    try:
        pray.magic = read_or_fail(f, 4)
        check_matches("magic", pray.magic, b"PRAY")
        pray.blocks = []
        while f.peek():
            block = PrayBlock()
            pray.blocks.append(block)
            block.type = read_or_fail(f, 4)
            block.name = read_or_fail(f, 128).rstrip(b"\x00")
            block.length = read_uint32le(f)
            block.decompressed_length = read_uint32le(f)
            block.compressed = read_uint32le(f)
            if block.compressed not in (0, 1):
                raise Exception(f"Invalid PRAY flags {block.compressed=}")
            if block.length != block.decompressed_length and block.compressed != 1:
                raise Exception(
                    f"PRAY lengths don't match but not flagged compressed {block.length=} {block.decompressed_length=} {block.compressed=}"
                )

            data = read_or_fail(f, block.length)
            if block.compressed:
                try:
                    data = zlib.decompress(data)
                except zlib.error as e:
                    block.error = e
                    continue
                if len(data) != block.decompressed_length:
                    raise Exception(
                        f"PRAY decompressed data length doesn't match header {len(data)=} {block.decompressed_length=}"
                    )

            if block.type in (b"MESG", b"REQU", b"CHAT", b"warp"):
                r = bufreader(data)
                block.num_int_tags = read_uint32le(r)
                block.int_tags = []
                for _ in range(block.num_int_tags):
                    key_length = read_uint32le(r)
                    key = read_or_fail(r, key_length)
                    value = read_uint32le(r)
                    block.int_tags.append((key, value))
                block.num_string_tags = read_uint32le(r)
                block.string_tags = []
                for _ in range(block.num_string_tags):
                    key_length = read_uint32le(r)
                    key = read_or_fail(r, key_length)
                    value_length = read_uint32le(r)
                    value = read_or_fail(r, value_length)
                    block.string_tags.append((key, value))

                check_matches("rest of data", r.read(), b"")
            else:
                block.data = PrettyBuffer(data)

        check_matches("rest of data", f.read(), b"")
        return pray
    except:
        logging.debug(pray)
        raise


def parse_pray_message_client(f, header):
    class NetBabelPrayMessageClient(AutoRepr):
        pass

    message = NetBabelPrayMessageClient()
    try:

        message.recipient_id = read_uint32le(f)
        message.recipient_hid = read_uint32le(f)
        p = f.tell()
        message.payload_length_minus_eight = read_uint32le(f)
        check_matches(
            "payload_length_minus_eight",
            message.payload_length_minus_eight,
            header.sometimes_payload_length,
        )
        message.maybe_from_hid = read_uint32le(f)
        message.maybe_from_id = read_uint32le(f)
        message.payload_length_minus_thirty_two = read_uint32le(f)
        check_matches(
            "payload_length_minus_thirty_two",
            message.payload_length_minus_thirty_two,
            message.payload_length_minus_eight - 24,
        )
        message.unknown7 = read_uint32le(f)
        message.unknown8 = read_uint32le(f)
        message.unknown9 = read_uint32le(f)
        message.unknown10 = read_uint32le(f)
        message.unknown11 = read_uint32le(f)

        r = bufreader(read_or_fail(f, message.payload_length_minus_thirty_two - 12))

        message.pray = parse_pray(r)

        # check_matches("rest of data", f.read(), b"")
        check_matches(
            "payload length", f.tell() - p, message.payload_length_minus_eight
        )
        return message
    finally:
        logging.info(message)


def parse_pray_message_server(f, header):
    class NetBabelPrayMessageServer(AutoRepr):
        pass

    message = NetBabelPrayMessageServer()
    try:
        p = f.tell()
        message.payload_length = read_uint32le(f)
        message.maybe_from_hid = read_uint16le(f)
        message.unknown3 = read_uint16le(f)
        message.maybe_from_id = read_uint32le(f)
        message.unknown5 = read_uint32le(f)
        message.unknown6 = read_uint32le(f)
        message.unknown7 = read_uint32le(f)
        message.unknown8 = read_uint32le(f)
        message.maybe_simple_message = read_uint32le(f)
        message.unknown10 = read_uint32le(f)

        # TODO: better way to distinguish this
        if f.peek(4) == b"PRAY":
            # if message.payload_length == 62893:
            #     print(f.read())
            #     raise NotEnoughData()
            r = bufreader(read_or_fail(f, message.payload_length - 36))
            message.pray = parse_pray(r)
        else:
            message.name_length = read_uint16le(f)
            if message.name_length > 400:
                f.seek(f.tell() - 2)
                print(f.read())
                assert False
            message.unknown11 = read_uint16le(f)

            message.name = read_or_fail(f, message.name_length)
            message.unknown11 = read_uint32le(f)
            message.unknown12 = read_uint32le(f)
            message.value_length = read_uint32le(f)
            message.value = read_or_fail(f, message.value_length)
            message.unknown13 = read_uint32le(f)
            message.unknown14 = read_uint32le(f)
        check_matches("payload length", f.tell() - p, message.payload_length)
        # check_matches("rest of data", f.read(), b"")
        return message
    finally:
        logging.debug(message)
        # remaining = f.read()
        # print(remaining)
        # print(len(remaining))


# NetBabel header
#       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
#      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 0000 |PackageType|       ECHO LOAD       |  User ID  |
#      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# 0020 | ??? | ??? | Pkg.Count |         ?????         |
#      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


class NetBabelHeader(AutoRepr):
    pass


def parse_netbabel_header(f):
    try:
        header = NetBabelHeader()
        header.package_type = read_uint32le(f)
        header.echo_load = list(read_or_fail(f, 8))
        header.user_id = read_uint32le(f)
        header.user_hid = read_uint16le(f)
        header.unknown2 = read_uint16le(f)
        warn_matches("NetBabelHeader.unknown2", header.unknown2, 0)
        header.pkg_count = read_uint32le(f)
        header.sometimes_payload_length = read_uint32le(f)
        header.unknown3 = read_uint32le(f)
        warn_matches("NetBabelHeader.unknown3", header.unknown3, 0)
        return header
    finally:
        # logging.debug(f"{header}")
        pass


# def parse_netbabel(r):
#     try:
#         header = NetBabelHeader()
#         header.package_type = read_uint32le(r)
#         header.echo_load = list(read_or_fail(r, 8))
#         header.user_id = read_uint32le(r)
#         header.unknown1 = read_uint16le(r)
#         warn_matches("NetBabelHeader.unknown1", header.unknown1, 0)
#         header.unknown2 = read_uint16le(r)
#         warn_matches("NetBabelHeader.unknown2", header.unknown2, 0)
#         header.pkg_count = read_uint32le(r)
#         header.unknown3 = read_or_fail(r, 8)
#         warn_matches(
#             "NetBabelHeader.unknown3",
#             header.unknown3,
#             b"\x00\x00\x00\x00\x00\x00\x00\x00",
#         )
#     finally:
#         logging.debug(f"{header}")
#
#     if header.package_type == 0x25:
#         parse_net_line_request(r, header)
#     elif header.package_type == 0xA:
#         parse_net_line_response(r, header)
#     elif header.package_type == 0xF:
#         parse_net_unik_request(r, header)
#     elif header.package_type == 0x10:
#         parse_netbabel_0x10(r, header)
#     else:
#         raise Exception(f"Unknown package type {hex(header.package_type)}")


ip_logger = logging.getLogger("ip")


def parse_ipv4_header_le(f):
    class IPv4Header(AutoRepr):
        pass

    try:
        header = IPv4Header()
        version_and_header_length = read_uint8(f)
        header.version = (version_and_header_length & 0xF0) >> 4
        if header.version != 4:
            raise Exception(f"IPv4 header has wrong version {header.version=}")
        header.header_length_quads = version_and_header_length & 0xF
        if header.header_length_quads < 5:
            raise Exception(
                f"IPv4 header_length was too small {header.header_length_quads=}"
            )
        if header.header_length_quads != 5:
            raise Exception(
                f"IPv4 header length >5 not implemented {header.header_length_quads=}"
            )
        header.dscp_and_ecn = read_uint8(f)
        header.total_length = read_uint16be(f)
        header.identification = read_uint16be(f)
        header.flags_and_fragment_offset = read_uint16be(f)
        header.ttl = read_uint8(f)
        header.protocol = read_uint8(f)
        header.header_checksum = read_uint16be(f)
        header.source_ipaddr = read_ipaddr_be(f)
        header.dest_ipaddr = read_ipaddr_be(f)

        return header

    finally:
        ip_logger.debug(f"{header}")


tcp_logger = logging.getLogger("tcp")


def parse_tcp_header_le(f):
    class TCPHeader(AutoRepr):
        pass

    try:
        header = TCPHeader()
        header.source_port = read_uint16be(f)
        header.dest_port = read_uint16be(f)
        header.sequence_number = read_uint32be(f)
        header.ack_number = read_uint32be(f)

        data_offset_and_reserved = read_uint8(f)
        header.data_offset_quads = (data_offset_and_reserved & 0xF0) >> 4
        header.reserved = data_offset_and_reserved & 0xF
        if header.data_offset_quads < 5:
            raise Exception(
                f"TCP data offset was too small {header.data_offset_quads=}"
            )
        # if header.data_offset_quads != 5:
        #     raise Exception(f"TCP data offset >5 not implemented {header.data_offset_quads=}")

        header.flags = read_uint8(f)
        header.window_size = read_uint16be(f)
        header.checksum = read_uint16be(f)
        header.urgent_pointer = read_uint16be(f)
        if header.data_offset_quads > 5:
            header.extra = read_or_fail(f, (header.data_offset_quads - 5) * 4)

        return header
    finally:
        tcp_logger.debug(f"{header}")


PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_BE_NANOSECOND = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_LE_NANOSECOND = b"\x4d\x3c\xb2\xa1"
PCAP_LINKLAYER_ETHERNET = 1
ETHERTYPE_IP = 8
ETHERTYPE_ARP = 0x608
IPPROTO_TCP = 6
IPPROTO_UDP = 17


pcap_logger = logging.getLogger("pcap")


class PcapHeader(AutoRepr):
    pass


def parse_pcapheader_le(f):
    try:
        header = PcapHeader()
        header.magic = read_or_fail(f, 4)
        check_matches("magic", header.magic, PCAP_MAGIC_LE)
        header.version_major = read_uint16le(f)
        header.version_minor = read_uint16le(f)
        header.timezone_correction_seconds = read_sint32le(f)
        header.sigfigs = read_uint32le(f)
        header.max_length_packets = read_uint32le(f)
        header.link_layer_type = read_uint32le(f)
        return header
    finally:
        pcap_logger.debug(f"{header}")


class PcapPacketHeader(AutoRepr):
    pass


def parse_pcap_packetheader_le(f):
    try:
        header = PcapPacketHeader()
        header.ts_sec = datetime.datetime.fromtimestamp(read_uint32le(f))
        header.ts_usec = read_uint32le(f)
        header.timestamp = header.ts_sec + datetime.timedelta(
            microseconds=header.ts_usec
        )
        header.incl_len = read_uint32le(f)
        header.orig_len = read_uint32le(f)

        return header
    finally:
        pcap_logger.debug(f"{header}")


def peek_pcap_header(f):
    return peek_exact(f, 4) in (
        PCAP_MAGIC_BE,
        PCAP_MAGIC_BE_NANOSECOND,
        PCAP_MAGIC_LE_NANOSECOND,
        PCAP_MAGIC_LE,
    )


class PcapReader:
    def __init__(self, f):
        if peek_exact(f, 4) == PCAP_MAGIC_BE:
            raise Exception("Big-endian Pcap file")
        elif peek_exact(f, 4) == PCAP_MAGIC_BE_NANOSECOND:
            raise Exception("Big-endian Pcap file with nanosecond resolution")
        elif peek_exact(f, 4) == PCAP_MAGIC_LE_NANOSECOND:
            raise Exception("Little-endian Pcap file with nanosecond resolution")
        elif peek_exact(f, 4) == PCAP_MAGIC_LE:
            self.pcap_header = parse_pcapheader_le(f)
        else:
            raise Exception("Not a valid Pcap-format stream")

        if self.pcap_header.link_layer_type != PCAP_LINKLAYER_ETHERNET:
            raise NotImplementedError(f"{self.pcap_header.link_layer_type=}")

        self._f = f

    def __iter__(self):
        while self._f.peek():
            pcap_packet = parse_pcap_packetheader_le(self._f)

            if pcap_packet.incl_len != pcap_packet.orig_len:
                # logging.error(
                #     f"Pcap packet header different lengths unsupported {pcap_packet=}"
                # )
                # logging.error("Data: %r", read_or_fail(self._f, pcap_packet.orig_len))
                # continue
                raise Exception(
                    f"Pcap packet header different lengths unsupported {pcap_packet=}"
                )
            # read_or_fail(self._f)

            p = self._f.tell()
            ethernet = parse_ethernetheader_le(self._f)
            if ethernet.packet_type == ETHERTYPE_ARP:
                logging.error(f"Skipping ARP packet {pcap_packet=} {ethernet=}")
                logging.error(
                    "data after Ethernet packet: %r",
                    read_or_fail(self._f, pcap_packet.incl_len - (self._f.tell() - p)),
                )
                continue
            if ethernet.packet_type != ETHERTYPE_IP:
                raise NotImplementedError(f"{ethernet.packet_type=}")
            ipv4 = parse_ipv4_header_le(self._f)
            if ipv4.protocol == IPPROTO_UDP:
                logging.error(f"Skipping UDP packet {pcap_packet=} {ethernet=} {ipv4=}")
                logging.error(
                    "data after IPv4 packet: %r",
                    read_or_fail(self._f, pcap_packet.incl_len - (self._f.tell() - p)),
                )
                continue
            if ipv4.protocol != IPPROTO_TCP:
                logging.error(f"{pcap_packet=} {ethernet=} {ipv4=}")
                raise NotImplementedError(f"{ipv4.protocol=}")
            if ipv4.total_length != pcap_packet.incl_len - 14:
                logging.error(
                    f"uh oh. lengths incorrect: {pcap_packet.incl_len=} {ipv4.total_length=} {pcap_packet=} {ipv4=}"
                )
                tcp = parse_tcp_header_le(self._f)
                logging.error(f"{tcp=}")
                logging.error(
                    "data after TCP packet: %r",
                    read_or_fail(self._f, pcap_packet.incl_len - (self._f.tell() - p)),
                )
                continue
            tcp = parse_tcp_header_le(self._f)

            yield (
                pcap_packet,
                ethernet,
                ipv4,
                tcp,
                read_or_fail(self._f, pcap_packet.incl_len - (self._f.tell() - p)),
            )


def read_etheraddr_le(f):
    buf = read_or_fail(f, 6)
    return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*buf).encode("ascii")


ethernet_logger = logging.getLogger("ethernet")


def parse_ethernetheader_le(f):
    class EthernetHeader(AutoRepr):
        pass

    try:
        header = EthernetHeader()
        header.dest_host = read_etheraddr_le(f)
        header.src_host = read_etheraddr_le(f)
        header.packet_type = read_uint16le(f)
        return header
    finally:
        ethernet_logger.debug(f"{header}")


def length_common_prefix(s1, s2):
    for i in range(min(len(s1), len(s2))):
        if s1[i] != s2[i]:
            return i
    return min(len(s1), len(s2))


class PcapJoiner:
    def __init__(self, pcap):
        self._pcap = iter(pcap)

    def __iter__(self):
        return self

    def __next__(self):
        packets = []
        packets.append(next(self._pcap))

        source = (packets[0][2].source_ipaddr, packets[0][3].source_port)
        dest = (packets[0][2].dest_ipaddr, packets[0][3].dest_port)

        while True:
            try:
                peeked = next(self._pcap)
            except StopIteration:
                break
            if len(peeked[4]) == 0:
                # sometimes packets are empty???
                continue
            if (peeked[2].source_ipaddr, peeked[3].source_port) == source and (
                peeked[2].dest_ipaddr,
                peeked[3].dest_port,
            ) == dest:
                packets.append(peeked)
            else:
                self._pcap = itertools.chain([peeked], self._pcap)
                break

        # TCP packets must be in order
        packets = sorted(packets, key=lambda p: p[3].sequence_number)
        timestamp = packets[0][0].timestamp
        data = b""

        # TCP packets can be duplicated
        i = 0
        while i < len(packets):
            if (
                i > 0
                and packets[i][3].sequence_number == packets[i - 1][3].sequence_number
            ):
                # TCP packets can be duplicated, and the second packet can have additional data???
                # not supposed to happen but deal with it
                newdata = packets[i][4]
                olddata = packets[i - 1][4]
                if newdata != olddata:
                    prefixsize = length_common_prefix(newdata, olddata)
                    assert prefixsize in (len(newdata), len(olddata))
                    if len(newdata) > prefixsize:
                        packets[i - 1] = (
                            packets[i - 1][0],
                            packets[i - 1][1],
                            packets[i - 1][2],
                            packets[i - 1][3],
                            newdata,
                        )
                del packets[i]
            else:
                i += 1

        for (_, _, _, _, buf) in packets:
            data += buf

        return (timestamp, source, dest, data)


def main():
    filenames = sys.argv[1:]
    if not filenames:
        sys.stderr.write(f"USAGE: {sys.argv[0]} files...")
        exit(1)

    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(funcName)s: %(message)s",
        level=logging.DEBUG,
    )
    pcap_logger.setLevel(logging.WARNING)
    ethernet_logger.setLevel(logging.WARNING)
    ip_logger.setLevel(logging.WARNING)
    tcp_logger.setLevel(logging.WARNING)

    for fname in filenames:
        print(fname)
        with open(fname, "rb") as f:
            num_zlib_errors = 0
            if peek_pcap_header(f):
                pcap = PcapReader(f)
                joiner = PcapJoiner(pcap)
                initialized = False
                for (timestamp, source, dest, data) in joiner:
                    if not initialized:
                        # TODO: meh?
                        if dest[1] == 49152:
                            server = dest
                            client = source
                        elif source[1] == 49152:
                            server = source
                            client = dest
                        initialized = True

                    logging.info(f"{timestamp=} {source=} {dest=} {len(data)=}")

                    r = bufreader(data)

                    try:
                        while r.peek():

                            header = parse_netbabel_header(r)
                            logging.info(header)

                            if source == client:
                                if header.package_type == 0x9:
                                    parse_pray_message_client(r, header)
                                elif header.package_type == 0xF:
                                    parse_net_unik_request(r, header)
                                elif header.package_type == 0x10:
                                    parse_netbabel_0x10_request(r, header)
                                elif header.package_type == 0x13:
                                    parse_net_ulin_request(r, header)
                                elif header.package_type == 0x18:
                                    parse_net_stat_request(r, header)
                                elif header.package_type == 0x25:
                                    parse_net_line_request(r, header)
                                elif header.package_type == 0x221:
                                    parse_net_ruso_request(r, header)
                                elif header.package_type == 0x321:
                                    parse_netbabel_0x321_client(r, header)
                                else:
                                    print(r.read()[0:256])
                                    raise Exception(
                                        f"Unknown package type {hex(header.package_type)}"
                                    )
                            elif source == server:
                                if header.package_type == 0x9:
                                    parse_pray_message_server(r, header)
                                elif header.package_type == 0xA:
                                    parse_net_line_response(r, header)
                                elif header.package_type == 0xD:
                                    parse_netbabel_0xd_server(r, header)
                                elif header.package_type == 0xE:
                                    parse_netbabel_0xe_server(r, header)
                                elif header.package_type == 0xF:
                                    parse_net_unik_response(r, header)
                                elif header.package_type == 0x13:
                                    parse_net_ulin_response(r, header)
                                elif header.package_type == 0x18:
                                    parse_net_stat_response(r, header)
                                elif header.package_type == 0x221:
                                    parse_net_ruso_response(r, header)
                                elif header.package_type == 0x321:
                                    parse_netbabel_0x321_server(r, header)
                                elif header.package_type in (0x172AC548, 0x19EA518):
                                    raise NotEnoughData(
                                        "Bad package type, assuming from previous notenoughdata error"
                                    )
                                else:
                                    print(r.read()[0:256])
                                    raise Exception(
                                        f"Unknown package type {hex(header.package_type)}"
                                    )
                            else:
                                assert False

                            print("")
                    except NotEnoughData as e:
                        logging.error("NotEnoughData: %r", e)
                        pass
                    except:
                        print(f.read()[:256])
                        raise

            # if header.package_type == 0x25:
            #     parse_net_line_request(r, header)
            # elif header.package_type == 0xA:
            #     parse_net_line_response(r, header)
            # elif header.package_type == 0xF:
            #     parse_net_unik_request(r, header)
            # elif header.package_type == 0x10:
            #     parse_netbabel_0x10(r, header)
            # else:
            #     raise Exception(f"Unknown package type {hex(header.package_type)}")

            # if not client_ipaddr:
            #     client_ipaddr
            # print(ip.source_ipaddr, ip.dest_ipaddr)
            # print(f"{pcap=} {ether=} {ip=} {tcp=} {data=}")


if __name__ == "__main__":
    main()
