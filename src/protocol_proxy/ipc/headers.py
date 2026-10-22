import logging
import struct

from abc import abstractmethod, ABCMeta
from uuid import UUID

_log = logging.getLogger(__name__)


class ProtocolHeaders(metaclass=ABCMeta):
    #  The endian_indicator and version number are added where needed and not included in the portion of the format here.
    FORMAT = 'Q32sH16s16s'
    HEADER_LENGTH = struct.calcsize(FORMAT)
    VERSION = 0                                     # 2 byte (16 bit) integer (H)
    #: Largest request id the version's header field holds (16 bits before version 2, 32 bits from version 2).
    REQUEST_ID_MAX = 0xFFFF
    #: Which remote (device, outstation, server...) a message concerns; versions before 2 carry none.
    remote_id: UUID | None = None

    @abstractmethod
    def __init__(self, data_length: int, method_name: str, request_id: int, sender_id, sender_token, **kwargs):
        if kwargs:
            _log.warning(f'Received extra kwargs for Proxy Protocol version {self.VERSION}: {list(kwargs.keys())}')
        self.data_length: int = data_length         # 8 byte (64 bit) integer (Q)
        self.method_name: str = method_name         # 32-byte (32 character) string (32s)
        self.request_id: int = request_id           #  2-byte (16 bit) integer (H)
        self.sender_id = sender_id                  # 16-byte UUID (16s)
        self.sender_token = sender_token            # 16-byte UUID (16s)
        # TODO: The token, and possibly sender_id should be an actual encrypted token based on those values, not plain text.

    @staticmethod
    def bitflag_is_set(bit_position, byte_value):
        return bool((byte_value & (1 << bit_position)) >> bit_position)

    def _check_request_id(self):
        if not 0 <= self.request_id <= self.REQUEST_ID_MAX:
            raise ValueError(f'Request id {self.request_id} does not fit the version {self.VERSION} header'
                             f' (maximum {self.REQUEST_ID_MAX}).')

    @abstractmethod
    def pack(self):
        # TODO: The sender_id is currently the proxy_id, which is a tuple. This should probably become a UUID?
        #  (Need to figure out how/where to map one to the other.)
        self._check_request_id()
        return struct.pack(f'>H{ProtocolHeaders.FORMAT}', self.VERSION, self.data_length,
                           self.method_name.encode('utf8'), self.request_id, self.sender_id.bytes,
                           self.sender_token.bytes)

    @abstractmethod
    def unpack(self, header_bytes):
        pass

    def __repr__(self):
        return f'ProtocolHeaders(FORMAT={self.FORMAT}, VERSION={self.VERSION},' \
               f'data_length={self.data_length}, method_name={self.method_name},' \
               f' request_id={self.request_id}, sender_id={self.sender_id}, sender_token={self.sender_token}'


class HeadersV1(ProtocolHeaders):
    FORMAT = ProtocolHeaders.FORMAT + 'H'
    HEADER_LENGTH = struct.calcsize(FORMAT)  # TODO: Should we make this a property instead?
    #: bitflags: bit 0 response expected; bits 1 and 2 are reserved for compression and encryption; bit 3 keep-alive.
    RESPONSE_EXPECTED_BIT = 0
    COMPRESSED_BIT = 1
    KEEP_ALIVE_BIT = 3
    VERSION = 1

    def __init__(self, data_length: int, method_name: str, request_id: int, sender_id, sender_token,
                 response_expected: bool = False, keep_alive: bool = False, compressed: bool = False, **kwargs):
        super(HeadersV1, self).__init__(data_length, method_name, request_id, sender_id, sender_token, **kwargs)
        self.response_expected: bool = response_expected  # Position 0 in bitflags within struct.
        # The payload is zlib-compressed (data_length counts the compressed bytes).
        self.compressed: bool = compressed
        # The sender keeps this connection open for further frames in both directions (a persistent connection); the
        # receiver may send to the authenticated sender on it instead of dialling the sender's advertised address.
        self.keep_alive: bool = keep_alive

    def _bitflags(self) -> int:
        return ((int(self.response_expected) << self.RESPONSE_EXPECTED_BIT)
                | (int(self.compressed) << self.COMPRESSED_BIT)
                | (int(self.keep_alive) << self.KEEP_ALIVE_BIT))

    def pack(self):
        return super(HeadersV1, self).pack() + struct.pack(f'>H', self._bitflags())    # 2 byte (16-bit) bitflags.

    @classmethod
    def unpack(cls, header_bytes):
        (data_length, method_bytes, request_id, sender_id_bytes, sender_token_bytes,
         bitflags) = struct.unpack('>' + cls.FORMAT, header_bytes)
        method = method_bytes.rstrip(b'\x00').decode('utf8')
        return cls(data_length, method, request_id, UUID(bytes=sender_id_bytes), UUID(bytes=sender_token_bytes),
                   cls.bitflag_is_set(cls.RESPONSE_EXPECTED_BIT, bitflags),
                   keep_alive=cls.bitflag_is_set(cls.KEEP_ALIVE_BIT, bitflags),
                   compressed=cls.bitflag_is_set(cls.COMPRESSED_BIT, bitflags))


class HeadersV2(HeadersV1):
    """Version 1 with a 32-bit request id and a 16-byte remote id (all zeros when absent).

    A proxy process serves many remotes, so the sender id alone cannot say which remote a pushed message concerns.
    The remote id is the identifier the caller gave the proxy when it registered the remote; the receiving connector
    dispatches on ``(method_name, remote_id)`` and falls back to the method-only callback. The request id is widened
    from 16 to 32 bits so that a persistent, multiplexed connection cannot wrap it within a session. Version 2 is the
    default for every message (``ProtocolProxyMessage.protocol_version``); receivers still accept version 1.

    Layout after the 2-byte version word: data_length Q, method_name 32s, request_id I, sender_id 16s,
    sender_token 16s, bitflags H, remote_id 16s (94 bytes).
    """
    FORMAT = 'Q32sI16s16sH16s'
    HEADER_LENGTH = struct.calcsize(FORMAT)
    VERSION = 2
    REQUEST_ID_MAX = 0xFFFFFFFF
    NO_REMOTE = bytes(16)

    def __init__(self, data_length: int, method_name: str, request_id: int, sender_id, sender_token,
                 response_expected: bool = False, remote_id: UUID | None = None, **kwargs):
        super(HeadersV2, self).__init__(data_length, method_name, request_id, sender_id, sender_token,
                                        response_expected, **kwargs)
        self.remote_id: UUID | None = remote_id

    def pack(self):
        self._check_request_id()
        return struct.pack(f'>H{self.FORMAT}', self.VERSION, self.data_length, self.method_name.encode('utf8'),
                           self.request_id, self.sender_id.bytes, self.sender_token.bytes, self._bitflags(),
                           self.remote_id.bytes if self.remote_id else self.NO_REMOTE)

    @classmethod
    def unpack(cls, header_bytes):
        (data_length, method_bytes, request_id, sender_id_bytes, sender_token_bytes, bitflags,
         remote_id_bytes) = struct.unpack('>' + cls.FORMAT, header_bytes)
        method = method_bytes.rstrip(b'\x00').decode('utf8')
        remote_id = None if remote_id_bytes == cls.NO_REMOTE else UUID(bytes=remote_id_bytes)
        return cls(data_length, method, request_id, UUID(bytes=sender_id_bytes), UUID(bytes=sender_token_bytes),
                   cls.bitflag_is_set(cls.RESPONSE_EXPECTED_BIT, bitflags), remote_id,
                   keep_alive=cls.bitflag_is_set(cls.KEEP_ALIVE_BIT, bitflags),
                   compressed=cls.bitflag_is_set(cls.COMPRESSED_BIT, bitflags))

    def __repr__(self):
        return super(HeadersV2, self).__repr__() + f', remote_id={self.remote_id}, keep_alive={self.keep_alive}, compressed={self.compressed}'
