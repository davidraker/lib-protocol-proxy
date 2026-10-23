import json
import logging
import os
import time
import zlib

from abc import abstractmethod, ABC, ABCMeta
from collections.abc import Generator
from dataclasses import dataclass
from itertools import cycle
from psutil import net_connections
from typing import Any, Awaitable, Callable, ClassVar, NamedTuple
from uuid import UUID

from . import callback, HeadersV1, HeadersV2, ProtocolHeaders
from .. import tls as _tls

_log = logging.getLogger(__name__)


class ProtocolProxyCallback(NamedTuple):
    method: Callable
    name: str
    provides_response: bool
    timeout: float


@dataclass
class ProtocolProxyMessage:
    method_name: str
    payload:  bytes | Awaitable[bytes] | Callable[[any], bytes]
    request_id: int = None
    response_expected: bool = False
    #: The remote this message concerns (see HeadersV2); the receiver dispatches on it when a callback is registered
    #: for it.
    remote_id: UUID | None = None
    #: Header version to send. Version 2 is the default for every message; 1 is for a peer that predates it.
    protocol_version: int = 2
    #: On a persistent connection, written only when no ordinary frame is waiting to be written (LOG batches), so
    #: logging never delays protocol traffic.
    low_priority: bool = False


class SocketParams(NamedTuple):
    address: str = 'localhost'
    port: int = 22801

    def __repr__(self):
        return f'{self.address}:{self.port}'


@dataclass(kw_only=True)
class ProtocolProxyPeer(ABC):
    """ Represents a known remote system.
            NOTE: Subclasses should implement concrete versions of:
             - a "process" field to represent the remote process.
             - a "ready" lock to indicate when the peer is ready for communication.
    """
    process: Any
    proxy_id: UUID
    ready: Any
    token: UUID
    socket_params: SocketParams = None
    #: Where this side dials the peer when that differs from what the peer advertised (a proxy that cannot be
    #: reached at its own address, or that the manager must dial because the proxy cannot dial the manager).
    dial_params: SocketParams = None
    #: The peer's proxy name (what the manager launched it as); the manager logs its records under it.
    name: str | None = None
    #: Connection lifetime toward this peer: True keeps one connection open for every frame in both directions,
    #: False dials a connection per message, None uses the connector's default (``IPCConnector.persistent``).
    persistent: bool | None = None
    #: The open persistent connection to this peer, if any: one this side dialled, or one the peer dialled and this
    #: side adopted when a frame arrived on it with the keep-alive bit set.
    connection: Any = None
    #: What the peer advertised in REGISTER_PEER (``ping``, ``log``, ``set_log_level``, ...).
    features: tuple = ()
    #: Connections with this peer are TLS (mutually authenticated against the manager's CA, see protocol_proxy.tls).
    tls: bool = False
    #: The 32-byte AEAD key shared with this peer, or None for clear text. Fixed for the peer's lifetime: every frame
    #: between two peers that share a key is encrypted, and a clear-text frame from such a peer is refused.
    key: bytes | None = None
    #: Liveness as the manager sees it: launching, registered, healthy, unhealthy (missed heartbeats), lost.
    state: str = 'launching'
    last_seen: float | None = None      # time.time() of the last frame or heartbeat reply from this peer
    missed: int = 0                     # consecutive heartbeats without a reply
    health: dict | None = None          # the peer's last PING reply (uptime, remotes, busy, last_activity)

    def mark_registered(self):
        """Called by the manager once this peer's address is known; a subclass may wake waiters here."""
        self.state = 'registered'
        self.last_seen = time.time()


class IPCConnector(metaclass=ABCMeta):
    PROTOCOL_VERSION = {1: HeadersV1, 2: HeadersV2}

    #: Frames larger than this (header and payload) take a dedicated per-message connection even toward a persistent
    #: peer, so a multi-megabyte registration or profile does not hold every other frame behind it.
    PERSISTENT_MAX_FRAME = 256 * 1024
    #: Payloads larger than this are zlib-compressed toward a peer that advertised ``compress``.
    COMPRESS_THRESHOLD = 4096
    #: What this connector tells its peers it understands (proxies in REGISTER_PEER, the manager in its reply).
    FEATURES: ClassVar[tuple[str, ...]] = ('compress', 'aead-chacha20poly1305')
    KEY_BYTES = 32
    NONCE_BYTES = 12
    TAG_BYTES = 16

    def __init__(self, *, proxy_id: UUID, token: UUID, proxy_name: str = None, inbound_params: SocketParams = None,
                 chunk_size: int = 1024, encrypt: bool = False, min_port: int = 22801, max_port: int = 22899,
                 persistent: bool = False, persistent_max_frame: int | None = PERSISTENT_MAX_FRAME,
                 compress_threshold: int | None = COMPRESS_THRESHOLD, tls_material: '_tls.TlsMaterial | None' = None,
                 **kwargs):
        """ Handles socket communication between ProtocolProxy and ProtocolProxyManager.

        Connection lifetime is a policy per peer (``ProtocolProxyPeer.persistent``), defaulting to ``persistent``
        here: per message (dial, one frame, its reply, close) or persistent (one connection per peer carrying frames
        in both directions, matched by request id, redialled on demand after a loss). A receiver reads frames until
        the sender closes, so either policy works against either peer; a frame whose header carries the keep-alive
        bit tells the receiver it may send back on that connection, which is how a peer without a reachable address
        (a proxy behind NAT that dialled in) is reached.
         TODO: Mechanism for polling communication with remote (where push is not possible)?
         TODO: Implement encryption.
        """
        self.chunk_size: int = chunk_size
        self.encrypt: bool = encrypt
        self.persistent: bool = persistent
        self.persistent_max_frame: int | None = persistent_max_frame
        self.compress_threshold: int | None = compress_threshold
        # Our certificate, key and CA for TLS connections (None: this end has no TLS identity). Contexts are built
        # lazily; a flavour may use a cooperative SSLContext class (gevent).
        self.tls_material: _tls.TlsMaterial | None = tls_material
        self._tls_contexts: dict[str, Any] = {}
        self.inbound_params = inbound_params
        self.min_port: int = min_port
        self.max_port: int = max_port
        self.proxy_id = proxy_id
        self.proxy_name = proxy_name if proxy_name else str(self.proxy_id)
        self.token = token

        self.started_at: float = time.time()
        self.last_activity: float | None = None     # when the last frame was received
        self.callbacks: dict[str, ProtocolProxyCallback] = {}
        # Callbacks for one remote: (method_name, remote_id). Looked up first; self.callbacks is the fallback.
        self.remote_callbacks: dict[tuple[str, UUID], ProtocolProxyCallback] = {}
        self.peers: dict[UUID, ProtocolProxyPeer] = {}
        self.register_callback(self._handle_response, 'RESPONSE')
        # Request ids are drawn per header version: 16 bits for version 1 peers, 32 bits from version 2.
        self._request_ids = {version: cycle(range(1, protocol.REQUEST_ID_MAX))
                             for version, protocol in self.PROTOCOL_VERSION.items()}

    @abstractmethod
    def _get_ip_addresses(self, host_name: str) -> set[str]:
        pass

    @abstractmethod
    @callback
    def _handle_response(self, headers: ProtocolHeaders, raw_message: bytes):
        pass

    @abstractmethod
    def send(self, remote: ProtocolProxyPeer, message: ProtocolProxyMessage):
        """Send a message to the remote and return a bool, AsyncResult (gevent) or Future (asyncio)."""
        pass

    @abstractmethod
    def _setup_inbound_server(self, socket_params: SocketParams = None):
        pass

    def unused_ports(self, address_info: set[str]) -> Generator[int]:
        used_ports = {nc.laddr.port for nc in net_connections() if
                      nc.laddr.ip in address_info}
        next_port = self.min_port
        for p in range(next_port, self.max_port + 1):
            if p not in used_ports:
                yield p

    def encode_payload(self, remote: ProtocolProxyPeer | None, payload: bytes) -> tuple[bytes, bool]:
        """The payload as it goes on the wire toward ``remote`` and whether it was compressed: zlib when the peer
        advertised ``compress`` and the payload exceeds the threshold (nothing is compressed toward a peer whose
        features are unknown, e.g. before its registration)."""
        if (remote is not None and self.compress_threshold is not None and 'compress' in remote.features
                and len(payload) > self.compress_threshold):
            return zlib.compress(payload), True
        return payload, False

    @staticmethod
    def decode_payload(headers: ProtocolHeaders, payload) -> bytes:
        """The payload as sent: decompressed when the header says so. Raises zlib.error on corrupt data."""
        if getattr(headers, 'compressed', False):
            return zlib.decompress(payload)
        return payload

    @staticmethod
    def _aead(key: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError as e:    # pragma: no cover - cryptography is a dependency
            raise RuntimeError('Encrypted IPC needs the "cryptography" package.') from e
        return ChaCha20Poly1305(key)

    @classmethod
    def new_key(cls) -> bytes:
        return os.urandom(cls.KEY_BYTES)

    def seal(self, remote: ProtocolProxyPeer | None, payload: bytes, pack_header: Callable[[int, bool, bool], bytes]) -> bytes:
        """The wire frame of ``payload`` toward ``remote``: compressed when the peer takes it, then encrypted when a
        key is shared with it. ``pack_header(data_length, compressed, encrypted)`` returns the header bytes (version
        word included); for an encrypted frame those bytes are the associated data, so the method name, request id,
        sender, remote and flags cannot be altered or moved onto another message without detection."""
        payload, compressed = self.encode_payload(remote, payload)
        key = remote.key if remote is not None else None
        if key is None:
            return pack_header(len(payload), compressed, False) + payload
        header = pack_header(len(payload) + self.NONCE_BYTES + self.TAG_BYTES, compressed, True)
        nonce = os.urandom(self.NONCE_BYTES)
        return header + nonce + self._aead(key).encrypt(nonce, payload, header)

    def open_frame(self, headers: ProtocolHeaders, raw_header: bytes, payload: bytes) -> bytes:
        """The payload as the sender had it: decrypted (and authenticated against ``raw_header``) when the frame is
        encrypted, then decompressed. Refuses a clear-text frame from a peer this side shares a key with, and an
        encrypted frame from one it does not (``PermissionError``); a forged or corrupted frame fails authentication
        (``cryptography.exceptions.InvalidTag``)."""
        peer = self.peers.get(getattr(headers, 'sender_id', None))
        key = peer.key if peer is not None else None
        if getattr(headers, 'encrypted', False):
            if key is None:
                raise PermissionError(f'encrypted {headers.method_name} from {headers.sender_id}, with whom no key is shared')
            if len(payload) < self.NONCE_BYTES + self.TAG_BYTES:
                raise PermissionError(f'encrypted {headers.method_name} from {headers.sender_id} is too short')
            nonce, body = bytes(payload[:self.NONCE_BYTES]), bytes(payload[self.NONCE_BYTES:])
            payload = self._aead(key).decrypt(nonce, body, bytes(raw_header))
        elif key is not None:
            raise PermissionError(f'clear-text {headers.method_name} from {headers.sender_id}, who must encrypt')
        return self.decode_payload(headers, payload)

    SSL_CONTEXT_CLASS = None        # a flavour may substitute a cooperative ssl.SSLContext subclass

    def tls_context(self, purpose: str):
        """The ``server`` or ``client`` TLS context for this end, or None without TLS material."""
        if self.tls_material is None:
            return None
        if purpose not in self._tls_contexts:
            factory = _tls.server_context if purpose == 'server' else _tls.client_context
            kwargs = {'context_class': self.SSL_CONTEXT_CLASS} if self.SSL_CONTEXT_CLASS is not None else {}
            self._tls_contexts[purpose] = factory(self.tls_material, **kwargs)
        return self._tls_contexts[purpose]

    def frame_identity_ok(self, headers: ProtocolHeaders, tls_peer: str | None) -> bool:
        """A frame is accepted only if its transport identity matches its claimed identity: over TLS the sender id must
        be the certificate's common name; a peer marked TLS must not arrive in the clear."""
        sender = getattr(headers, 'sender_id', None)
        if tls_peer is not None:
            if sender is None or sender.hex != tls_peer:
                _log.warning(f'{self.proxy_name}: frame from {sender} over a TLS connection authenticated as {tls_peer}; dropped.')
                return False
            return True
        peer = self.peers.get(sender)
        if peer is not None and peer.tls:
            _log.warning(f'{self.proxy_name}: clear-text frame from {sender}, who must use TLS; dropped.')
            return False
        return True

    def is_persistent(self, remote: ProtocolProxyPeer) -> bool:
        """Whether new connections toward this peer are kept open (the peer's own policy, else this connector's)."""
        return self.persistent if remote.persistent is None else remote.persistent

    def _fail_pending(self, request_ids, error: Exception):
        """Fail the awaited results of requests whose connection was lost; callers see ``error`` instead of waiting
        out their timeout. Flavours implement ``_fail_result`` for their result type."""
        for request_id in list(request_ids):
            if (result := self.response_results.get(request_id)) is not None:
                self._fail_result(result, error)

    def _fail_result(self, result, error: Exception):
        raise NotImplementedError

    @staticmethod
    def error_payload(method_name: str, error: str) -> bytes:
        """The JSON error reply both connectors send when a request cannot be answered properly."""
        return json.dumps({'status': 'error', 'error': error, 'method': method_name}).encode('utf8')

    def unanswerable(self, headers: ProtocolHeaders, cb_info: ProtocolProxyCallback | None) -> bytes | None:
        """When a request expects a response that no handler will give (unknown method, or a handler registered
        without one), the error reply to send instead, so the caller fails at once rather than waiting out its
        timeout. None when nothing is owed."""
        if not getattr(headers, 'response_expected', False):
            return None
        if cb_info is None:
            return self.error_payload(headers.method_name, f'Unknown method {headers.method_name}')
        if not cb_info.provides_response:
            return self.error_payload(headers.method_name, f'Method {headers.method_name} provides no response')
        return None

    @property
    def next_request_id(self):
        """The next request id for the default (version 2) header."""
        return self.request_id_for(ProtocolProxyMessage.protocol_version)

    def request_id_for(self, protocol_version: int) -> int:
        """The next request id that fits the given header version."""
        try:
            return next(self._request_ids[protocol_version])
        except KeyError:
            raise NotImplementedError(f'Unknown proxy protocol version: {protocol_version}') from None

    def register_callback(self, cb_method, method_name, provides_response=False, timeout=30.0,
                          remote_id: UUID | None = None):
        """Register the handler for ``method_name``.

        Without a ``remote_id`` the first registration wins and later ones are confirmations, so a handler shared by
        many callers must not depend on which of them registered it. With a ``remote_id`` the handler serves messages
        tagged with that remote (HeadersV2) and replaces any earlier handler for the same pair.
        """
        if remote_id is not None:
            self.remote_callbacks[(method_name, remote_id)] = ProtocolProxyCallback(cb_method, method_name,
                                                                                     provides_response, timeout=timeout)
            _log.info(f'{self.proxy_name} registered callback: {method_name} for remote {remote_id}')
        elif not self.callbacks.get(method_name):
            _log.info(f'{self.proxy_name} registered callback: {method_name}')
            self.callbacks[method_name] = ProtocolProxyCallback(cb_method, method_name, provides_response,
                                                                timeout=timeout)
        else:
            _log.info(f'{self.proxy_name} confirmed callback: {method_name} is registered.')

    def unregister_callback(self, method_name, remote_id: UUID | None = None) -> bool:
        """Remove a handler; returns whether one was registered."""
        if remote_id is not None:
            return self.remote_callbacks.pop((method_name, remote_id), None) is not None
        return self.callbacks.pop(method_name, None) is not None

    def find_callback(self, headers: ProtocolHeaders) -> ProtocolProxyCallback | None:
        """The handler for a received message: the remote's own if the message names one it has, else the method's.
        Called for every frame received, so it also records the last activity on this connector and from the sender."""
        self.last_activity = time.time()
        if (peer := self.peers.get(getattr(headers, 'sender_id', None))) is not None:
            peer.last_seen = self.last_activity
        remote_id = getattr(headers, 'remote_id', None)
        if remote_id is not None and (cb_info := self.remote_callbacks.get((headers.method_name, remote_id))):
            return cb_info
        return self.callbacks.get(headers.method_name)

    @abstractmethod
    def start(self, *_, **__):
        pass

    @abstractmethod
    def stop(self):
        pass
