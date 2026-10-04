import logging

from abc import abstractmethod, ABC, ABCMeta
from collections.abc import Generator
from dataclasses import dataclass
from itertools import cycle
from psutil import net_connections
from typing import Any, Awaitable, Callable, NamedTuple
from uuid import UUID

from . import callback, HeadersV1, HeadersV2, ProtocolHeaders

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
    #: for it. None sends a version 1 header.
    remote_id: UUID | None = None

    @property
    def protocol_version(self) -> int:
        return 2 if self.remote_id is not None else 1


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


class IPCConnector(metaclass=ABCMeta):
    PROTOCOL_VERSION = {1: HeadersV1, 2: HeadersV2}

    def __init__(self, *, proxy_id: UUID, token: UUID, proxy_name: str = None, inbound_params: SocketParams = None,
                 chunk_size: int = 1024, encrypt: bool = False, min_port: int = 22801, max_port: int = 22899,
                 **kwargs):
        """ Handles socket communication between ProtocolProxy and ProtocolProxyManager.
         TODO: Mechanism for polling communication with remote (where push is not possible)?
         TODO: Implement encryption.
        """
        self.chunk_size: int = chunk_size
        self.encrypt: bool = encrypt
        self.inbound_params = inbound_params
        self.min_port: int = min_port
        self.max_port: int = max_port
        self.proxy_id = proxy_id
        self.proxy_name = proxy_name if proxy_name else str(self.proxy_id)
        self.token = token

        self.callbacks: dict[str, ProtocolProxyCallback] = {}
        # Callbacks for one remote: (method_name, remote_id). Looked up first; self.callbacks is the fallback.
        self.remote_callbacks: dict[tuple[str, UUID], ProtocolProxyCallback] = {}
        self.peers: dict[UUID, ProtocolProxyPeer] = {}
        self.register_callback(self._handle_response, 'RESPONSE')
        self._request_id = cycle(range(1, 65535))

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

    @property
    def next_request_id(self):
        return next(self._request_id)

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
        """The handler for a received message: the remote's own if the message names one it has, else the method's."""
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
