import json
import logging
import struct

from dataclasses import dataclass, field
from gevent import sleep, spawn, with_timeout
from gevent.event import AsyncResult, Event
from gevent.greenlet import Greenlet
from gevent.lock import RLock
from gevent.socket import socket, getaddrinfo, AF_INET, SOCK_STREAM, SHUT_RDWR
from gevent.subprocess import Popen
from uuid import UUID
from weakref import WeakValueDictionary

from . import callback, IPCConnector, ProtocolHeaders, ProtocolProxyMessage, ProtocolProxyPeer, SocketParams

_log = logging.getLogger(__name__)

_TIMED_OUT = object()


@dataclass
class GeventProtocolProxyPeer(ProtocolProxyPeer):
    process: Popen = None
    ready: RLock = field(default_factory=RLock)     # one lock per peer; a shared default would serialize every peer


class GeventIPCConnector(IPCConnector):
    """Socket transport for the gevent manager and gevent proxies.

    Sockets are gevent sockets left in blocking mode: gevent keeps the descriptor non-blocking and parks the calling
    greenlet on the hub until the descriptor is ready, so every wait here is event-driven and costs no polling.
    One greenlet accepts connections and spawns a greenlet per connection; ``send`` spawns a greenlet per message.
    Connection lifetime is one frame per connection (the sender closes, or reads one reply and closes); ``_read_frame``
    and ``_dispatch`` do not depend on that, so a persistent connection is a reader that loops instead of closing.
    """
    LISTEN_BACKLOG = 128

    def __init__(self, *, proxy_id: UUID, token: UUID, proxy_name: str = None, inbound_params: SocketParams = None,
                 chunk_size: int = 1024, encrypt: bool = False, min_port: int = 22801, max_port: int = 22899,
                 max_io_wait_seconds: float = 30.0, **kwargs):
        self.inbound_server_socket: socket | None = None
        super(GeventIPCConnector, self).__init__(proxy_id=proxy_id, token=token, proxy_name=proxy_name,
                                                 inbound_params=inbound_params, chunk_size=chunk_size, encrypt=encrypt,
                                                 min_port=min_port, max_port=max_port, **kwargs)
        self.max_io_wait_seconds = max_io_wait_seconds  # deadline for any single socket operation, and for connect
        self.response_results: WeakValueDictionary[int, AsyncResult] = WeakValueDictionary()
        self.connections: set[socket] = set()           # open connections, closed when the loop stops
        self._stop = False
        self._serving = False
        self._served = Event()                          # set when the accept loop has exited
        self._served.set()

    def _get_ip_addresses(self, host_name: str) -> set[str]:
        return {ai[4][0] for ai in getaddrinfo(host_name, None)}

    def _setup_inbound_server(self, socket_params: SocketParams = None):
        if self.inbound_server_socket:
            return
        inbound_socket: socket = socket(AF_INET, SOCK_STREAM)
        if socket_params:
            try:
                inbound_socket.bind(socket_params)
                inbound_socket.listen(self.LISTEN_BACKLOG)
                self.inbound_params = SocketParams(*inbound_socket.getsockname()[:2])
                self.inbound_server_socket = inbound_socket
                return
            except (OSError, Exception) as e:
                _log.warning(f'Unable to bind to provided inbound socket {socket_params}. Trying next available. - {e}')
        else:
            socket_params = SocketParams()
        while True:
            try:
                next_port = next(self.unused_ports(self._get_ip_addresses(socket_params.address)))
                inbound_socket.bind((socket_params.address, next_port))
            except OSError:
                continue
            except StopIteration:
                _log.error(f'Unable to bind inbound socket to {socket_params.address}'
                           f' on any port in range: {self.min_port} - {self.max_port}.')
                break  # TODO: Should this return instead of break?
            else:
                self.inbound_params = SocketParams(*inbound_socket.getsockname())
                break
        try:
            inbound_socket.listen(self.LISTEN_BACKLOG)
        except (OSError, Exception) as e:
            _log.warning(f'{self.proxy_name}: Socket error listening on {self.inbound_params}: {e}')
        self.inbound_server_socket = inbound_socket
        _log.info(f'Created new inbound server socket: {self.inbound_params}.')

    @callback
    def _handle_response(self, headers: ProtocolHeaders, raw_message: bytes):
        result = self.response_results.get(headers.request_id)
        if not result:
            _log.warning(f'Received response {headers.request_id} from {headers.sender_id} containing "{raw_message.decode()}",'
                         f' but result object is no longer available.')
        else:
            result.set(raw_message)

    # ---- sending -------------------------------------------------------------------------------------------------
    def send(self, remote: ProtocolProxyPeer, message: ProtocolProxyMessage) -> bool | AsyncResult:
        """Send a message to the remote. Returns False when it cannot be attempted, an AsyncResult for the reply when
        one is expected, else True. The peer's ``ready`` lock is taken in the caller's greenlet, as it is re-entrant
        there for a post-registration function sending from inside ``wait_peer_registered``. Delivery itself runs in
        its own greenlet; a delivery failure is logged and leaves the AsyncResult unset for the caller's own timeout.
        """
        if not isinstance(remote, ProtocolProxyPeer):
            _log.error(f'{self.proxy_name}: send() requires a ProtocolProxyPeer, got {type(remote).__name__}: {remote}')
            return False
        try:
            with remote.ready:
                params = remote.socket_params
                if (params is None or getattr(params, 'address', None) is None
                        or getattr(params, 'port', None) is None):
                    _log.error(f"Refusing to connect: remote SocketParams is invalid: {params}")
                    return False
                address = (params.address, params.port)
        except (OSError, Exception) as e:
            _log.warning(f"{self.proxy_name}: Unexpected error preparing to send to"
                         f" {getattr(remote, 'socket_params', remote)}: {e}")
            return False
        if message.request_id is None:
            message.request_id = self.request_id_for(message.protocol_version)
        if message.response_expected:
            result = AsyncResult()
            self.response_results[message.request_id] = result
        else:
            result = True
        spawn(self._deliver, address, message)
        return result

    def _deliver(self, address: tuple[str, int], message: ProtocolProxyMessage):
        """Connect, write the frame, and, when a reply is expected, read one frame back; then close."""
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(self.max_io_wait_seconds)
        self.connections.add(sock)
        try:
            sock.connect(address)
            sock.sendall(self._frame(message))
            if message.response_expected:
                if (frame := self._read_frame(sock)) is not None:
                    self._dispatch(sock, *frame)
                else:
                    _log.warning(f'{self.proxy_name}: {address} closed the connection without answering'
                                 f' {message.method_name} (request_id: {message.request_id}).')
        except (OSError, Exception) as e:
            if not self._stop:
                _log.warning(f'{self.proxy_name}: Unable to send {message.method_name}'
                             f' (request_id: {message.request_id}) to {address}: {e}')
        finally:
            self.connections.discard(sock)
            self._close(sock)

    def _pack_headers(self, data_length: int, request_id: int, response_expected: bool, method_name: str,
                      protocol_version: int = 1, remote_id=None) -> bytes:
        if not (protocol := self.PROTOCOL_VERSION.get(protocol_version)):
            raise NotImplementedError(f'Unable to send with unknown proxy protocol version: {protocol_version}')
        extra = {'remote_id': remote_id} if protocol_version >= 2 else {}
        return protocol(data_length, method_name, request_id, self.proxy_id, self.token, response_expected,
                        **extra).pack()

    def _frame(self, message: ProtocolProxyMessage) -> bytes:
        """The wire bytes of a message: header then payload, written with one sendall."""
        payload = message.payload
        if isinstance(payload, (AsyncResult, Greenlet)):
            payload = payload.get()
        payload = b'' if payload is None else payload       # a handler that returned nothing still gets its reply out
        return self._pack_headers(len(payload), message.request_id, message.response_expected, message.method_name,
                                  message.protocol_version, message.remote_id) + bytes(payload)

    # ---- receiving -----------------------------------------------------------------------------------------------
    def _recv_exact(self, sock: socket, length: int) -> bytes | None:
        """Exactly ``length`` bytes, or None if the peer closed first. Each recv parks this greenlet until data is
        there; the socket's timeout bounds each wait."""
        buffer = bytearray()
        while len(buffer) < length:
            if not (chunk := sock.recv(length - len(buffer))):
                return None
            buffer += chunk
        return bytes(buffer)

    def _read_frame(self, sock: socket) -> tuple[ProtocolHeaders, bytes] | None:
        """One frame from the socket, or None when the peer closed before sending one. A frame cut short is logged
        and also yields None."""
        if (version_bytes := self._recv_exact(sock, 2)) is None:
            return None
        version_num = struct.unpack('>H', version_bytes)[0]
        if not (protocol := self.PROTOCOL_VERSION.get(version_num)):
            raise NotImplementedError(f'Unknown protocol version ({version_num}) received from {self._peer_name(sock)}')
        if (header_bytes := self._recv_exact(sock, protocol.HEADER_LENGTH)) is None:
            _log.warning(f'{self.proxy_name}: {self._peer_name(sock)} closed the connection inside a header.')
            return None
        headers = protocol.unpack(header_bytes)
        if (payload := self._recv_exact(sock, headers.data_length)) is None:
            _log.warning(f'{self.proxy_name}: {self._peer_name(sock)} closed the connection inside the payload of'
                         f' {headers.method_name} (request_id: {headers.request_id}).')
            return None
        return headers, payload

    def _dispatch(self, sock: socket, headers: ProtocolHeaders, payload: bytes):
        """Run the handler for a frame and, if the handler provides a response, write it back on the same socket.
        A handler that raises or exceeds its timeout answers with the same JSON error the asyncio connector sends."""
        if not (cb_info := self.find_callback(headers)):
            _log.warning(f'{self.proxy_name}: Received unknown method name: {headers.method_name}'
                         f' from {self._peer_name(sock)} with request ID: {headers.request_id}')
            return
        try:
            result = with_timeout(cb_info.timeout, cb_info.method, self, headers, payload, timeout_value=_TIMED_OUT)
            if result is _TIMED_OUT:
                raise TimeoutError(f'timed out after {cb_info.timeout} seconds')
            if isinstance(result, (AsyncResult, Greenlet)):
                result = result.get(timeout=cb_info.timeout)
        except TimeoutError as e:
            _log.warning(f'{self.proxy_name}: Callback {headers.method_name} {e}')
            result = json.dumps({'status': 'error', 'error': f'Operation {e}', 'method': headers.method_name}).encode('utf8')
        except Exception as e:
            _log.warning(f'{self.proxy_name}: Callback {headers.method_name} raised: {e!r}')
            result = json.dumps({'status': 'error', 'error': repr(e), 'method': headers.method_name}).encode('utf8')
        if cb_info.provides_response:
            sock.sendall(self._frame(ProtocolProxyMessage(method_name='RESPONSE', payload=result,
                                                          request_id=headers.request_id)))

    def _handle_connection(self, sock: socket):
        """Serve one accepted connection: one frame, its reply if any, then close."""
        self.connections.add(sock)
        try:
            if (frame := self._read_frame(sock)) is not None:
                self._dispatch(sock, *frame)
        except (OSError, Exception) as e:
            if not self._stop:
                _log.warning(f'{self.proxy_name}: Error serving connection from {self._peer_name(sock)}: {e}')
        finally:
            self.connections.discard(sock)
            self._close(sock)

    def select_loop(self):
        """Accept connections until ``stop()``; spawn this. The name is kept from the select-based implementation.
        A second caller waits for the running loop to finish rather than starting another."""
        if self._serving:
            self._served.wait()
            return
        if self.inbound_server_socket is None:
            self._setup_inbound_server(self.inbound_params)
        self._serving, server = True, self.inbound_server_socket
        self._served.clear()
        try:
            while not self._stop:
                try:
                    client, _ = server.accept()
                except (OSError, Exception) as e:
                    if self._stop:
                        break
                    _log.warning(f'{self.proxy_name}: Error accepting a connection: {e}')
                    sleep(0.1)      # do not spin on a persistent accept failure (e.g. out of descriptors)
                    continue
                client.settimeout(self.max_io_wait_seconds)
                spawn(self._handle_connection, client)
        finally:
            for s in list(self.connections):
                self._close(s)
            self.connections.clear()
            self._serving = False
            self._served.set()

    # ---- lifecycle -----------------------------------------------------------------------------------------------
    def start(self, *_, **__):
        self._setup_inbound_server(self.inbound_params)

    def stop(self):
        """Stop accepting; the accept loop exits as soon as its socket is closed and then closes open connections."""
        self._stop = True
        if (server := self.inbound_server_socket) is not None:
            self.inbound_server_socket = None
            self._close(server)

    @staticmethod
    def _close(sock: socket):
        try:
            sock.shutdown(SHUT_RDWR)
        except (OSError, Exception):
            pass    # already closed or never connected; nothing left to do
        sock.close()

    @staticmethod
    def _peer_name(sock: socket) -> str:
        try:
            return str(sock.getpeername())
        except OSError:
            return 'an unknown peer'
