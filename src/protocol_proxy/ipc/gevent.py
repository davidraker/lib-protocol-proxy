import json
import logging
import socket as _socket
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
    registered: Event = field(default_factory=Event)    # set when the manager has recorded this peer's address

    def mark_registered(self):
        super().mark_registered()
        self.registered.set()

    ready: RLock = field(default_factory=RLock)     # one lock per peer; a shared default would serialize every peer
    connect_lock: RLock = field(default_factory=RLock)      # one dial at a time toward this peer


class GeventConnection:
    """One TCP connection: a socket, a serialised writer and, for a connection that stays open, the request ids
    awaiting responses on it (failed when the connection is lost). ``peer_id`` is the authenticated peer at the other
    end once known. Per-message connections carry one frame and its reply; persistent ones carry frames in both
    directions until a side closes."""

    def __init__(self, sock: socket, persistent: bool = False, peer_id: UUID | None = None):
        self.sock = sock
        self.persistent = persistent
        self.peer_id = peer_id
        self.write_lock = RLock()
        self.pending: set[int] = set()
        self.closed = Event()

    @property
    def alive(self) -> bool:
        return not self.closed.is_set()

    def write(self, data: bytes):
        with self.write_lock:
            self.sock.sendall(data)

    def close(self):
        if not self.closed.is_set():
            self.closed.set()
            GeventIPCConnector._close(self.sock)

    def __repr__(self):
        kind = 'persistent' if self.persistent else 'per-message'
        return f'GeventConnection({kind}, {GeventIPCConnector._peer_name(self.sock)}, peer={self.peer_id})'


class GeventIPCConnector(IPCConnector):
    """Socket transport for the gevent manager and gevent proxies.

    Sockets are gevent sockets left in blocking mode: gevent keeps the descriptor non-blocking and parks the calling
    greenlet on the hub until the descriptor is ready, so every wait here is event-driven and costs no polling.
    One greenlet accepts connections and spawns a reader greenlet per connection, which serves frames until the
    other side closes. ``send`` dials a connection per message by default; toward a persistent peer it writes on the
    peer's one open connection (dialling it if needed, under the peer's connect lock) and the reader on that
    connection delivers the responses by request id. Handlers on a persistent connection run in their own greenlets,
    so a slow one does not hold up the frames behind it.
    """
    LISTEN_BACKLOG = 128
    # TCP keepalive on persistent connections: the kernel probes an idle connection after KEEPIDLE seconds, every
    # KEEPINTVL seconds, and resets it after KEEPCNT failed probes, so a vanished peer is noticed in under a minute.
    KEEPALIVE = {'TCP_KEEPIDLE': 15, 'TCP_KEEPINTVL': 5, 'TCP_KEEPCNT': 4}

    def __init__(self, *, proxy_id: UUID, token: UUID, proxy_name: str = None, inbound_params: SocketParams = None,
                 chunk_size: int = 1024, encrypt: bool = False, min_port: int = 22801, max_port: int = 22899,
                 max_io_wait_seconds: float = 30.0, **kwargs):
        self.inbound_server_socket: socket | None = None
        super(GeventIPCConnector, self).__init__(proxy_id=proxy_id, token=token, proxy_name=proxy_name,
                                                 inbound_params=inbound_params, chunk_size=chunk_size, encrypt=encrypt,
                                                 min_port=min_port, max_port=max_port, **kwargs)
        self.max_io_wait_seconds = max_io_wait_seconds  # deadline for any single socket operation, and for connect
        self.response_results: WeakValueDictionary[int, AsyncResult] = WeakValueDictionary()
        self.connections: set[GeventConnection] = set()     # open connections, closed when the connector stops
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

    def _fail_result(self, result: AsyncResult, error: Exception):
        if not result.ready():
            result.set_exception(error)

    # ---- sending -------------------------------------------------------------------------------------------------
    def send(self, remote: ProtocolProxyPeer, message: ProtocolProxyMessage) -> bool | AsyncResult:
        """Send a message to the remote. Returns False when it cannot be attempted, an AsyncResult for the reply when
        one is expected, else True. The peer's ``ready`` lock is taken in the caller's greenlet, as it is re-entrant
        there for a post-registration function sending from inside ``wait_peer_registered``. Delivery itself runs in
        its own greenlet; a delivery failure is logged and fails the AsyncResult (or leaves it to the caller's
        timeout when the failure is the peer's silence).

        An open persistent connection to the peer is used when there is one. Otherwise a persistent peer gets one
        dialled, and any other peer gets a connection for this message alone. A frame larger than
        ``persistent_max_frame`` takes its own connection when the peer's address is known.
        """
        if not isinstance(remote, ProtocolProxyPeer):
            _log.error(f'{self.proxy_name}: send() requires a ProtocolProxyPeer, got {type(remote).__name__}: {remote}')
            return False
        try:
            with remote.ready:
                params = remote.socket_params
                address = None
                if params is not None and getattr(params, 'address', None) and getattr(params, 'port', None):
                    address = (params.address, params.port)
                link = remote.connection if remote.connection is not None and remote.connection.alive else None
                if address is None and link is None:
                    _log.error(f"{self.proxy_name}: Refusing to send to {remote.proxy_id}: no open connection and"
                               f" its SocketParams are invalid: {params}")
                    return False
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
        if link is not None or self.is_persistent(remote):
            spawn(self._deliver_persistent, remote, address, message)
        else:
            spawn(self._deliver, address, message)
        return result

    def _deliver(self, address: tuple[str, int], message: ProtocolProxyMessage):
        """Connect, write the frame, and, when a reply is expected, read one frame back; then close."""
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(self.max_io_wait_seconds)
        conn = GeventConnection(sock)
        self.connections.add(conn)
        try:
            sock.connect(address)
            conn.write(self._frame(message))
            if message.response_expected:
                if (frame := self._read_frame(sock)) is not None:
                    self._dispatch(conn, *frame)
                else:
                    _log.warning(f'{self.proxy_name}: {address} closed the connection without answering'
                                 f' {message.method_name} (request_id: {message.request_id}).')
                    self._fail_pending([message.request_id], ConnectionError(
                        f'{address} closed the connection without answering {message.method_name}'))
        except (OSError, Exception) as e:
            if not self._stop:
                _log.warning(f'{self.proxy_name}: Unable to send {message.method_name}'
                             f' (request_id: {message.request_id}) to {address}: {e}')
            if message.response_expected:
                self._fail_pending([message.request_id], ConnectionError(f'{message.method_name} to {address}: {e}'))
        finally:
            self.connections.discard(conn)
            conn.close()

    def _deliver_persistent(self, remote: ProtocolProxyPeer, address: tuple[str, int] | None,
                            message: ProtocolProxyMessage):
        """Write the frame on the peer's persistent connection, dialling one first if there is none."""
        frame = self._frame(message, keep_alive=True)
        if address is not None and self.persistent_max_frame and len(frame) > self.persistent_max_frame:
            return self._deliver(address, message)      # its own connection, so it does not delay the frames behind it
        try:
            conn = self._link(remote, address)
            if message.response_expected:
                conn.pending.add(message.request_id)
            conn.write(frame)
        except (OSError, Exception) as e:
            if not self._stop:
                _log.warning(f'{self.proxy_name}: Unable to send {message.method_name}'
                             f' (request_id: {message.request_id}) to {remote.proxy_id}: {e}')
            if message.response_expected:
                self._fail_pending([message.request_id], ConnectionError(f'{message.method_name} to {remote.proxy_id}: {e}'))

    def _link(self, remote: ProtocolProxyPeer, address: tuple[str, int] | None) -> GeventConnection:
        """The peer's open persistent connection, dialled now if it has none and its address is known."""
        with remote.connect_lock:
            if (conn := remote.connection) is not None and conn.alive:
                return conn
            if address is None:
                raise ConnectionError(f'no open connection to {remote.proxy_id} and no address to dial')
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(self.max_io_wait_seconds)
            try:
                sock.connect(address)
            except (OSError, Exception):
                sock.close()
                raise
            conn = self._open(sock, persistent=True, peer_id=remote.proxy_id)
            remote.connection = conn
            _log.info(f'{self.proxy_name}: opened a persistent connection to {remote.proxy_id} @ {address}.')
            return conn

    def _pack_headers(self, data_length: int, request_id: int, response_expected: bool, method_name: str,
                      protocol_version: int = 1, remote_id=None, keep_alive: bool = False) -> bytes:
        if not (protocol := self.PROTOCOL_VERSION.get(protocol_version)):
            raise NotImplementedError(f'Unable to send with unknown proxy protocol version: {protocol_version}')
        extra = {'remote_id': remote_id} if protocol_version >= 2 else {}
        return protocol(data_length, method_name, request_id, self.proxy_id, self.token, response_expected,
                        keep_alive=keep_alive, **extra).pack()

    def _frame(self, message: ProtocolProxyMessage, keep_alive: bool = False) -> bytes:
        """The wire bytes of a message: header then payload, written with one sendall."""
        payload = message.payload
        if isinstance(payload, (AsyncResult, Greenlet)):
            payload = payload.get()
        payload = b'' if payload is None else payload       # a handler that returned nothing still gets its reply out
        return self._pack_headers(len(payload), message.request_id, message.response_expected, message.method_name,
                                  message.protocol_version, message.remote_id, keep_alive) + bytes(payload)

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

    def _dispatch(self, conn: GeventConnection, headers: ProtocolHeaders, payload: bytes):
        """Run the handler for a frame and, if the handler provides a response, write it back on the same connection.
        A handler that raises or exceeds its timeout answers with the same JSON error the asyncio connector sends."""
        cb_info = self.find_callback(headers)
        if cb_info is None:
            _log.warning(f'{self.proxy_name}: Received unknown method name: {headers.method_name}'
                         f' from {self._peer_name(conn.sock)} with request ID: {headers.request_id}')
        if (owed := self.unanswerable(headers, cb_info)) is not None:
            self._reply(conn, headers, owed)      # the caller asked for a reply nobody will give: fail it now
        if cb_info is None:
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
            self._reply(conn, headers, result)

    def _reply(self, conn: GeventConnection, headers: ProtocolHeaders, payload):
        response = ProtocolProxyMessage(method_name='RESPONSE', payload=payload, request_id=headers.request_id)
        try:
            conn.write(self._frame(response, keep_alive=conn.persistent))
        except (OSError, Exception) as e:
            if not self._stop:
                _log.warning(f'{self.proxy_name}: Unable to answer {headers.method_name}'
                             f' (request_id: {headers.request_id}) on {conn}: {e}')

    def _adopt(self, conn: GeventConnection, headers: ProtocolHeaders):
        """A frame with the keep-alive bit arrived on an accepted connection: the sender keeps it open, so if the
        sender is an authenticated peer, send to it on this connection from now on (replacing any earlier one)."""
        peer = self.peers.get(headers.sender_id)
        if peer is None or peer.token != headers.sender_token:
            _log.debug(f'{self.proxy_name}: not adopting a keep-alive connection from unauthenticated {headers.sender_id}')
            return
        self._make_persistent(conn, peer.proxy_id)
        previous, peer.connection = peer.connection, conn
        if previous is not None and previous is not conn and previous.alive:
            _log.info(f'{self.proxy_name}: {peer.proxy_id} opened a new persistent connection; closing {previous}.')
            previous.close()

    def _make_persistent(self, conn: GeventConnection, peer_id: UUID):
        conn.persistent, conn.peer_id = True, peer_id
        conn.sock.settimeout(None)      # idle is normal on a persistent connection; keepalive notices a dead peer
        try:
            conn.sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)
            for name, value in self.KEEPALIVE.items():
                if (option := getattr(_socket, name, None)) is not None:
                    conn.sock.setsockopt(_socket.IPPROTO_TCP, option, value)
        except OSError as e:
            _log.debug(f'{self.proxy_name}: unable to set TCP keepalive on {conn}: {e}')

    def _serve(self, conn: GeventConnection):
        """Read and dispatch frames on a connection until the other side closes it (or it fails, or we stop)."""
        reason = 'closed by the peer'
        try:
            while not self._stop:
                if (frame := self._read_frame(conn.sock)) is None:
                    break
                headers, payload = frame
                if headers.keep_alive and not conn.persistent:
                    self._adopt(conn, headers)
                if headers.method_name == 'RESPONSE':
                    conn.pending.discard(headers.request_id)
                if conn.persistent:
                    spawn(self._dispatch, conn, headers, payload)   # a slow handler must not block the frames behind
                else:
                    self._dispatch(conn, headers, payload)
                    break   # per message: one frame, its reply if any, then close (a sender owed no reply fails fast)
        except (OSError, Exception) as e:
            if conn.closed.is_set():
                reason = 'closed'       # this side closed it (stop, replacement, or its peer was dropped): not an error
            else:
                reason = str(e)
                if not self._stop:
                    _log.warning(f'{self.proxy_name}: Error serving {conn}: {e}')
        finally:
            self._drop(conn, reason)

    def _open(self, sock: socket, persistent: bool = False, peer_id: UUID | None = None) -> GeventConnection:
        """Track a connected socket and start serving frames on it."""
        conn = GeventConnection(sock, peer_id=peer_id)
        if persistent:
            self._make_persistent(conn, peer_id)
        self.connections.add(conn)
        spawn(self._serve, conn)
        return conn

    def _drop(self, conn: GeventConnection, reason: str):
        """Forget a connection: close it, fail the requests still awaiting responses on it, and detach it from its
        peer so the next send dials afresh."""
        self.connections.discard(conn)
        conn.close()
        if conn.pending:
            self._fail_pending(conn.pending, ConnectionError(f'connection to {conn.peer_id} lost: {reason}'))
            conn.pending.clear()
        if conn.peer_id is not None and (peer := self.peers.get(conn.peer_id)) is not None \
                and peer.connection is conn:
            peer.connection = None
            if not self._stop and reason != 'closed':
                _log.info(f'{self.proxy_name}: persistent connection to {conn.peer_id} {reason}.')

    def _handle_connection(self, sock: socket):
        """Serve one accepted connection (kept for callers of the old name)."""
        self._serve(GeventConnection(sock))

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
                self._open(client)
        finally:
            self._close_connections()
            self._serving = False
            self._served.set()

    # ---- lifecycle -----------------------------------------------------------------------------------------------
    def start(self, *_, **__):
        self._setup_inbound_server(self.inbound_params)

    def stop(self):
        """Stop accepting and close every connection; the accept loop and the readers exit as their sockets close."""
        self._stop = True
        if (server := self.inbound_server_socket) is not None:
            self.inbound_server_socket = None
            self._close(server)
        self._close_connections()

    def _close_connections(self):
        for conn in list(self.connections):
            conn.close()

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
