import asyncio
import inspect
import json # TODO: Should we really be using JSON for error responses. If not, then what?
import logging
import socket as _socket
import struct

from asyncio import BufferedProtocol, Condition, Future, subprocess, Transport
from asyncio.base_events import Server
from dataclasses import dataclass, field
from uuid import UUID
from weakref import WeakValueDictionary

from . import (callback, IPCConnector, ProtocolHeaders, ProtocolProxyCallback, ProtocolProxyMessage, ProtocolProxyPeer,
               SocketParams)

_log = logging.getLogger(__name__)


@dataclass
class AsyncioProtocolProxyPeer(ProtocolProxyPeer):
    process: subprocess.Process = None
    ready: Condition = Condition()
    connect_lock: asyncio.Lock = field(default_factory=asyncio.Lock)    # one dial at a time toward this peer


class AsyncioIPCConnector(IPCConnector):
    """Socket transport for asyncio proxies (and the asyncio manager). Connection lifetime follows the same policy as
    the gevent connector: a connection per message by default; toward a persistent peer, one ``IPCProtocol`` carries
    frames in both directions, is dialled on demand and redialled after a loss, and a frame arriving with the
    keep-alive bit on an accepted connection makes that connection the way back to its authenticated sender."""
    KEEPALIVE = {'TCP_KEEPIDLE': 15, 'TCP_KEEPINTVL': 5, 'TCP_KEEPCNT': 4}

    def __init__(self, *, proxy_id, token, proxy_name: str = None, connect_timeout: float = 30.0, **kwargs):
        self.inbound_server: Server | None = None
        self.loop = asyncio.get_running_loop()
        super(AsyncioIPCConnector, self).__init__(proxy_id=proxy_id, token=token, proxy_name=proxy_name, **kwargs)
        self.connect_timeout = connect_timeout      # a dial that neither completes nor is refused fails after this
        self.response_results: WeakValueDictionary[int, Future] = WeakValueDictionary()
        self.connections: set[IPCProtocol] = set()      # open connections, closed when the connector stops

    async def _get_ip_addresses(self, host_name: str) -> set[str]:
        return {ai[4][0] for ai in await self.loop.getaddrinfo(host_name, None)}

    @callback
    async def _handle_response(self, headers: ProtocolHeaders, raw_message: bytes):
        result = self.response_results.get(headers.request_id)
        if not result:
            _log.warning(
                f'Received response {headers.request_id} from {headers.sender_id} containing "{raw_message.decode()}",'
                f' but result object is no longer available.')
        else:
            if not result.done():
                result.set_result(raw_message)

    def _fail_result(self, result: Future, error: Exception):
        if not result.done():
            result.set_exception(error)

    async def send(self, remote: AsyncioProtocolProxyPeer, message: ProtocolProxyMessage) -> bool | Future:
        """Send a message to the remote. Returns False when it cannot be attempted, a Future for the reply when one
        is expected, else True. An open persistent connection to the peer is used when there is one; otherwise a
        persistent peer gets one dialled and any other peer gets a connection for this message alone. A frame larger
        than ``persistent_max_frame`` takes its own connection when the peer's address is known."""
        if not isinstance(remote, ProtocolProxyPeer):
            _log.error(f'{self.proxy_name}: send() requires a ProtocolProxyPeer, got {type(remote).__name__}: {remote}')
            return False
        params = remote.socket_params
        address = None
        if params is not None and getattr(params, 'address', None) and getattr(params, 'port', None):
            address = (params.address, params.port)
        link = remote.connection if remote.connection is not None and remote.connection.alive else None
        if address is None and link is None:
            _log.error(f"{self.proxy_name}: Refusing to send to {remote.proxy_id}: no open connection and"
                       f" its SocketParams are invalid: {params}")
            return False
        if message.request_id is None:
            message.request_id = self.request_id_for(message.protocol_version)
        if message.response_expected:
            result = self.loop.create_future()
            self.response_results[message.request_id] = result
        else:
            result = True
        if link is None and not self.is_persistent(remote):
            return await self._send_per_message(remote, address, message, result)
        frame_length = self.PROTOCOL_VERSION[message.protocol_version].HEADER_LENGTH + 2 + len(message.payload)
        if address is not None and self.persistent_max_frame and frame_length > self.persistent_max_frame:
            return await self._send_per_message(remote, address, message, result)   # its own connection
        try:
            protocol = await self._link(remote, address)
            if message.response_expected:
                protocol.pending.add(message.request_id)
            protocol.transport.write(protocol._message_to_bytes(message, keep_alive=True))
        except (OSError, Exception) as e:
            _log.warning(f'{self.proxy_name}: Unable to send {message.method_name}'
                         f' (request_id: {message.request_id}) to {remote.proxy_id}: {e}')
            if message.response_expected:
                self._fail_pending([message.request_id], ConnectionError(f'{message.method_name} to {remote.proxy_id}: {e}'))
        return result

    async def _send_per_message(self, remote: AsyncioProtocolProxyPeer, address: tuple[str, int],
                                message: ProtocolProxyMessage, result):
        """Dial a connection for this message alone; the protocol writes the frame on connect and, when a reply is
        expected, reads it and closes."""
        connection_attempts = 5
        while connection_attempts:
            try:
                async with remote.ready:
                    transport, _ = await asyncio.wait_for(self.loop.create_connection(
                        lambda: IPCProtocol(connector=self, outgoing_message=message), *address), self.connect_timeout)
            except (ConnectionError, asyncio.TimeoutError, OSError) as e:
                # TODO: How might we be smarter about this?
                connection_attempts -= 1
                if connection_attempts:
                    await asyncio.sleep(1)
                    continue
                _log.warning(f'{self.proxy_name}: Unable to send {message.method_name}'
                             f' (request_id: {message.request_id}) to {address}: {e}')
                if message.response_expected:
                    self._fail_pending([message.request_id], ConnectionError(f'{message.method_name} to {address}: {e}'))
            else:
                if not message.response_expected:
                    transport.close()
            break
        return result

    async def _link(self, remote: AsyncioProtocolProxyPeer, address: tuple[str, int] | None) -> 'IPCProtocol':
        """The peer's open persistent connection, dialled now if it has none and its address is known."""
        async with remote.connect_lock:
            if (protocol := remote.connection) is not None and protocol.alive:
                return protocol
            if address is None:
                raise ConnectionError(f'no open connection to {remote.proxy_id} and no address to dial')
            _, protocol = await asyncio.wait_for(self.loop.create_connection(
                lambda: IPCProtocol(connector=self, persistent=True, peer_id=remote.proxy_id), *address),
                self.connect_timeout)
            remote.connection = protocol
            _log.info(f'{self.proxy_name}: opened a persistent connection to {remote.proxy_id} @ {address}.')
            return protocol

    def _adopt(self, protocol: 'IPCProtocol', headers: ProtocolHeaders):
        """A frame with the keep-alive bit arrived on an accepted connection: the sender keeps it open, so if the
        sender is an authenticated peer, send to it on this connection from now on (replacing any earlier one)."""
        peer = self.peers.get(headers.sender_id)
        if peer is None or peer.token != headers.sender_token:
            _log.debug(f'{self.proxy_name}: not adopting a keep-alive connection from unauthenticated {headers.sender_id}')
            return
        protocol._make_persistent(peer.proxy_id)
        previous, peer.connection = peer.connection, protocol
        if previous is not None and previous is not protocol and previous.alive:
            _log.info(f'{self.proxy_name}: {peer.proxy_id} opened a new persistent connection; closing the earlier one.')
            previous.close()

    def _connection_lost(self, protocol: 'IPCProtocol', reason: str):
        self.connections.discard(protocol)
        if protocol.pending:
            self._fail_pending(protocol.pending, ConnectionError(f'connection to {protocol.peer_id} lost: {reason}'))
            protocol.pending.clear()
        if protocol.peer_id is not None and (peer := self.peers.get(protocol.peer_id)) is not None \
                and peer.connection is protocol:
            peer.connection = None
            _log.info(f'{self.proxy_name}: persistent connection to {protocol.peer_id} {reason}.')

    async def _setup_inbound_server(self, socket_params: SocketParams = None):
        on_lost_connection = self.loop.create_future()
        factory = IPCProtocol.get_factory(connector=self, on_lost_connection=on_lost_connection)
        if socket_params:
            try:
                self.inbound_server = await self.loop.create_server(factory, *socket_params,
                                                                    start_serving=True, family=2)
                return
            except (OSError, Exception) as e:
                _log.warning(f'Unable to bind to provided inbound socket {socket_params}. Trying next available. - {e}')
        else:
            socket_params = SocketParams()
        while True:
            try:
                next_port = next(self.unused_ports(await self._get_ip_addresses(socket_params.address)))
                self.inbound_server = await self.loop.create_server(factory, socket_params.address, next_port,
                                                                    start_serving=True, family=2)
                #_log.debug(f'{self.proxy_name} AFTER START SERVING. Server is: {self.inbound_server}')
            except OSError:
                continue
            except StopIteration:
                _log.error(f'Unable to bind inbound socket to {socket_params.address}'
                           f' on any port in range: {self.min_port} - {self.max_port}.')
                break
            else:
                # Only take first 2 elements (host, port) from getsockname()
                # IPv6 sockets return 4-tuple (host, port, flowinfo, scope_id)
                sockname = self.inbound_server.sockets[0].getsockname()
                self.inbound_params = SocketParams(sockname[0], sockname[1])
                break

    async def start(self, *_, **__):
        await self._setup_inbound_server(self.inbound_params)
        #_log.debug(f' {self.proxy_name} STARTED with INBOUND PARAMS SENT AS: {self.inbound_params}.')

    async def stop(self):
        for protocol in list(self.connections):
            protocol.close()
        if self.inbound_server is not None:
            self.inbound_server.close()
            await self.inbound_server.wait_closed()


class IPCProtocol(BufferedProtocol):
    def __init__(self, connector: AsyncioIPCConnector, on_lost_connection=None, buffer_size=32768,
                 minimum_read_size: int = 76, outgoing_message=None, protocol_version: int = 1,
                 persistent: bool = False, peer_id: UUID | None = None):
        self.buffer_size = buffer_size
        self.connector: AsyncioIPCConnector = connector
        # Persistent: frames in both directions until a side closes; per message: one frame and its reply.
        self.persistent, self.peer_id = persistent, peer_id
        self.pending: set[int] = set()          # request ids awaiting responses on this connection
        self._lost = False
        # _log.debug(f'{self.connector.proxy_name} INBOUND ASyncioIPC PROTOCOL: IN PROTOCOL INIT')
        self.minimum_read_size = minimum_read_size  # TODO: Default is V1 header length. Is this appropriate?
        self.outgoing_message = outgoing_message
        self.on_con_lost = on_lost_connection
        self.protocol_version: int = protocol_version

        self.loop = asyncio.get_running_loop()
        self.received_data: memoryview = memoryview(bytearray(buffer_size))  # TODO: Set default buffer to 32k. Is this appropriate?
                                                                #  Can we track the utilization and adjust if full or never used?
        self.head, self.tail, self.count = 0, 0, 0
        self.protocol = self.connector.PROTOCOL_VERSION.get(self.protocol_version)
        if not self.protocol:  # TODO: There should probably be a max protocol exchange in initial handshake. Better than checking protocol of every message?
            raise NotImplementedError(f'{self.connector.proxy_name} -- '
                                      f'Unable to send with unknown proxy protocol version: {self.protocol_version}')
        self.header_length = self.protocol.HEADER_LENGTH + 2
        self.transport: Transport | None = None

    @property
    def alive(self) -> bool:
        return self.transport is not None and not self._lost and not self.transport.is_closing()

    def close(self):
        if self.transport is not None:
            self.transport.close()

    def _make_persistent(self, peer_id: UUID | None):
        self.persistent, self.peer_id = True, peer_id
        sock = self.transport.get_extra_info('socket') if self.transport is not None else None
        if sock is None:
            return
        try:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)
            for name, value in self.connector.KEEPALIVE.items():
                if (option := getattr(_socket, name, None)) is not None:
                    sock.setsockopt(_socket.IPPROTO_TCP, option, value)
        except OSError as e:
            _log.debug(f'{self.connector.proxy_name}: unable to set TCP keepalive: {e}')

    def buffer_updated(self, n_bytes: int) -> None:
        """Account for ``n_bytes`` just read into the buffer and dispatch every complete frame it now holds.

        The buffer is a ring; a frame that would not fit between the read position and the end of the ring (or in
        the ring at all) straightens the buffered bytes out to the start first, growing the buffer when the frame is
        larger than it. Frames are therefore always read from a contiguous slice.
        """
        try:
            if not self.transport:
                _log.warning(f'{self.connector.proxy_name} -- Unable to locate transport for received buffer.')
            self.tail = (self.tail + n_bytes) % self.buffer_size
            self.count += n_bytes
            while self.count >= 2:
                # Each frame names its own header version (the sender picks version 2 only when it tags a remote).
                if self.head + 2 > self.buffer_size:
                    self._straighten(self.buffer_size)
                version = struct.unpack('>H', bytes(self.received_data[self.head:self.head + 2]))[0]
                protocol = self.connector.PROTOCOL_VERSION.get(version)
                if protocol is None:
                    raise NotImplementedError(f'Unknown protocol version ({version}) received by {self.connector.proxy_name}')
                header_length = protocol.HEADER_LENGTH + 2
                if self.count < header_length:
                    return
                if self.head + header_length > self.buffer_size:
                    self._straighten(self.buffer_size)
                header_end = self.head + header_length
                headers = protocol.unpack(self.received_data[self.head + 2:header_end])
                frame_length = header_length + headers.data_length
                if self.head + frame_length > self.buffer_size:
                    self._straighten(frame_length + self.minimum_read_size)
                    header_end = self.head + header_length
                if self.count < frame_length:
                    return
                message_end = header_end + headers.data_length
                data = self.received_data[header_end:message_end]
                self.head = message_end % self.buffer_size
                self.count -= frame_length
                if headers.keep_alive and not self.persistent:
                    self.connector._adopt(self, headers)
                if headers.method_name == 'RESPONSE':
                    self.pending.discard(headers.request_id)
                cb_info = self.connector.find_callback(headers)
                if cb_info is None:
                    _log.warning(f'{self.connector.proxy_name} -- No callback found for method: {headers.method_name}.')
                if (owed := self.connector.unanswerable(headers, cb_info)) is not None:
                    self._reply(headers, owed)        # the caller asked for a reply nobody will give: fail it now
                if cb_info is not None:
                    self.loop.create_task(self._run_callback(cb_info, headers, data))
                if (cb_info is None or not cb_info.provides_response) and not self.persistent:
                    self.transport.close()
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in buffer_updated: {e!r}')

    def _straighten(self, minimum_size: int) -> None:
        """Move the buffered bytes to the start of a (possibly larger) buffer so the next frame is contiguous."""
        size = max(minimum_size, self.buffer_size)
        fresh = bytearray(size)
        if self.head + self.count <= self.buffer_size:
            fresh[:self.count] = self.received_data[self.head:self.head + self.count]
        else:
            first = self.buffer_size - self.head
            fresh[:first] = self.received_data[self.head:self.buffer_size]
            fresh[first:self.count] = self.received_data[0:self.count - first]
        self.received_data = memoryview(fresh)
        self.buffer_size = size
        self.head, self.tail = 0, self.count % size

    async def _run_callback(self, callback_info: ProtocolProxyCallback, headers, data):
        try:
            result = callback_info.method(self.connector, headers, data.tobytes())
            if inspect.isawaitable(result):
                result = await asyncio.wait_for(result, timeout=callback_info.timeout)
        except asyncio.TimeoutError as e:
            error_message = f"timed out after {callback_info.timeout} seconds with error message: {e}"
            _log.warning(f'{self.connector.proxy_name} -- Callback {headers.method_name} {error_message}')
            error_response = {'status': 'error', 'error': f'Operation {error_message}', 'method': headers.method_name}
            result = json.dumps(error_response).encode('utf8')
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Callback {headers.method_name} raised: {e!r}')
            result = json.dumps({'status': 'error', 'error': repr(e), 'method': headers.method_name}).encode('utf8')
        if callback_info.provides_response:
            self._reply(headers, b'' if result is None else result)
            if not self.persistent:
                self.transport.close()

    def _reply(self, headers, payload: bytes):
        message = ProtocolProxyMessage(method_name='RESPONSE', payload=payload, request_id=headers.request_id)
        if self.transport is None or self.transport.is_closing():
            _log.warning(f'{self.connector.proxy_name} -- Connection gone before answering {headers.method_name}'
                         f' (request_id: {headers.request_id}).')
            return
        self.transport.write(self._message_to_bytes(message, keep_alive=self.persistent))

    def connection_made(self, transport: Transport):
        #_log.debug(f"[IPCProtocol] connection_made: transport={transport}")
        try:
            self.transport = transport
            self.connector.connections.add(self)
            if self.persistent:
                self._make_persistent(self.peer_id)
            if self.outgoing_message:
                # TODO: Should we send in chunks and sleep in between?
                transport.write(self._message_to_bytes(self.outgoing_message))
                if not self.outgoing_message.response_expected:
                    transport.close()
                else:
                    self.pending.add(self.outgoing_message.request_id)    # failed if the peer closes without answering
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in connection_made: {e}')

    def _message_to_bytes(self, message: ProtocolProxyMessage, keep_alive: bool = False):
        protocol = self.connector.PROTOCOL_VERSION[message.protocol_version]
        extra = {'remote_id': message.remote_id} if message.protocol_version >= 2 else {}
        message_bytes = bytearray(protocol(len(message.payload), message.method_name,
                                           message.request_id, self.connector.proxy_id,
                                           self.connector.token, message.response_expected, keep_alive=keep_alive,
                                           **extra).pack())
        message_bytes.extend(message.payload)  # TODO: Does payload still need to be encoded?
        return message_bytes

    def connection_lost(self, exc):
        self._lost = True
        try:
            self.connector._connection_lost(self, str(exc) if exc else 'closed by the peer')
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in connection_lost: {e}')

    def get_buffer(self, size_hint):
        try:
            return self.received_data[self.tail:self.tail + min(max(size_hint, self.minimum_read_size), self.buffer_size)]
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in get_buffer: {e}')

    def eof_received(self) -> bool | None:
        # None: close the transport, so connection_lost runs and the requests pending on this connection are failed.
        # (Returning True kept the transport half-open, and a peer's close was never noticed.)
        return None

    @classmethod
    def get_factory(cls, connector, on_lost_connection, *args, **kwargs):
        def factory():
            return cls(connector=connector, on_lost_connection=on_lost_connection, *args, **kwargs)
        return factory
