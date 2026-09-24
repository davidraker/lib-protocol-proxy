import asyncio
import inspect
import json # TODO: Should we really be using JSON for error responses. If not, then what?
import logging

from asyncio import BufferedProtocol, Condition, Future, subprocess, Transport
from asyncio.base_events import Server
from dataclasses import dataclass
from weakref import WeakValueDictionary

from . import (callback, IPCConnector, ProtocolHeaders, ProtocolProxyCallback, ProtocolProxyMessage, ProtocolProxyPeer,
               SocketParams)

_log = logging.getLogger(__name__)


@dataclass
class AsyncioProtocolProxyPeer(ProtocolProxyPeer):
    process: subprocess.Process = None
    ready: Condition = Condition()


class AsyncioIPCConnector(IPCConnector):
    def __init__(self, *, proxy_id, token, proxy_name: str = None, **kwargs):
        self.inbound_server: Server | None = None
        self.loop = asyncio.get_running_loop()
        super(AsyncioIPCConnector, self).__init__(proxy_id=proxy_id, token=token, proxy_name=proxy_name, **kwargs)
        self.response_results: WeakValueDictionary[int, Future] = WeakValueDictionary()

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
            result.set_result(raw_message)

    async def send(self, remote: AsyncioProtocolProxyPeer, message: ProtocolProxyMessage) -> bool | Future:
        if not isinstance(remote, ProtocolProxyPeer):
            _log.error(f'{self.proxy_name}: send() requires a ProtocolProxyPeer, got {type(remote).__name__}: {remote}')
            return False
        if message.request_id is None:
            message.request_id = self.next_request_id
        if message.response_expected:
            result = self.loop.create_future()
            self.response_results[message.request_id] = result
        else:
            result = True
        connection_attempts = 5
        while connection_attempts:
            try:
                async with remote.ready:
                    transport, _ = await self.loop.create_connection(
                        lambda: IPCProtocol(connector=self, outgoing_message=message), *remote.socket_params) # on_lost_connection=on_lost_connection,
                # TODO: Wait until the protocol signals that the connection is lost and close the transport.
                #await on_lost_connection
            except ConnectionError:
                # TODO: How might we be smarter about this?
                connection_attempts -= 1
                await asyncio.sleep(1)
                continue
            else:
                if not message.response_expected:
                    transport.close()
                break
        return result

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
        self.inbound_server.close()
        await self.inbound_server.wait_closed()


class IPCProtocol(BufferedProtocol):
    def __init__(self, connector: AsyncioIPCConnector, on_lost_connection=None, buffer_size=32768,
                 minimum_read_size: int = 76, outgoing_message=None, protocol_version: int = 1):
        self.buffer_size = buffer_size
        self.connector: AsyncioIPCConnector = connector
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

    def buffer_updated(self, n_bytes: int) -> None:
        try:
            # TODO: This is probably missing error handling and may not close the transport if it errs?
            if not self.transport:
                _log.warning(f'{self.connector.proxy_name} -- Unable to locate transport for received buffer.')
            self.tail = (self.tail + n_bytes) % self.buffer_size
            self.count += n_bytes
            # TODO: How to mitigate the possibility of an overflow?
            # TODO: This block tested the version of each incoming frame.
            #  Is this better or worse than assuming version number stays the same?
            # version_end = 2
            # if len(self.received_data) > version_end:
            #     if not (protocol := self.connector.PROTOCOL_VERSION.get(struct.unpack('>H', self.received_data[:2])[0])):
            #         raise NotImplementedError(f'Unknown protocol version ({protocol.VERSION})'
            #                                   f' received from: {self.transport.get_extra_info("peer_name")}')
            #     header_end = version_end + protocol.HEADER_LENGTH

            if self.count >= self.header_length:
                header_end = self.head + self.header_length
                header_bytes = self.received_data[self.head+2:header_end]
                headers = self.protocol.unpack(header_bytes)  # TODO: Should this be in try block?
                message_end = header_end + headers.data_length
                if self.head + self.count >= message_end:
                    # TODO: This same wrapping logic is needed for reading headers too! Break into helper function.
                    if not message_end < self.buffer_size:
                        message_end = message_end % self.buffer_size
                        data = self.received_data[header_end:self.buffer_size] + self.received_data[0:message_end]
                    else:
                        data = self.received_data[header_end:message_end]
                    self.head = message_end
                    self.count -= 2 + self.header_length + headers.data_length
                    if cb_info := self.connector.callbacks.get(headers.method_name):
                        self.loop.create_task(self._run_callback(cb_info, headers, data))
                        if not cb_info.provides_response:
                            self.transport.close()
                    else:
                        self.transport.close()
                        _log.warning(f'{self.connector.proxy_name} -- No callback found for method: {headers.method_name}.')

        except Exception as e:
            _log.debug(f'{self.connector.proxy_name} -- Exception in buffer_updated: {e}')

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
            if result is None:
                result = b''
            message = ProtocolProxyMessage(method_name='RESPONSE', payload=result, request_id=headers.request_id)
            self.transport.write(self._message_to_bytes(message))
            self.transport.close()

    def connection_made(self, transport: Transport):
        #_log.debug(f"[IPCProtocol] connection_made: transport={transport}")
        try:
            self.transport = transport
            if self.outgoing_message:
                # TODO: Should we send in chunks and sleep in between?
                transport.write(self._message_to_bytes(self.outgoing_message))
                if not self.outgoing_message.response_expected:
                    transport.close()
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in connection_made: {e}')

    def _message_to_bytes(self, message: ProtocolProxyMessage):
        message_bytes = bytearray(self.protocol(len(message.payload), message.method_name,
                                                message.request_id, self.connector.proxy_id,
                                                self.connector.token, message.response_expected).pack())
        message_bytes.extend(message.payload)  # TODO: Does payload still need to be encoded?
        return message_bytes

    def connection_lost(self, exc):
        try:
            pass
            # _log.debug(f'{self.connector.proxy_name} -- Connection lost, exc: "{exc}"')
            # _log.debug(f'self.on_con_lost is a {type(self.on_con_lost)} with value: {self.on_con_lost}')
            # if self.on_con_lost is not None:
            #     self.on_con_lost.set_result(True)  # TODO: What is using the on_con_lost thing?
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in connection_lost: {e}')

    def get_buffer(self, size_hint):
        try:
            return self.received_data[self.tail:self.tail + min(max(size_hint, self.minimum_read_size), self.buffer_size)]
        except Exception as e:
            _log.warning(f'{self.connector.proxy_name} -- Exception in get_buffer: {e}')

    def eof_received(self) -> bool | None:
        try:
            return True  # TODO: This should probably go back to being None (or not defined at all), no?
        except Exception as e:
            _log.debug(f'{self.connector.proxy_name} -- Exception in eof_received: {e}')

    @classmethod
    def get_factory(cls, connector, on_lost_connection, *args, **kwargs):
        def factory():
            return cls(connector=connector, on_lost_connection=on_lost_connection, *args, **kwargs)
        return factory
