import asyncio
import json
import logging

from abc import ABC
from typing import cast
from uuid import UUID

from ..ipc.asyncio import AsyncioIPCConnector, Future, AsyncioProtocolProxyPeer, SocketParams
from . import ProtocolProxy

_log = logging.getLogger(__name__)


class AsyncioProtocolProxy(AsyncioIPCConnector, ProtocolProxy, ABC):
    def __init__(self, *, manager_address: str, manager_port: int, manager_id: UUID, manager_token: UUID, token: UUID,
                 proxy_id: UUID, proxy_name: str = None, registration_retry_delay: float = 20.0,
                 registration_attempts: int = 2, registration_timeout: float = 5.0, **kwargs):
        super(AsyncioProtocolProxy, self).__init__(manager_address=manager_address, manager_port=manager_port,
                                                   manager_id=manager_id, proxy_id=proxy_id,
                                                   registration_retry_delay=registration_retry_delay,
                                                   token=token, proxy_name=proxy_name, **kwargs)
        self.peers[manager_id] = AsyncioProtocolProxyPeer(proxy_id=manager_id, socket_params=self.manager_params,
                                                          token=manager_token)
        self.registration_attempts = registration_attempts
        self.registration_timeout = registration_timeout
        self.registered = False

    def get_local_socket_params(self) -> SocketParams:
        if self.inbound_server is None:
            raise RuntimeError(f'{self.proxy_name}: start() must be called before registering with the manager.')
        # Only take first 2 elements (host, port) from getsockname()
        # IPv6 sockets return 4-tuple (host, port, flowinfo, scope_id)
        sockname = self.inbound_server.sockets[0].getsockname()
        return SocketParams(sockname[0], sockname[1])

    async def send_registration(self, remote: AsyncioProtocolProxyPeer) -> bool:
        for attempt in range(1, self.registration_attempts + 1):
            try:
                message = self._get_registration_message()
                manager_response = await self.send(remote, message)
                if isinstance(manager_response, Future):
                    manager_response = await asyncio.wait_for(manager_response, timeout=self.registration_timeout)
                success = (json.loads(manager_response.decode('utf8'))
                           if isinstance(manager_response, (bytes, bytearray)) else bool(manager_response))
            except asyncio.TimeoutError:
                _log.warning(f'{self.proxy_name}: No registration response from manager within'
                             f' {self.registration_timeout} seconds (attempt {attempt}).')
                success = False
            except Exception as e:
                _log.warning(f'{self.proxy_name}: Error sending registration (attempt {attempt}): {e}')
                success = False
            if success:
                self.registered = True
                _log.info(f'{self.proxy_name}: Registered with manager @ {remote.socket_params}.')
                return True
            if attempt < self.registration_attempts:
                await asyncio.sleep(self.registration_retry_delay)
        _log.error(f'{self.proxy_name}: Unable to register with Proxy Manager @ {remote.socket_params}'
                   f' after {self.registration_attempts} attempts.')
        return False

    async def start(self):
        """Create the inbound server, register with the manager, then serve until stopped."""
        await super(AsyncioProtocolProxy, self).start()
        if not await self.send_registration(cast(AsyncioProtocolProxyPeer, self.peers[self.manager])):
            raise RuntimeError(f'{self.proxy_name}: registration with the Proxy Manager failed.')
        async with self.inbound_server:
            await self.inbound_server.serve_forever()
