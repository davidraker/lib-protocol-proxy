import json
import logging

from abc import ABC
from gevent import joinall, sleep, spawn, Greenlet
from gevent.event import AsyncResult
from gevent.timeout import Timeout
from typing import cast
from uuid import UUID

from ..ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer, SocketParams
from . import ProtocolProxy

_log = logging.getLogger(__name__)


class GeventProtocolProxy(GeventIPCConnector, ProtocolProxy, ABC):
    def __init__(self, *, proxy_id: UUID, token: UUID, manager_address: str, manager_port: int, manager_id: UUID,
                 manager_token: UUID, proxy_name: str = None, registration_retry_delay: float = 20.0,
                 registration_attempts: int = 2, registration_timeout: float = 5.0, **kwargs):
        """ A gevent class for protocols requiring a standalone process to handle incoming and outgoing requests.

        Subclasses override ``main_loop`` for protocol work and call ``run()`` (or ``start()`` and join the
        returned greenlets). Nothing is sent to the manager until ``start()`` has created the inbound socket.
        """
        super(GeventProtocolProxy, self).__init__(proxy_id=proxy_id, token=token, proxy_name=proxy_name,
                                                  manager_address=manager_address, manager_port=manager_port,
                                                  manager_id=manager_id,
                                                  registration_retry_delay=registration_retry_delay, **kwargs)
        self.peers[manager_id] = GeventProtocolProxyPeer(proxy_id=manager_id, socket_params=self.manager_params,
                                                         token=manager_token)
        self.registration_attempts = registration_attempts
        self.registration_timeout = registration_timeout
        self.registered = False
        self._greenlets: list[Greenlet] = []

    def get_local_socket_params(self) -> SocketParams:
        if self.inbound_server_socket is None:
            raise RuntimeError(f'{self.proxy_name}: start() must be called before registering with the manager.')
        return SocketParams(*self.inbound_server_socket.getsockname()[:2])

    def send_registration(self, remote: GeventProtocolProxyPeer) -> bool:
        for attempt in range(1, self.registration_attempts + 1):
            try:
                message = self._get_registration_message()
                manager_response = self.send(remote, message)
                if isinstance(manager_response, AsyncResult):
                    manager_response = manager_response.get(timeout=self.registration_timeout)
                success = (json.loads(manager_response.decode('utf8'))
                           if isinstance(manager_response, (bytes, bytearray)) else bool(manager_response))
            except Timeout:
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
                sleep(self.registration_retry_delay)
        _log.error(f'{self.proxy_name}: Unable to register with Proxy Manager @ {remote.socket_params}'
                   f' after {self.registration_attempts} attempts. Stopping.')
        self.stop()
        return False

    def main_loop(self):
        """Protocol-specific work. Runs concurrently with the select loop; should return when self._stop is set."""
        while not self._stop:
            sleep(0.5)

    def start(self, *_, **__) -> list[Greenlet]:
        """Create the inbound socket, then start the select loop, registration, and main loop."""
        super(GeventProtocolProxy, self).start()
        self._greenlets = [spawn(self.select_loop),
                           spawn(self.send_registration, cast(GeventProtocolProxyPeer, self.peers[self.manager])),
                           spawn(self.main_loop)]
        return self._greenlets

    def run(self) -> int:
        """Start and block until stopped. Returns a process exit code."""
        try:
            joinall(self.start(), raise_error=True)
        finally:
            self.stop()
        return 0 if self.registered else 1
