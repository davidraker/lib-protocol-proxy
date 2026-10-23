import json
import logging
import os
import signal

from abc import ABC
from gevent import joinall, signal_handler, sleep, spawn, Greenlet
from gevent.event import AsyncResult
from gevent.timeout import Timeout
from typing import cast
from uuid import UUID

from ..ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer, SocketParams
from ..logs import write_json_line
from . import ProtocolProxy

_log = logging.getLogger(__name__)


class GeventProtocolProxy(GeventIPCConnector, ProtocolProxy, ABC):
    PATCH_GEVENT = True     # gevent proxies rely on patched sockets; see protocol_proxy.proxy.launch.main

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
        # With manager_dials the manager peer has no address: every send uses the connection the manager opened.
        self.peers[manager_id] = GeventProtocolProxyPeer(proxy_id=manager_id, token=manager_token, key=self.manager_key,
                                                         tls=self.manager_tls,
                                                         socket_params=None if self.manager_dials else self.manager_params)
        self.registration_attempts = registration_attempts
        self.registration_timeout = registration_timeout
        self.registered = False
        self._greenlets: list[Greenlet] = []
        self._signal_watcher = None

    def get_local_socket_params(self) -> SocketParams:
        if self.inbound_server_socket is None:
            raise RuntimeError(f'{self.proxy_name}: start() must be called before registering with the manager.')
        return SocketParams(*self.inbound_server_socket.getsockname()[:2])

    def _wait_for_manager(self):
        """Block until the manager has connected (manager_dials mode); logs every MANAGER_WAIT_LOG_INTERVAL seconds."""
        waited = 0.0
        while not self._stop and not self.manager_linked():
            if waited % self.MANAGER_WAIT_LOG_INTERVAL < 0.1:
                _log.info(f'{self.proxy_name}: waiting for the manager to connect to {self.inbound_params}.')
            sleep(0.1)
            waited += 0.1

    def send_registration(self, remote: GeventProtocolProxyPeer) -> bool:
        if self.manager_dials:
            self._wait_for_manager()
            if self._stop:
                return False
        for attempt in range(1, self.registration_attempts + 1):
            try:
                message = self._get_registration_message()
                manager_response = self.send(remote, message)
                if isinstance(manager_response, AsyncResult):
                    manager_response = manager_response.get(timeout=self.registration_timeout)
                success = self.registration_accepted(remote, manager_response)
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
                self.on_registered()
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

    def _start_log_flusher(self):
        self._greenlets.append(spawn(self._flush_logs_loop))

    def _flush_logs_loop(self):
        while not self._stop and self.log_handler is not None:
            waited = 0.0
            while (not self._stop and self.log_handler is not None and waited < self.LOG_FLUSH_INTERVAL
                   and len(self.log_handler) < self.LOG_BATCH_SIZE):
                sleep(0.02)
                waited += 0.02
            self.flush_logs()

    def flush_logs(self):
        """Ship one LOG batch to the manager (no response expected). Nothing here logs on failure: the records that
        could not be sent go back to stderr, and a logging call from the flusher would only queue more."""
        if (message := self.log_batch_message(self.LOG_BATCH_SIZE)) is None:
            return
        try:
            sent = self.send(cast(GeventProtocolProxyPeer, self.peers[self.manager]), message)
        except Exception:
            sent = False
        if sent is False:
            for fields in json.loads(message.payload)['records']:
                write_json_line(fields)

    def stop(self):
        self.stop_socket_logging()
        if self._signal_watcher is not None and not getattr(self, '_in_signal_handler', False):
            self._signal_watcher.cancel()
            self._signal_watcher = None
        super(GeventProtocolProxy, self).stop()

    def _watch_manager(self):
        while not self._stop and self.manager_alive():
            sleep(self.manager_watch_interval)
        if not self._stop:
            self._manager_lost = True
            try:
                self.on_manager_lost()
            except Exception:
                _log.exception(f'{self.proxy_name}: stopping after the manager was lost raised; exiting.')
                os._exit(1)

    def _on_terminate_signal(self):
        """SIGTERM is how the manager stops a proxy: stop gracefully so protocols get to flush their state. The
        watcher stays armed while stopping (a second SIGTERM during shutdown must not kill the process; with the
        watcher cancelled it would) and is cancelled when ``run`` finishes or ``stop`` is called from elsewhere."""
        if not self._stop:
            _log.info(f'{self.proxy_name}: received SIGTERM; stopping.')
            self.arm_hard_exit('SIGTERM')
            self._in_signal_handler = True
            try:
                self.stop()
            except Exception:
                _log.exception(f'{self.proxy_name}: stop() raised on SIGTERM; exiting.')
                os._exit(1)
            finally:
                self._in_signal_handler = False

    def start(self, *_, **__) -> list[Greenlet]:
        """Create the inbound socket, then start the accept loop, registration, main loop and manager watchdog."""
        self.guard_logging()
        super(GeventProtocolProxy, self).start()
        if self._signal_watcher is None:
            self._signal_watcher = signal_handler(signal.SIGTERM, self._on_terminate_signal)
        self._greenlets = [spawn(self.select_loop),
                           spawn(self.send_registration, cast(GeventProtocolProxyPeer, self.peers[self.manager])),
                           spawn(self.main_loop),
                           spawn(self._watch_manager)]
        return self._greenlets

    def run(self) -> int:
        """Start and block until stopped. Returns a process exit code."""
        try:
            joinall(self.start(), raise_error=True)
        finally:
            self.stop()
            if self._signal_watcher is not None:        # stop() ran from the signal handler and kept it armed
                self._signal_watcher.cancel()
                self._signal_watcher = None
        return 0 if self.registered else 1
