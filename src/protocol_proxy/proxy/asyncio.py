import asyncio
import json
import logging
import os
import signal

from abc import ABC
from typing import cast
from uuid import UUID

from ..ipc.asyncio import AsyncioIPCConnector, Future, AsyncioProtocolProxyPeer, SocketParams
from ..logs import write_json_line
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
        self.peers[manager_id] = AsyncioProtocolProxyPeer(proxy_id=manager_id, token=manager_token, key=self.manager_key,
                                                          tls=self.manager_tls,
                                                          socket_params=None if self.manager_dials else self.manager_params)
        self.registration_attempts = registration_attempts
        self.registration_timeout = registration_timeout
        self.registered = False
        self._stopping = False
        self._log_flusher: asyncio.Task | None = None

    def get_local_socket_params(self) -> SocketParams:
        if self.inbound_server is None:
            raise RuntimeError(f'{self.proxy_name}: start() must be called before registering with the manager.')
        # Only take first 2 elements (host, port) from getsockname()
        # IPv6 sockets return 4-tuple (host, port, flowinfo, scope_id)
        sockname = self.inbound_server.sockets[0].getsockname()
        return SocketParams(sockname[0], sockname[1])

    async def _wait_for_manager(self):
        waited = 0.0
        while not self._stopping and not self.manager_linked():
            if waited % self.MANAGER_WAIT_LOG_INTERVAL < 0.1:
                _log.info(f'{self.proxy_name}: waiting for the manager to connect to {self.inbound_params}.')
            await asyncio.sleep(0.1)
            waited += 0.1

    async def send_registration(self, remote: AsyncioProtocolProxyPeer) -> bool:
        if self.manager_dials:
            await self._wait_for_manager()
            if self._stopping:
                return False
        for attempt in range(1, self.registration_attempts + 1):
            try:
                message = self._get_registration_message()
                manager_response = await self.send(remote, message)
                if isinstance(manager_response, Future):
                    manager_response = await asyncio.wait_for(manager_response, timeout=self.registration_timeout)
                success = self.registration_accepted(remote, manager_response)
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

    async def _watch_manager(self):
        while self.manager_alive():
            await asyncio.sleep(self.manager_watch_interval)
        self._manager_lost = True
        try:
            result = self.on_manager_lost()
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            _log.exception(f'{self.proxy_name}: stopping after the manager was lost raised; exiting.')
            os._exit(1)

    def _start_log_flusher(self):
        self._log_flusher = self.loop.create_task(self._flush_logs_loop())

    async def _flush_logs_loop(self):
        try:
            while not self._stopping and self.log_handler is not None:
                waited = 0.0
                while (not self._stopping and self.log_handler is not None and waited < self.LOG_FLUSH_INTERVAL
                       and len(self.log_handler) < self.LOG_BATCH_SIZE):
                    await asyncio.sleep(0.02)
                    waited += 0.02
                await self.flush_logs()
        except asyncio.CancelledError:
            pass

    async def flush_logs(self):
        """Ship one LOG batch to the manager (no response expected); records that cannot be sent go to stderr."""
        if (message := self.log_batch_message(self.LOG_BATCH_SIZE)) is None:
            return
        try:
            sent = await self.send(cast(AsyncioProtocolProxyPeer, self.peers[self.manager]), message)
        except Exception:
            sent = False
        if sent is False:
            for fields in json.loads(message.payload)['records']:
                write_json_line(fields)

    async def stop(self):
        """Stop serving. A protocol overrides this to close its sessions and flush state first, then calls super."""
        self._stopping = True
        if self._log_flusher is not None:
            self._log_flusher.cancel()
            self._log_flusher = None
        self.stop_socket_logging()
        if self.inbound_server is not None:
            await super(AsyncioProtocolProxy, self).stop()

    def _on_terminate_signal(self, signum: int):
        """SIGTERM is how the manager stops a proxy: stop gracefully so protocols get to flush their state."""
        if self._stopping:
            return
        _log.info(f'{self.proxy_name}: received {signal.Signals(signum).name}; stopping.')
        self.arm_hard_exit(signal.Signals(signum).name)

        def stopped(task: asyncio.Task):
            if not task.cancelled() and task.exception() is not None:
                _log.error(f'{self.proxy_name}: stop() raised on {signal.Signals(signum).name}: {task.exception()!r}; exiting.')
                os._exit(1)
        self.loop.create_task(self.stop()).add_done_callback(stopped)

    async def start(self):
        """Create the inbound server, register with the manager, then serve until stopped, terminated or orphaned."""
        self.guard_logging()
        await super(AsyncioProtocolProxy, self).start()
        if not await self.send_registration(cast(AsyncioProtocolProxyPeer, self.peers[self.manager])):
            raise RuntimeError(f'{self.proxy_name}: registration with the Proxy Manager failed.')
        self.on_registered()
        watchdog = asyncio.ensure_future(self._watch_manager())
        try:
            self.loop.add_signal_handler(signal.SIGTERM, self._on_terminate_signal, signal.SIGTERM)
        except (RuntimeError, ValueError, NotImplementedError) as e:     # not the main thread, or no loop support
            _log.debug(f'{self.proxy_name}: no SIGTERM handler installed: {e}')
        try:
            async with self.inbound_server:
                await self.inbound_server.serve_forever()
        except asyncio.CancelledError:
            if not (self._manager_lost or self._stopping):      # closing the server from stop() cancels serve_forever
                raise
        finally:
            watchdog.cancel()
            try:
                self.loop.remove_signal_handler(signal.SIGTERM)
            except (RuntimeError, ValueError, NotImplementedError):
                pass
