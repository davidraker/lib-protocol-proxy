import abc
import json
import logging
import os
import sys
import time

from datetime import datetime, timezone

from importlib import import_module
from pkgutil import iter_modules
from typing import ClassVar
from uuid import UUID

from ..ipc import callback, IPCConnector, ProtocolHeaders, ProtocolProxyMessage, ProtocolProxyPeer, SocketParams
from ..logs import guard_logging, SocketLogHandler, switch_to_socket, switch_to_stderr

_log = logging.getLogger(__name__)


# noinspection PyMissingConstructor
class ProtocolProxy(IPCConnector, metaclass=abc.ABCMeta):
    # Name of a module-level function, in the same module as the subclass, which adds protocol-specific command-line
    # options: ``(ArgumentParser) -> (ArgumentParser, runner)`` where ``runner(**options)`` creates and starts the
    # proxy. None means the proxy takes no options and is launched as ``cls(**options).start()``.
    LAUNCHER: ClassVar[str | None] = None
    # Whether the proxy process must be gevent monkey-patched before this module is imported.
    PATCH_GEVENT: ClassVar[bool] = False

    # LOG batches: flushed every LOG_FLUSH_INTERVAL seconds or as soon as LOG_BATCH_SIZE records are queued.
    LOG_FLUSH_INTERVAL = 0.2
    LOG_BATCH_SIZE = 64

    def __init__(self, *, manager_address: str, manager_port: int, manager_id: UUID,
                 registration_retry_delay: float = 20.0, manager_watch_interval: float = 1.0,
                 socket_logging: bool = True, key: bytes | None = None, manager_dials: bool = False,
                 ipc_tls=None, **kwargs):
        """NOTE: Proxy implementations MUST:
            1. Subclass a multitasking subclass of IPCConnector (gevent, asyncio, etc.)
            2. Subclass this "ProtocolProxy" class.
            3. Call super first to IPCConnector parent then this ProtocolProxy parent._
            4. Create a ProtocolProxyPeer subclass for the manager and store it in self.peers.
            5. Call send_registration asynchronously in their constructor after super calls.
        """
        #_log.debug('PP: IN INIT.')
        super(ProtocolProxy, self).__init__(tls_material=ipc_tls, **kwargs)
        # The AEAD key the manager wrote to stdin after the tokens (None: clear text). Flavours put it on their
        # manager peer, so every frame to and from the manager is encrypted. With TLS material, every connection with
        # the manager is TLS, mutually authenticated against the manager's CA.
        self.manager_key: bytes | None = key
        self.manager_tls: bool = ipc_tls is not None
        if self.encrypt and key is None:
            raise ValueError(f'{self.proxy_name}: --encrypt is set but no key was provided on stdin.')
        self.registration_retry_delay: float = registration_retry_delay
        # A proxy that cannot reach the manager's address (behind NAT, or started where the manager is not reachable)
        # waits for the manager to connect to its listener instead and registers over that connection; the manager
        # authenticates itself with the id and token this proxy was launched with, as on any frame.
        self.manager_dials: bool = manager_dials
        self.manager_params = SocketParams(manager_address, manager_port)
        self.manager = manager_id
        # The manager is the parent process. If it dies, this proxy is an orphan: it would hold its listeners and
        # ports while a restarted manager launches a replacement, so the run loops watch the parent and stop.
        self.manager_watch_interval: float = manager_watch_interval
        self._parent_pid: int = os.getppid()
        self._manager_lost: bool = False
        # Once registered, records are shipped to the manager in LOG batches over the IPC socket instead of stderr
        # (the channel every launch mode has, and the encrypted one when the IPC is). stderr still carries everything
        # before registration and whatever is left in the queue at exit.
        self.socket_logging: bool = socket_logging
        self.log_handler: SocketLogHandler | None = None
        self.register_callback(self.handle_set_log_level, 'SET_LOG_LEVEL', provides_response=True)
        self.register_callback(self.handle_ping, 'PING', provides_response=True)
        self.apply_plugins()

    # ---- liveness -------------------------------------------------------------------------------------------------
    #: Advertised in REGISTER_PEER so the manager knows what this proxy answers.
    FEATURES: ClassVar[tuple[str, ...]] = ('ping', 'log', 'set_log_level', 'compress', 'aead-chacha20poly1305',
                                           'aead-aes256gcm')
    MANAGER_WAIT_LOG_INTERVAL = 30.0

    def manager_linked(self) -> bool:
        """Whether the manager has an open persistent connection to this proxy (adopted or dialled)."""
        peer = self.peers.get(self.manager)
        return peer is not None and peer.connection is not None and peer.connection.alive

    def registration_accepted(self, remote: ProtocolProxyPeer, manager_response) -> bool:
        """Read the manager's REGISTER_PEER reply: ``{"registered": true, "features": [...]}`` from a current manager
        (its features are recorded on the peer, e.g. to compress toward it), plain ``true``/``false`` from an older
        one. Returns whether registration was accepted."""
        if isinstance(manager_response, (bytes, bytearray)):
            try:
                manager_response = json.loads(manager_response.decode('utf8'))
            except (ValueError, UnicodeDecodeError):
                return False
        if isinstance(manager_response, dict):
            remote.features = tuple(manager_response.get('features') or ())
            return bool(manager_response.get('registered', manager_response.get('status') != 'error'))
        return bool(manager_response)

    def health_report(self) -> dict:
        """What a PING reply carries. ``remotes`` is protocol-specific: the base counts the remotes with their own
        callbacks registered; a protocol may override to report what it actually serves, and set ``busy`` while a
        long operation is in progress."""
        last = self.last_activity
        return {'uptime': round(time.time() - self.started_at, 3),
                'remotes': len({remote_id for _, remote_id in self.remote_callbacks}),
                'busy': False,
                'last_activity': datetime.fromtimestamp(last, timezone.utc).isoformat() if last else None}

    @callback
    def handle_ping(self, headers: ProtocolHeaders, raw_message: bytes) -> bytes:
        """The manager's heartbeat: reply with the health report."""
        return json.dumps(self.health_report(), default=str).encode('utf8')

    # ---- logging over the socket ----------------------------------------------------------------------------------
    def on_registered(self):
        """Called once registration with the manager has succeeded. Starts shipping logs over the socket."""
        if self.socket_logging and self.log_handler is None:
            handler = SocketLogHandler()
            if switch_to_socket(handler):
                self.log_handler = handler
                self._start_log_flusher()
                _log.info(f'{self.proxy_name}: logging over the IPC socket from here on.')

    def _start_log_flusher(self):
        """Flavours start their periodic ``flush_logs`` here."""

    def log_batch_message(self, limit: int | None = None) -> ProtocolProxyMessage | None:
        """The next LOG push (``{"records": [...], "dropped": n}``), or None when nothing is queued."""
        if self.log_handler is None:
            return None
        records, dropped = self.log_handler.drain(limit)
        if not records and not dropped:
            return None
        payload = json.dumps({'records': records, 'dropped': dropped}, default=str).encode('utf8')
        return ProtocolProxyMessage(method_name='LOG', payload=payload, low_priority=True)

    def stop_socket_logging(self):
        """Back to stderr: what is still queued goes out as JSON lines there, so the manager reads it from the pipe."""
        if self.log_handler is not None:
            handler, self.log_handler = self.log_handler, None
            switch_to_stderr(handler)

    @callback
    def handle_set_log_level(self, headers: ProtocolHeaders, raw_message: bytes) -> bytes:
        """``{"level": "DEBUG"}`` from the manager sets the root logger's level at run time; replies with the level
        in force. The manager gates on the same level on its side, so both ends agree."""
        try:
            level = json.loads(raw_message.decode('utf8')).get('level')
            if isinstance(level, str):
                level = level.upper()
            logging.getLogger().setLevel(level)
            _log.info(f'{self.proxy_name}: log level set to {logging.getLevelName(logging.getLogger().level)}.')
        except (ValueError, TypeError, AttributeError) as e:
            return json.dumps({'status': 'error', 'error': f'Invalid log level: {e}', 'method': 'SET_LOG_LEVEL'}).encode('utf8')
        return json.dumps({'level': logging.getLevelName(logging.getLogger().level)}).encode('utf8')

    def guard_logging(self):
        """Run from start(), once the protocol library is imported: strip handlers a library installed on its own
        loggers (they would print a second, plain copy of every record), logging which loggers had them. A no-op
        unless this process was configured by the launcher (see protocol_proxy.logs)."""
        guard_logging()

    def manager_alive(self) -> bool:
        """Whether the process that launched this proxy is still its parent (an orphan is re-parented)."""
        return os.getppid() == self._parent_pid

    def on_manager_lost(self):
        """Called once, from the run loop, when the manager process has gone. The default logs and stops the proxy;
        a protocol may override this to flush state first (and should still call super or stop)."""
        _log.warning(f'{self.proxy_name}: the manager process ({self._parent_pid}) is gone. Stopping.')
        return self.stop()      # a coroutine for asyncio proxies; the watchdog awaits it


    @abc.abstractmethod
    def get_local_socket_params(self) -> SocketParams:
        pass

    @classmethod
    @abc.abstractmethod
    def get_unique_remote_id(cls, unique_remote_id: tuple) -> tuple:
        """Get a unique identifier for the proxy server
         given a unique_remote_id and protocol-specific set of parameters."""
        pass

    @abc.abstractmethod
    def send_registration(self, remote: ProtocolProxyPeer) -> ProtocolProxyMessage:
        """Send a registration message to the remote manager."""

    def apply_plugins(self):
        module_name = type(self).__module__
        if module_name == '__main__':    # Running via "python -m"; runpy records the real name in __spec__.
            spec = getattr(sys.modules.get('__main__'), '__spec__', None)
            module_name = spec.name if spec else ''
        try:
            installed_plugins = import_module(f'protocol_proxy.plugins.protocol.{module_name.split(".")[2]}')
            for m in iter_modules(installed_plugins.__path__, installed_plugins.__name__ + '.'):
                if hasattr(m, 'name') and m.name.split('.')[-1]:
                    module = import_module(m.name)
                    if hasattr(module, 'PROXY_PLUGINS'):
                        for interface_plugin in module.PROXY_PLUGINS:
                            interface_plugin.plug_into(self)
        except ModuleNotFoundError:
            return
        except AttributeError as e:
            _log.warning(f'Unable to load plugin "{m.name}: {e}')
        except IndexError:
            _log.warning(f'Unable to determine protocol_type to load plugins (module: "{module_name}").')
        except Exception as e:
            _log.warning(f'Unexpected error loading plugins: {e}')

    def _get_registration_message(self):
        # _log.debug(f'{self.proxy_name}: IN GET REGISTRATION MESSAGE')
        local_address, local_port = self.get_local_socket_params()
        message = ProtocolProxyMessage(
            method_name='REGISTER_PEER',
            payload= json.dumps({'address': local_address, 'port':local_port, 'proxy_id': self.proxy_id.hex,
                                 'token': self.token.hex, 'features': list(self.FEATURES),
                                 'cipher': self.cipher}).encode('utf8'),
            response_expected=True
        )
        return message
