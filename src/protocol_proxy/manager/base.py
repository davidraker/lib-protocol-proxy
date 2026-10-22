import json
import logging
import os
import sys
import time

from abc import abstractmethod, ABC
from importlib import import_module
from inspect import ismethod
from typing import Callable, Iterable, Type, TypeVar
from uuid import uuid4, UUID
from weakref import WeakMethod, WeakValueDictionary

from ..ipc import IPCConnector, ProtocolHeaders, ProtocolProxyMessage, ProtocolProxyPeer, SocketParams
from ..logs import LAUNCHED_BY_MANAGER_ENV, handle_log_batch, log_entries, proxy_logger_name
from ..proxy import ProtocolProxy
from ..proxy.launch import str2bool

_log = logging.getLogger(__name__)


Self = TypeVar("Self", bound="ProtocolProxyManager")  # TODO: Deprecated by typing.Self in 3.11 and later.

class ProtocolProxyManager(IPCConnector, ABC):
    managers = WeakValueDictionary()

    def __init__(self, *, proxy_class: Type[ProtocolProxy], proxy_name: str = 'Manager',
                 heartbeat_interval: float = 10.0, heartbeat_timeout: float = 5.0, heartbeat_misses: int = 3,
                 **kwargs):
        self.unique_ids = {}
        super().__init__(proxy_id=self.get_proxy_id('proxy_manager'), proxy_name=proxy_name, token=uuid4(), **kwargs)
        self.proxy_class = proxy_class
        # Heartbeat: PING every registered peer each interval; a peer that misses ``heartbeat_misses`` replies in a
        # row is lost (same path as a process exit). 0 disables. The flavour's loop starts with the first get_proxy.
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout
        self.heartbeat_misses = heartbeat_misses
        # Weak references to ``callback(peer, reason)`` callables, told when a launched proxy is lost (see on_peer_lost).
        self.peer_lost_callbacks: list = []
        self.register_callback(self.handle_peer_registration, 'REGISTER_PEER', provides_response=True)
        self.register_callback(self.handle_log, 'LOG')

    def on_peer_lost(self, callback: Callable[[ProtocolProxyPeer, str], None]):
        """Call ``callback(peer, reason)`` whenever a proxy this manager launched is lost: its process exited, or it
        never registered. By then the peer is already removed, so the next ``get_proxy`` for its key launches a fresh
        process; users typically re-run their setup (``get_proxy`` + ``wait_peer_registered``) from the callback.
        Bound methods are held weakly, so a user object that goes away is forgotten with it; plain functions are
        held strongly."""
        self.peer_lost_callbacks.append(WeakMethod(callback) if ismethod(callback) else (lambda cb=callback: cb))

    def _notify_peer_lost(self, peer: ProtocolProxyPeer, reason: str):
        live = []
        for weak in self.peer_lost_callbacks:
            if (callback := weak()) is None:
                continue
            live.append(weak)
            try:
                callback(peer, reason)
            except Exception as e:
                _log.warning(f'PPM: peer-lost callback {callback} raised for peer {peer.proxy_id}: {e}')
        self.peer_lost_callbacks = live

    @abstractmethod
    def wait_peer_registered(self, peer, timeout, func=None, *args, **kwargs):
        """ Waits for a peer to be ready, optionally calling a function when it is.
            - if a func is passed, run it with any passed args/kwargs once the peer is ready.
        #  - remove the peer (and logs a warning) if it times out without registering.
        """

    def _setup_proxy_process_command(self, unique_remote_id: tuple, **kwargs) -> tuple:
        #_log.debug(f'@@@@@@@@@ PASSED UAI is: {unique_remote_id}')
        unique_remote_id = self.proxy_class.get_unique_remote_id(unique_remote_id)
        #_log.debug(f'@@@@@@@@@ UAI AFTER LOOKUP is: {unique_remote_id}')
        proxy_id = self.get_proxy_id(unique_remote_id)
        #_log.debug('@@@@@@@@@ PROXY ID is: {}'.format(proxy_id))
        proxy_name = str(unique_remote_id)
        if proxy_id not in self.peers:
            #_log.debug(f'@@@@@@@@@ PROXY_ID IS NOT IN PEERS. SETTING UP COMMAND.')
            module, func = self.proxy_class.__module__, self.proxy_class.__name__
            kwargs = {k: v for k, v in kwargs.items() if k != 'manager_callbacks' and v is not None}
            # The proxy logs at the level this manager would handle its records at, unless the caller chose one.
            kwargs.setdefault('log_level', logging.getLevelName(self.proxy_logger(proxy_name).getEffectiveLevel()))
            protocol_specific_params = [i for pair in [(f"--{k.replace('_', '-')}", str(v))
                                                       for k, v in kwargs.items()] for i in pair]
            # Launched through the generic entry point so the proxy module is imported exactly once (see launch.main).
            entry_options = ['--gevent'] if getattr(self.proxy_class, 'PATCH_GEVENT', False) else []
            command = [sys.executable, '-m', 'protocol_proxy.proxy', *entry_options, f'{module}:{func}',
                       '--proxy-id', proxy_id.hex, '--proxy-name', proxy_name,
                       '--manager-id', self.proxy_id.hex, '--manager-address', self.inbound_params.address,
                       '--manager-port', str(self.inbound_params.port), *protocol_specific_params]
        else:
            #_log.debug(f'@@@@@@@@@ PROXY_ID IS IN PEERS. NOT SETTING UP COMMAND.')
            command = None
        return command, proxy_id, proxy_name

    @classmethod
    @abstractmethod
    def get_proxy(cls, unique_remote_id: tuple, **kwargs) -> tuple[Self, ProtocolProxyPeer] | None:
        """ Get or create a ProtocolProxyPeer for the specified unique_remote_id.
                NOTE: Subclasses are required to implement this method, but
                    should not call super. The class method is a convenience wrapper
                    to handle the case where the ProtocolProxyManager instance needs
                    to be found as well.  This is useful, for instance, where multiple
                    protocols may be employed by a single user as there will be one
                    concrete ProtocolProxyManager per protocol.
        """
        if isinstance(cls, ProtocolProxyManager):
            _log.warning(f'Subclass {cls.__class__.__name__} improperly called super on abstract method get_proxy().')
        if len(unique_remote_id) >= 1:
            likely_module = unique_remote_id[0]
            try:
                manager = cls.get_manager(likely_module, kwargs.pop('manager_callbacks', None))
                return manager, manager.get_proxy(unique_remote_id, **kwargs)
            except (ImportError, ValueError) as e:
                _log.warning(f'Unable to find a manager for get_proxy call: {e}')
        return None

    def get_proxy_id(self, unique_remote_id: tuple | str) -> UUID:
        """Lookup or create a UUID for the proxy server
         given a unique_remote_id and protocol-specific set of parameters."""
        proxy_id = self.unique_ids.get(unique_remote_id)
        if not proxy_id:
            proxy_id = uuid4()
            self.unique_ids[unique_remote_id] = proxy_id
        return proxy_id

    def handle_peer_registration(self, headers: ProtocolHeaders, raw_message: bytes):
        message = json.loads(raw_message.decode('utf8'))
        proxy: ProtocolProxyPeer = self.peers.get(headers.sender_id)
        if not proxy:
            _log.error(f'PPM: Received registration message from unknown peer: {headers.sender_id}.')
            return json.dumps(False).encode('utf8')
        if  (address := message.get('address')) and (port := message.get('port')):
            proxy.socket_params = SocketParams(address=address, port=port)
            proxy.features = tuple(message.get('features') or ())
            proxy.mark_registered()
            _log.info(f'PPM: Successfully registered peer: {proxy.proxy_id} @ {proxy.socket_params}'
                      f' (features: {", ".join(proxy.features) or "none"})')
            return json.dumps({'registered': True, 'features': list(self.FEATURES)}).encode('utf8')
        else:  # TODO: Is there any reasonable situation where this runs and returns false?
            _log.error(f'PPM: Failed to register peer: {proxy.proxy_id} with message: {message}.')
            return json.dumps(False).encode('utf8')

    # ---- heartbeat and health ------------------------------------------------------------------------------------
    def ping_message(self) -> ProtocolProxyMessage:
        return ProtocolProxyMessage(method_name='PING', payload=b'', response_expected=True)

    def peers_to_ping(self) -> list[ProtocolProxyPeer]:
        """Registered peers launched by this manager (those with a process); a peer still registering is skipped."""
        return [peer for peer in list(self.peers.values())
                if peer.socket_params is not None and getattr(peer, 'process', None) is not None]

    def heartbeat_answered(self, peer: ProtocolProxyPeer, raw_reply) -> None:
        """A PING reply (any reply: an old proxy answers with an unknown-method error, which still proves it alive)."""
        peer.last_seen = time.time()
        peer.missed = 0
        peer.state = 'healthy'
        try:
            report = json.loads(raw_reply.decode('utf8') if isinstance(raw_reply, (bytes, bytearray)) else raw_reply)
            peer.health = report if isinstance(report, dict) and report.get('status') != 'error' else peer.health
        except (ValueError, TypeError, AttributeError):
            pass

    def heartbeat_missed(self, peer: ProtocolProxyPeer, why: str) -> bool:
        """A PING went unanswered. Returns True when the peer has now missed enough to be considered lost; the
        flavour then runs its peer-lost path."""
        if self.peers.get(peer.proxy_id) is not peer:
            return False                    # already replaced or removed; nothing more to do
        peer.missed += 1
        peer.state = 'unhealthy'
        lost = peer.missed >= self.heartbeat_misses
        _log.log(logging.WARNING if lost else logging.INFO,
                 f'PPM: {peer.name or peer.proxy_id} missed heartbeat {peer.missed} of {self.heartbeat_misses} ({why}).')
        if lost:
            peer.state = 'lost'
        return lost

    def health(self) -> dict[str, dict]:
        """Liveness of every peer this manager knows, keyed by proxy name (id when unnamed): the state machine
        (launching, registered, healthy, unhealthy, lost), when it was last heard from, consecutive misses, the
        features it advertised, its pid, and its last PING report."""
        report = {}
        for peer in list(self.peers.values()):
            process = getattr(peer, 'process', None)
            report[peer.name or str(peer.proxy_id)] = {
                'proxy_id': str(peer.proxy_id), 'state': peer.state, 'last_seen': peer.last_seen,
                'missed': peer.missed, 'features': list(peer.features), 'persistent': self.is_persistent(peer),
                'connected': peer.connection is not None and peer.connection.alive,
                'pid': getattr(process, 'pid', None), 'report': peer.health}
        return report

    def handle_log(self, headers: ProtocolHeaders, raw_message: bytes):
        """A LOG batch from a registered proxy: its records are handled through the proxy's logger exactly like
        lines read from its stderr (see protocol_proxy.logs.handle_log_batch)."""
        peer: ProtocolProxyPeer = self.peers.get(headers.sender_id)
        if peer is None:
            _log.warning(f'PPM: LOG batch from unknown peer {headers.sender_id} ignored.')
            return
        name = peer.name if peer.name is not None else str(peer.proxy_id)
        pid = getattr(getattr(peer, 'process', None), 'pid', None)
        try:
            handle_log_batch(raw_message, self.proxy_logger(name), pid=pid, process_name=name)
        except (ValueError, TypeError, UnicodeDecodeError) as e:
            _log.warning(f'PPM: Undecodable LOG batch from {name}: {e}')

    def set_proxy_log_level(self, peer: ProtocolProxyPeer, level: str | int):
        """Change a running proxy's log level (``SET_LOG_LEVEL``) and gate its records here at the same level.
        Returns what ``send`` returns: the pending reply (``{"level": ...}``) or False."""
        level_name = logging.getLevelName(level) if isinstance(level, int) else str(level).upper()
        name = peer.name if peer.name is not None else str(peer.proxy_id)
        self.proxy_logger(name).setLevel(level_name)
        return self.send(peer, ProtocolProxyMessage(method_name='SET_LOG_LEVEL',
                                                    payload=json.dumps({'level': level_name}).encode('utf8'),
                                                    response_expected=True))

    @classmethod
    def get_manager(cls, proxy_class: Type[ProtocolProxy] | str,
                    manager_callbacks: Iterable[tuple[Callable, str]] = None) -> Self:
        """Get or create a ProtocolProxyManager for the specified proxy class.
            If a string is passed, it will attempt to import the class from the
            protocol_proxy.protocol.<name> module.
           :raises: ValueError | ImportError
        """
        if isinstance(proxy_class, str):
            try:
                module = import_module('protocol_proxy.protocol.' + proxy_class)
                if hasattr(module, 'PROXY_CLASS'):
                    proxy_class = module.PROXY_CLASS
            except ImportError as e:
                raise ImportError(f'Failed to import proxy class "{proxy_class}": {e}')
        if not isinstance(proxy_class, type) or not issubclass(proxy_class, ProtocolProxy):
            raise ValueError(f'Unable to find the specified ProtocolProxy subclass, got {proxy_class}.')

        if proxy_class.__name__ in cls.managers:
            manager = cls.managers[proxy_class.__name__]
        else:
            _log.info(f'Creating manager of class "{cls.__name__}" for new proxies of class: ({proxy_class.__name__}).')
            manager = cls(proxy_class=proxy_class)
            for callback in manager_callbacks or []:
                if not callable(callback[0]) or not isinstance(callback[1], str):
                    _log.warning(f'Attempted to register invalid callback for'
                                 f' ProtocolProxyManager[{proxy_class.__name__}]: {callback}.'
                                 ' Callback parameters must be (Callable, str)')
                    continue
                manager.register_callback(*callback)
            cls.managers[proxy_class.__name__] = manager
        return manager

    @classmethod
    def get_by_proxy_id(cls, proxy_id: UUID) -> tuple[Self | None, ProtocolProxyPeer | None]:
        for manager in cls.managers.values():
            if proxy_id in manager.peers:
                return manager, manager.peers[proxy_id]
        return None, None

    @staticmethod
    def peer_policy(kwargs: dict) -> bool | None:
        """The connection policy for a proxy launched with these options: ``persistent`` (bool or its command-line
        spelling) when given, else None for the manager's default. The option travels to the proxy as ``--persistent``
        with every other kwarg, so both ends apply the same policy."""
        value = kwargs.get('persistent')
        return None if value is None else str2bool(value)

    def proxy_logger(self, proxy_name: str) -> logging.Logger:
        """The logger a launched proxy's records are handled through in this process:
        ``protocol_proxy.proxies.<ProxyClass>.<proxy name>``. Its effective level gates the records and is passed
        to the proxy as ``--log-level``, so operators tune a proxy like any other logger."""
        return logging.getLogger(proxy_logger_name(self.proxy_class.__name__, proxy_name))

    @staticmethod
    def proxy_environment() -> dict[str, str]:
        """Environment for a launched proxy: the manager's, plus the marker that selects the JSON log channel."""
        return {**os.environ, LAUNCHED_BY_MANAGER_ENV: '1'}

    def log_subprocess_output(self, stream, logger: logging.Logger, stream_name: str = 'stderr',
                              pid: int | None = None, process_name: str | None = None):
        """Read one of a launched proxy's pipes to its end, handling each line as a record of ``logger`` (see
        protocol_proxy.logs.log_entries). Asyncio managers override this with a coroutine."""
        log_entries(iter(stream.readline, b''), logger, stream_name=stream_name, pid=pid, process_name=process_name)
