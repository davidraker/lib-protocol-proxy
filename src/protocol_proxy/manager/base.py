import json
import logging
import os
import sys
import time

from abc import abstractmethod, ABC
from inspect import ismethod
from typing import Callable, Iterable, Type, TypeVar
from uuid import uuid4, UUID
from weakref import WeakMethod, WeakValueDictionary

from ..ipc import IPCConnector, ProtocolHeaders, ProtocolProxyMessage, ProtocolProxyPeer, SocketParams
from ..logs import LAUNCHED_BY_MANAGER_ENV, handle_log_batch, log_entries, proxy_logger_name
from ..manifest import Manifest, find as find_manifest
from ..tls import Authority, TlsMaterial
from ..proxy import ProtocolProxy
from ..proxy.launch import str2bool

_log = logging.getLogger(__name__)


Self = TypeVar("Self", bound="ProtocolProxyManager")  # TODO: Deprecated by typing.Self in 3.11 and later.

class ProtocolProxyManager(IPCConnector, ABC):
    managers = WeakValueDictionary()

    def __init__(self, *, manifest: Manifest | None = None, proxy_class: Type[ProtocolProxy] | None = None,
                 proxy_name: str = 'Manager', heartbeat_interval: float = 10.0, heartbeat_timeout: float = 5.0,
                 heartbeat_misses: int = 3, ipc_tls: bool = False, **kwargs):
        if manifest is None:
            if proxy_class is None:
                raise ValueError('A manager needs a Manifest (or, for a Python proxy in this environment, its class).')
            manifest = Manifest.for_proxy_class(proxy_class)
        #: What this manager launches and how it keys the processes: see protocol_proxy.manifest.
        self.manifest: Manifest = manifest
        self.unique_ids = {}
        # The launch options the first remote of each process gave for the manifest's must_match keys.
        self.shared_options: dict[tuple, dict] = {}
        # TLS toward launched proxies: this manager is the certificate authority (created with the first TLS proxy)
        # and issues itself and each TLS proxy a certificate; ``ipc_tls`` here makes it the default for every proxy.
        self.tls_default: bool = ipc_tls
        self.authority: Authority | None = None
        super().__init__(proxy_id=self.get_proxy_id('proxy_manager'), proxy_name=proxy_name, token=uuid4(), **kwargs)
        # Heartbeat: PING every registered peer each interval; a peer that misses ``heartbeat_misses`` replies in a
        # row is lost (same path as a process exit). 0 disables. The flavour's loop starts with the first get_proxy.
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout
        self.heartbeat_misses = heartbeat_misses
        self.stopping_pids: set[int] = set()        # processes this manager is terminating: not heartbeat misses
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
        key = self.manifest.process_key(unique_remote_id, kwargs)
        if (first := self.shared_options.get(key)) is not None:
            if conflicts := self.manifest.identity.conflicts(first, kwargs):
                raise ValueError(f'Remote {unique_remote_id} would share proxy process {key} but differs in '
                                 f'{", ".join(conflicts)}, which the {self.manifest.name} manifest requires to match.')
        else:
            self.shared_options[key] = {k: kwargs.get(k) for k in self.manifest.identity.must_match}
        proxy_id = self.get_proxy_id(key)
        proxy_name = str(key)
        if proxy_id not in self.peers:
            prefix, python, _ = self.launcher_prefix(kwargs)
            if prefix and kwargs.get('ssh_forward', True) and 'manager_address' not in kwargs:
                kwargs = {**kwargs, 'manager_address': '127.0.0.1'}      # the forwarded port on the proxy's host
            kwargs = {k: v for k, v in kwargs.items() if k not in self.MANAGER_ONLY_OPTIONS and v is not None}
            # The proxy logs at the level this manager would handle its records at, unless the caller chose one.
            kwargs.setdefault('log_level', logging.getLevelName(self.proxy_logger(proxy_name).getEffectiveLevel()))
            if self.encrypt:
                kwargs.setdefault('encrypt', True)      # the proxy must read the key the manager writes to stdin
            if str2bool(kwargs.get('encrypt', False)):
                kwargs.setdefault('cipher', self.cipher)    # one choice for both ends unless the caller says otherwise
            if self.tls_default:
                kwargs.setdefault('ipc_tls', True)      # and the TLS material after it
            manager_address = kwargs.pop('manager_address', self.inbound_params.address)
            protocol_specific_params = [i for pair in [(f"--{k.replace('_', '-')}", str(v))
                                                       for k, v in kwargs.items()] for i in pair]
            # The manifest's command (its {python} is this interpreter, or the remote one behind an SSH prefix),
            # then the standard options every proxy takes, then the protocol-specific launch options.
            command = [*prefix, *self.manifest.launch_command(python, [
                       '--proxy-id', proxy_id.hex, '--proxy-name', proxy_name,
                       '--manager-id', self.proxy_id.hex, '--manager-address', str(manager_address),
                       '--manager-port', str(self.inbound_params.port), *protocol_specific_params])]
        else:
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
            except (LookupError, ValueError) as e:
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
            cipher = message.get('cipher')
            _log.info(f'PPM: Successfully registered peer: {proxy.proxy_id} @ {proxy.socket_params}'
                      f' (features: {", ".join(proxy.features) or "none"}'
                      f'{f"; encrypts with {cipher}" if cipher and proxy.key else ""})')
            return json.dumps({'registered': True, 'features': list(self.FEATURES)}).encode('utf8')
        else:  # TODO: Is there any reasonable situation where this runs and returns false?
            _log.error(f'PPM: Failed to register peer: {proxy.proxy_id} with message: {message}.')
            return json.dumps(False).encode('utf8')

    # ---- heartbeat and health ------------------------------------------------------------------------------------
    def ping_message(self) -> ProtocolProxyMessage:
        return ProtocolProxyMessage(method_name='PING', payload=b'', response_expected=True)

    def peers_to_ping(self) -> list[ProtocolProxyPeer]:
        """Registered peers launched by this manager (those with a process); a peer still registering, or one whose
        process this manager is stopping, is skipped (a stopping proxy refuses connections, which is not a miss)."""
        return [peer for peer in list(self.peers.values())
                if peer.socket_params is not None and (process := getattr(peer, 'process', None)) is not None
                and getattr(process, 'pid', None) not in self.stopping_pids]

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
    def get_manager(cls, proxy: Manifest | Type[ProtocolProxy] | str,
                    manager_callbacks: Iterable[tuple[Callable, str]] = None) -> Self:
        """Get or create the ProtocolProxyManager for a proxy: by its manifest, by name (the manifest is found through
        protocol_proxy.manifest: the PROTOCOL_PROXY_MANIFESTS directories, then the protocol_proxy.manifests entry
        points), or, for a Python proxy class in this environment, by the class itself.
           :raises: LookupError (no manifest of that name) | ValueError
        """
        if isinstance(proxy, str):
            manifest = find_manifest(proxy)
        elif isinstance(proxy, Manifest):
            manifest = proxy
        elif isinstance(proxy, type) and issubclass(proxy, ProtocolProxy):
            manifest = Manifest.for_proxy_class(proxy)
        else:
            raise ValueError(f'Expected a Manifest, a proxy name or a ProtocolProxy subclass, got {proxy!r}.')

        if manifest.name in cls.managers:
            manager = cls.managers[manifest.name]
        else:
            _log.info(f'Creating manager of class "{cls.__name__}" for new proxies of {manifest.name}.')
            manager = cls(manifest=manifest)
            for callback in manager_callbacks or []:
                if not callable(callback[0]) or not isinstance(callback[1], str):
                    _log.warning(f'Attempted to register invalid callback for'
                                 f' ProtocolProxyManager[{manifest.name}]: {callback}.'
                                 ' Callback parameters must be (Callable, str)')
                    continue
                manager.register_callback(*callback)
            cls.managers[manifest.name] = manager
        return manager

    @classmethod
    def get_by_proxy_id(cls, proxy_id: UUID) -> tuple[Self | None, ProtocolProxyPeer | None]:
        for manager in cls.managers.values():
            if proxy_id in manager.peers:
                return manager, manager.peers[proxy_id]
        return None, None

    def peer_tls(self, kwargs: dict) -> bool:
        """Whether a proxy launched with these options talks TLS on the IPC: the ``ipc_tls`` kwarg when given, else the
        manager's default (``tls`` is left to protocols, e.g. the MQTT proxy's broker TLS)."""
        value = kwargs.get('ipc_tls')
        return self.tls_default if value is None else str2bool(value)

    def tls_material_for(self, proxy_id: UUID) -> TlsMaterial:
        """Issue a TLS proxy its certificate (and give this manager its own, the first time)."""
        if self.authority is None:
            self.authority = Authority(f'protocol-proxy manager {self.proxy_id}')
            addresses = [self.inbound_params.address] if self.inbound_params is not None else []
            self.tls_material = self.authority.issue(self.proxy_id.hex, addresses)
            self._tls_contexts.clear()
        return self.authority.issue(proxy_id.hex)

    def peer_encrypted(self, kwargs: dict) -> bool:
        """Whether a proxy launched with these options gets an AEAD key: the ``encrypt`` kwarg when given (it travels
        to the proxy as ``--encrypt``), else this manager's own ``encrypt`` setting."""
        value = kwargs.get('encrypt')
        return self.encrypt if value is None else str2bool(value)

    #: get_proxy kwargs the manager consumes itself; everything else travels to the proxy as ``--name value``.
    MANAGER_ONLY_OPTIONS = frozenset({'manager_callbacks', 'dial', 'ssh_host', 'ssh_options', 'ssh_forward',
                                      'remote_python', 'remote_env'})
    SSH_BASE_OPTIONS = ('-o', 'BatchMode=yes')

    def launcher_prefix(self, kwargs: dict) -> tuple[list[str], str, dict[str, str]]:
        """How the proxy command is wrapped: ``(prefix, python, env)``. Locally the prefix is empty, python is this
        interpreter and env is the manager's with the launch marker. With ``ssh_host`` the prefix is
        ``ssh -o BatchMode=yes [-R <manager port>:127.0.0.1:<manager port>] [ssh_options...] host`` and the remote
        command is ``env <marker> [remote_env...] <remote_python> -m protocol_proxy.proxy ...``: the same argument
        list, tokens (and key) still on stdin, logs still on the pipes. The reverse forward (``ssh_forward``, default
        True) lets the proxy dial ``127.0.0.1:<manager port>`` on its host and reach this manager; with persistent
        connections the manager never needs to dial the proxy, so no forward the other way is required."""
        env = self.proxy_environment()
        if not (host := kwargs.get('ssh_host')):
            return [], sys.executable, env
        prefix = ['ssh', *self.SSH_BASE_OPTIONS]
        if kwargs.get('ssh_forward', True) and self.inbound_params is not None:
            port = self.inbound_params.port
            prefix += ['-R', f'{port}:127.0.0.1:{port}']
        prefix += [*(kwargs.get('ssh_options') or []), str(host), 'env', f'{LAUNCHED_BY_MANAGER_ENV}=1']
        prefix += [f'{k}={v}' for k, v in (kwargs.get('remote_env') or {}).items()]
        return prefix, str(kwargs.get('remote_python') or 'python3'), env

    @staticmethod
    def dial_target(kwargs: dict) -> SocketParams | None:
        """Where the manager must dial a proxy launched with ``manager_dials=True``: the ``dial`` kwarg
        ``(address, port)``, else the proxy's ``inbound_address``/``inbound_port`` launch options (which the proxy
        listens on). None for a proxy that dials in itself."""
        if not str2bool(kwargs.get('manager_dials', False)):
            return None
        if (dial := kwargs.get('dial')) is not None:
            return SocketParams(*dial)
        port = kwargs.get('inbound_port')
        if port is None:
            raise ValueError('manager_dials=True needs the proxy\'s inbound_port (and inbound_address) or a dial=(address, port)')
        return SocketParams(kwargs.get('inbound_address') or 'localhost', int(port))

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
        return logging.getLogger(proxy_logger_name(self.manifest.name, proxy_name))

    def proxy_environment(self, python: str | None = None) -> dict[str, str]:
        """Environment for a launched proxy: the manager's, the manifest's (with ``{python}`` and ``{manifest_dir}``
        resolved), and the marker that selects the JSON log channel."""
        return {**os.environ, **self.manifest.launch_environment(python or sys.executable), LAUNCHED_BY_MANAGER_ENV: '1'}

    def log_subprocess_output(self, stream, logger: logging.Logger, stream_name: str = 'stderr',
                              pid: int | None = None, process_name: str | None = None):
        """Read one of a launched proxy's pipes to its end, handling each line as a record of ``logger`` (see
        protocol_proxy.logs.log_entries). Asyncio managers override this with a coroutine."""
        log_entries(iter(stream.readline, b''), logger, stream_name=stream_name, pid=pid, process_name=process_name)
