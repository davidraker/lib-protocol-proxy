import json
import logging
import sys

from abc import abstractmethod, ABC
from importlib import import_module
from typing import Callable, Iterable, Type, TypeVar
from uuid import uuid4, UUID
from weakref import WeakValueDictionary

from ..ipc import IPCConnector, ProtocolHeaders, ProtocolProxyPeer, SocketParams
from ..proxy import ProtocolProxy

_log = logging.getLogger(__name__)


Self = TypeVar("Self", bound="ProtocolProxyManager")  # TODO: Deprecated by typing.Self in 3.11 and later.

class ProtocolProxyManager(IPCConnector, ABC):
    managers = WeakValueDictionary()

    def __init__(self, *, proxy_class: Type[ProtocolProxy], proxy_name: str = 'Manager', **kwargs):
        self.unique_ids = {}
        super().__init__(proxy_id=self.get_proxy_id('proxy_manager'), proxy_name=proxy_name, token=uuid4(), **kwargs)
        self.proxy_class = proxy_class
        self.register_callback(self.handle_peer_registration, 'REGISTER_PEER', provides_response=True)

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
            _log.info(f'PPM: Successfully registered peer: {proxy.proxy_id} @ {proxy.socket_params}')
            return json.dumps(True).encode('utf8')
        else:  # TODO: Is there any reasonable situation where this runs and returns false?
            _log.error(f'PPM: Failed to register peer: {proxy.proxy_id} with message: {message}.')
            return json.dumps(False).encode('utf8')

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

    @abstractmethod
    def log_subprocess_output(self, stream):
        pass

    @staticmethod
    def log_subprocess_output_line(raw_line):
        line = raw_line.decode().strip()
        try:
            try:
                entry = json.loads(line)
                log = logging.getLogger(entry['name'])
                log.log(logging.getLevelName(entry['level'].upper()), f":{entry['lineno']} {entry['message']}")
            except (json.JSONDecodeError, KeyError, TypeError):
                log = logging.getLogger(__name__)
                log.log(logging.ERROR, line)
        except UnicodeDecodeError:
            log = logging.getLogger(__name__)
            log.log(logging.ERROR, raw_line)
        except Exception as e:
            _log.error(f'Encountered unknown exception parsing logs from proxy: {e}')
