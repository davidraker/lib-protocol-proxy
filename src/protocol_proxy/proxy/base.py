import abc
import json
import logging
import sys

from importlib import import_module
from pkgutil import iter_modules
from typing import ClassVar
from uuid import UUID

from ..ipc import IPCConnector, ProtocolProxyMessage, ProtocolProxyPeer, SocketParams

_log = logging.getLogger(__name__)


# noinspection PyMissingConstructor
class ProtocolProxy(IPCConnector, metaclass=abc.ABCMeta):
    # Name of a module-level function, in the same module as the subclass, which adds protocol-specific command-line
    # options: ``(ArgumentParser) -> (ArgumentParser, runner)`` where ``runner(**options)`` creates and starts the
    # proxy. None means the proxy takes no options and is launched as ``cls(**options).start()``.
    LAUNCHER: ClassVar[str | None] = None
    # Whether the proxy process must be gevent monkey-patched before this module is imported.
    PATCH_GEVENT: ClassVar[bool] = False

    def __init__(self, *, manager_address: str, manager_port: int, manager_id: UUID,
                 registration_retry_delay: float = 20.0, **kwargs):
        """NOTE: Proxy implementations MUST:
            1. Subclass a multitasking subclass of IPCConnector (gevent, asyncio, etc.)
            2. Subclass this "ProtocolProxy" class.
            3. Call super first to IPCConnector parent then this ProtocolProxy parent._
            4. Create a ProtocolProxyPeer subclass for the manager and store it in self.peers.
            5. Call send_registration asynchronously in their constructor after super calls.
        """
        #_log.debug('PP: IN INIT.')
        super(ProtocolProxy, self).__init__(**kwargs)
        self.registration_retry_delay: float = registration_retry_delay
        self.manager_params = SocketParams(manager_address, manager_port)
        self.manager = manager_id
        self.apply_plugins()


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
                                 'token': self.token.hex}).encode('utf8'),
            response_expected=True
        )
        return message
