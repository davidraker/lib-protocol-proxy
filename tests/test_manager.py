from unittest import mock
from uuid import uuid4

from protocol_proxy.ipc import SocketParams
from protocol_proxy.manager.gevent import GeventProtocolProxyManager
from protocol_proxy.proxy.gevent import GeventProtocolProxy


class DummyProxy(GeventProtocolProxy):
    @classmethod
    def get_unique_remote_id(cls, unique_remote_id):
        return unique_remote_id


def test_command_line_skips_none_and_manager_only_kwargs():
    manager = GeventProtocolProxyManager(proxy_class=DummyProxy)
    manager.inbound_params = SocketParams('127.0.0.1', 22801)
    command, proxy_id, name = manager._setup_proxy_process_command(
        ('dummy', 'x'), host='h', port=1, password=None, tls=True, manager_callbacks=[(print, 'X')])
    # DummyProxy is a GeventProtocolProxy, so the entry point is told to monkey-patch before importing it.
    assert command[1:5] == ['-m', 'protocol_proxy.proxy', '--gevent', f'{DummyProxy.__module__}:DummyProxy']
    tail = command[command.index('--host'):]
    assert tail == ['--host', 'h', '--port', '1', '--tls', 'True']
    assert '--manager-callbacks' not in command and '--password' not in command


def test_class_get_proxy_pops_manager_callbacks():
    with mock.patch.object(GeventProtocolProxyManager, 'get_manager') as get_manager:
        manager = get_manager.return_value
        callbacks = [(print, 'A')]
        GeventProtocolProxyManager.__mro__[1].get_proxy.__func__(
            GeventProtocolProxyManager, ('mqtt', 'h'), manager_callbacks=callbacks, host='h')
        get_manager.assert_called_once_with('mqtt', callbacks)
        manager.get_proxy.assert_called_once_with(('mqtt', 'h'), host='h')
