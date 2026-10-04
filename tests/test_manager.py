import io

from unittest import mock
from uuid import uuid4

import gevent
from gevent.event import Event

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


class FakeProcess:
    """A launched proxy process that exits when the test says so."""
    _pids = iter(range(1000, 2000))

    def __init__(self, *args, **kwargs):
        self.pid = next(self._pids)
        self.stdin = io.BytesIO()
        self.stdout, self.stderr = io.BytesIO(b''), io.BytesIO(b'')
        self.returncode = None
        self._exited = Event()
        self.terminated = False

    def exit(self, code):
        self.returncode = code
        self._exited.set()

    def wait(self, timeout=None):
        self._exited.wait(timeout)
        return self.returncode

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.exit(-15)

    kill = terminate


def _manager():
    manager = GeventProtocolProxyManager(proxy_class=DummyProxy)
    manager.inbound_params = SocketParams('127.0.0.1', 22801)
    return manager


class TestSupervision:
    def test_dead_process_removes_peer_and_notifies_listeners(self):
        lost = []
        manager = _manager()
        manager.on_peer_lost(lambda peer, reason: lost.append((peer, reason)))
        with mock.patch('protocol_proxy.manager.gevent.Popen', FakeProcess), mock.patch('atexit.register'):
            peer = manager.get_proxy(('dummy', 'x'))
            assert manager.get_proxy(('dummy', 'x')) is peer                   # alive: no relaunch
            peer.process.exit(3)
            gevent.sleep(0.05)
            assert peer.proxy_id not in manager.peers
            assert lost == [(peer, 'process exited with code 3')]
            replacement = manager.get_proxy(('dummy', 'x'))                    # relaunched on demand
        assert replacement is not peer and replacement.proxy_id == peer.proxy_id
        assert replacement.process.pid != peer.process.pid

    def test_exit_of_a_replaced_process_leaves_the_current_peer_alone(self):
        lost = []
        manager = _manager()
        manager.on_peer_lost(lambda peer, reason: lost.append(peer))
        with mock.patch('protocol_proxy.manager.gevent.Popen', FakeProcess), mock.patch('atexit.register'):
            old = manager.get_proxy(('dummy', 'x'))
            del manager.peers[old.proxy_id]                                     # e.g. a registration timeout
            new = manager.get_proxy(('dummy', 'x'))
            old.process.exit(1)
            gevent.sleep(0.05)
        assert manager.peers[new.proxy_id] is new and lost == []

    def test_registration_timeout_stops_the_process_and_notifies(self):
        lost, ran = [], []
        manager = _manager()
        manager.on_peer_lost(lambda peer, reason: lost.append(reason))
        with mock.patch('protocol_proxy.manager.gevent.Popen', FakeProcess), mock.patch('atexit.register'):
            peer = manager.get_proxy(('dummy', 'x'))
            manager.wait_peer_registered(peer, 0.05, lambda: ran.append(1))
            gevent.sleep(0.05)
        assert peer.proxy_id not in manager.peers and ran == []
        assert peer.process.terminated and lost == ['did not register within 0.05 seconds']

    def test_failing_post_registration_function_keeps_the_peer(self):
        lost = []
        manager = _manager()
        manager.on_peer_lost(lambda peer, reason: lost.append(reason))
        with mock.patch('protocol_proxy.manager.gevent.Popen', FakeProcess), mock.patch('atexit.register'):
            peer = manager.get_proxy(('dummy', 'x'))
            peer.socket_params = SocketParams('127.0.0.1', 5)

            def boom():
                raise RuntimeError('registration payload rejected')
            manager.wait_peer_registered(peer, 0.05, boom)                     # does not raise
        assert manager.peers[peer.proxy_id] is peer and lost == [] and not peer.process.terminated

    def test_listeners_are_held_weakly(self):
        manager = _manager()

        class User:
            def __init__(self): self.seen = []
            def lost(self, peer, reason): self.seen.append(reason)
        user, gone = User(), User()
        manager.on_peer_lost(user.lost)
        manager.on_peer_lost(gone.lost)
        del gone
        manager._notify_peer_lost(mock.Mock(proxy_id=uuid4()), 'why')
        assert user.seen == ['why'] and len(manager.peer_lost_callbacks) == 1
