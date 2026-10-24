"""A proxy that cannot dial the manager: it waits for the manager to connect, registers over that connection, and
everything after travels on it. Only a connection that authenticates as the manager is accepted."""
import json
import os
import socket
import time
from pathlib import Path
from uuid import uuid4

import gevent
import pytest
from gevent import sleep, spawn

from protocol_proxy.ipc import ProtocolProxyMessage, SocketParams
from protocol_proxy.ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer
from protocol_proxy.manager.gevent import GeventProtocolProxyManager
from protocol_proxy.proxy.gevent import GeventProtocolProxy
from test_manager import FakeProcess


class InProcessProxy(GeventProtocolProxy):
    pass


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait(predicate, timeout=10, what='condition'):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, f'timed out waiting for {what}'
        sleep(0.02)


@pytest.fixture
def stack():
    manager = GeventProtocolProxyManager(proxy_class=InProcessProxy, heartbeat_interval=0, min_port=23501,
                                         max_port=23599)
    manager.start()
    loop = spawn(manager.select_loop)
    port = _free_port()
    # The proxy is given an unreachable manager address on purpose: it must never try it.
    proxy = InProcessProxy(proxy_id=uuid4(), token=uuid4(), proxy_name='nat', manager_address='203.0.113.1',
                           manager_port=1, manager_id=manager.proxy_id, manager_token=manager.token,
                           manager_dials=True, inbound_params=SocketParams('127.0.0.1', port), min_port=23501,
                           max_port=23599, socket_logging=False, registration_timeout=2)
    peer = GeventProtocolProxyPeer(proxy_id=proxy.proxy_id, token=proxy.token, process=FakeProcess(), name='nat',
                                   persistent=True, dial_params=SocketParams('127.0.0.1', port))
    manager.peers[peer.proxy_id] = peer
    greenlets = proxy.start()
    yield manager, proxy, peer
    proxy.stop()
    manager.stop()
    gevent.joinall(greenlets + [loop], timeout=2)


def test_proxy_waits_then_registers_over_the_connection_the_manager_opens(stack):
    manager, proxy, peer = stack
    sleep(0.3)
    assert not proxy.registered and proxy.peers[manager.proxy_id].socket_params is None   # waiting, not dialling
    dialer = spawn(manager._dial_until_registered, peer, 0.2)
    manager.wait_peer_registered(peer, 10)
    _wait(lambda: proxy.registered, what='the proxy to see the registration reply')
    assert peer.registered.is_set() and peer.state == 'registered'
    assert dialer.join(2) is None or dialer.ready()
    link = peer.connection
    assert link is not None and link.alive and link.persistent
    # Every request to the proxy, and every push back, uses that one connection; the advertised address is not dialled.
    reply = json.loads(manager.send(peer, manager.ping_message()).get(timeout=5))
    assert reply['uptime'] >= 0 and peer.connection is link
    assert proxy.peers[manager.proxy_id].connection is not None and len(proxy.connections) == 1
    manager.register_callback(lambda ipc, h, raw: b'seen', 'PUSH', provides_response=True)
    assert proxy.send(proxy.peers[manager.proxy_id], ProtocolProxyMessage(method_name='PUSH', payload=b'',
                                                                          response_expected=True)).get(timeout=5) == b'seen'
    assert len(manager.connections) == 1


def test_only_the_authenticated_manager_can_attach(stack):
    manager, proxy, peer = stack

    class Impostor(GeventIPCConnector):
        pass
    impostor = Impostor(proxy_id=manager.proxy_id, token=uuid4(), proxy_name='impostor', min_port=23501, max_port=23599)
    target = GeventProtocolProxyPeer(proxy_id=proxy.proxy_id, token=proxy.token, socket_params=proxy.inbound_params,
                                     persistent=True)
    impostor.send(target, ProtocolProxyMessage(method_name='PING', payload=b'', response_expected=True))
    sleep(0.3)
    assert not proxy.registered and not proxy.manager_linked()           # not adopted: wrong token
    impostor.stop()
    spawn(manager._dial_until_registered, peer, 0.2)
    manager.wait_peer_registered(peer, 10)
    _wait(lambda: proxy.registered, what='registration')
    assert proxy.manager_linked()


def test_manager_launch_options_and_dial_target():
    manager = GeventProtocolProxyManager(proxy_class=InProcessProxy)
    assert manager.dial_target({}) is None
    assert manager.dial_target({'manager_dials': True, 'inbound_port': 5}) == SocketParams('localhost', 5)
    assert manager.dial_target({'manager_dials': 'True', 'inbound_address': '10.0.0.9', 'inbound_port': '7'}) == \
        SocketParams('10.0.0.9', 7)
    assert manager.dial_target({'manager_dials': True, 'dial': ('10.0.0.9', 8), 'inbound_port': 7}) == SocketParams('10.0.0.9', 8)
    with pytest.raises(ValueError):
        manager.dial_target({'manager_dials': True})
    manager.inbound_params = SocketParams('127.0.0.1', 22801)
    command, *_ = manager._setup_proxy_process_command(('x',), manager_dials=True, inbound_port=7, dial=('h', 8))
    assert '--manager-dials' in command and '--dial' not in command            # dial is the manager's own option


def test_real_proxy_that_cannot_dial_in_is_reached_by_the_manager(monkeypatch):
    tests_dir = str(Path(__file__).resolve().parent)
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(filter(None, [tests_dir, os.environ.get('PYTHONPATH')])))
    import dummy_proxies as dummies
    manager = GeventProtocolProxyManager(proxy_class=dummies.AsyncioDummy, heartbeat_interval=0.3)
    manager.start()
    loop = spawn(manager.select_loop)
    peer = None
    try:
        port = _free_port()
        # manager_address is a black hole: the only way to the proxy is the connection the manager opens.
        peer = manager.get_proxy(('dummy', 'nat'), manager_dials=True, inbound_address='127.0.0.1', inbound_port=port,
                                 manager_address='203.0.113.1', manager_port=1, encrypt=True)
        manager.wait_peer_registered(peer, 20)
        assert peer.socket_params is not None, 'the proxy did not register over the manager\'s connection'
        assert peer.dial_params == SocketParams('127.0.0.1', port) and peer.connection.alive
        _wait(lambda: peer.state == 'healthy', what='a heartbeat reply')
        assert json.loads(manager.set_proxy_log_level(peer, 'WARNING').get(timeout=5)) == {'level': 'WARNING'}
        assert len(manager.connections) == 1
        manager._cleanup_proxy_process(peer.process)
        assert peer.process.returncode == 0
    finally:
        if peer is not None and peer.process is not None and peer.process.poll() is None:
            peer.process.kill()
        if manager._heartbeat is not None:
            manager._heartbeat.kill()
        manager.stop()
        gevent.joinall([loop], timeout=2)
