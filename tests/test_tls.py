"""TLS between a manager and its proxies: the manager is the CA, every connection either way is mutually
authenticated, plain and TLS proxies share the manager's listener, and nothing with a foreign certificate gets in."""
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
from protocol_proxy import tls as tlsmod
from test_manager import FakeProcess


class InProcessProxy(GeventProtocolProxy):
    pass


def _wait(predicate, timeout=10, what='condition'):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, f'timed out waiting for {what}'
        sleep(0.02)


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def manager():
    manager = GeventProtocolProxyManager(proxy_class=InProcessProxy, heartbeat_interval=0, min_port=23601,
                                         max_port=23699)
    manager.start()
    loop = spawn(manager.select_loop)
    yield manager
    manager.stop()
    gevent.joinall([loop], timeout=2)


def _proxy(manager, tls_material=None, manager_dials=False, inbound=None):
    proxy = InProcessProxy(proxy_id=uuid4(), token=uuid4(), proxy_name='tls' if tls_material else 'plain',
                           manager_address='127.0.0.1', manager_port=manager.inbound_params.port,
                           manager_id=manager.proxy_id, manager_token=manager.token, ipc_tls=tls_material,
                           manager_dials=manager_dials, inbound_params=inbound, min_port=23601, max_port=23699,
                           socket_logging=False, registration_timeout=3, persistent=True)
    peer = GeventProtocolProxyPeer(proxy_id=proxy.proxy_id, token=proxy.token, process=FakeProcess(),
                                   name=proxy.proxy_name, tls=tls_material is not None)
    manager.peers[peer.proxy_id] = peer
    return proxy, peer


def test_tls_and_plain_proxies_share_the_managers_listener(manager):
    tls_proxy, tls_peer = _proxy(manager, manager.tls_material_for(uuid4()))      # issued like a launched proxy
    tls_peer.tls = True
    # re-issue for the real id so the certificate names it
    tls_proxy.tls_material = manager.tls_material_for(tls_proxy.proxy_id)
    plain_proxy, plain_peer = _proxy(manager)
    greenlets = tls_proxy.start() + plain_proxy.start()
    try:
        manager.wait_peer_registered(tls_peer, 10)
        manager.wait_peer_registered(plain_peer, 10)
        _wait(lambda: tls_proxy.registered and plain_proxy.registered, what='both registrations')
        tls_conn = tls_peer.connection
        assert tls_conn is not None and tls_conn.tls_peer == tls_proxy.proxy_id.hex
        assert tls_conn.sock.version() == 'TLSv1.3'
        plain_conn = plain_peer.connection
        assert plain_conn is None or plain_conn.tls_peer is None
        for peer in (tls_peer, plain_peer):
            reply = json.loads(manager.send(peer, manager.ping_message()).get(timeout=5))
            assert 'uptime' in reply
        assert tlsmod.peer_common_name(tls_proxy.peers[manager.proxy_id].connection.sock) == manager.proxy_id.hex
    finally:
        tls_proxy.stop()
        plain_proxy.stop()
        gevent.joinall(greenlets, timeout=2)


def test_foreign_certificates_and_clear_text_from_a_tls_peer_are_refused(manager):
    tls_proxy, tls_peer = _proxy(manager, None)
    tls_proxy.tls_material = manager.tls_material_for(tls_proxy.proxy_id)
    tls_proxy.manager_tls = True
    tls_proxy.peers[manager.proxy_id].tls = True
    tls_peer.tls = True
    greenlets = tls_proxy.start()
    try:
        manager.wait_peer_registered(tls_peer, 10)
        _wait(lambda: tls_proxy.registered, what='registration')
        # Someone with the manager's id but a certificate from another authority: the handshake fails.
        other = tlsmod.Authority('attacker').issue(manager.proxy_id.hex)

        class Impostor(GeventIPCConnector):
            pass
        impostor = Impostor(proxy_id=manager.proxy_id, token=manager.token, proxy_name='impostor', tls_material=other,
                            min_port=23601, max_port=23699)
        target = GeventProtocolProxyPeer(proxy_id=tls_proxy.proxy_id, token=tls_proxy.token,
                                         socket_params=tls_proxy.inbound_params, tls=True)
        result = impostor.send(target, ProtocolProxyMessage(method_name='PING', payload=b'', response_expected=True))
        with pytest.raises(ConnectionError):
            result.get(timeout=5)
        # Clear text with the right id and token, where TLS is required: dropped, no reply.
        plain = Impostor(proxy_id=manager.proxy_id, token=manager.token, proxy_name='plain-impostor',
                         min_port=23601, max_port=23699)
        target_plain = GeventProtocolProxyPeer(proxy_id=tls_proxy.proxy_id, token=tls_proxy.token,
                                               socket_params=tls_proxy.inbound_params)
        result = plain.send(target_plain, ProtocolProxyMessage(method_name='PING', payload=b'', response_expected=True))
        assert result.wait(0.5) is None
        impostor.stop()
        plain.stop()
        # The legitimate manager still gets through.
        assert 'uptime' in json.loads(manager.send(tls_peer, manager.ping_message()).get(timeout=5))
    finally:
        tls_proxy.stop()
        gevent.joinall(greenlets, timeout=2)


def test_manager_dials_a_tls_proxy(manager):
    port = _free_port()
    proxy, peer = _proxy(manager, None, manager_dials=True, inbound=SocketParams('127.0.0.1', port))
    proxy.tls_material = manager.tls_material_for(proxy.proxy_id)
    proxy.manager_tls = True
    proxy.peers[manager.proxy_id].tls = True
    peer.tls, peer.persistent, peer.dial_params = True, True, SocketParams('127.0.0.1', port)
    greenlets = proxy.start()
    try:
        spawn(manager._dial_until_registered, peer, 0.2)
        manager.wait_peer_registered(peer, 10)
        _wait(lambda: proxy.registered, what='registration over the manager-dialled TLS connection')
        assert peer.connection.tls_peer == proxy.proxy_id.hex and peer.connection.sock.version() == 'TLSv1.3'
        assert 'uptime' in json.loads(manager.send(peer, manager.ping_message()).get(timeout=5))
    finally:
        proxy.stop()
        gevent.joinall(greenlets, timeout=2)


@pytest.mark.parametrize('proxy_class_name', ['GeventDummy', 'AsyncioDummy'])
def test_real_proxy_launched_with_tls(proxy_class_name, monkeypatch):
    tests_dir = str(Path(__file__).resolve().parent)
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(filter(None, [tests_dir, os.environ.get('PYTHONPATH')])))
    import dummy_proxies as dummies
    manager = GeventProtocolProxyManager(proxy_class=getattr(dummies, proxy_class_name), ipc_tls=True, encrypt=True,
                                         heartbeat_interval=0.3)
    manager.start()
    loop = spawn(manager.select_loop)
    peer = None
    try:
        peer = manager.get_proxy(('dummy', 'tls'), persistent=True)
        assert peer.tls and manager.authority is not None and manager.tls_material is not None
        manager.wait_peer_registered(peer, 25)
        assert peer.socket_params is not None, 'the TLS proxy did not register'
        assert peer.connection is not None and peer.connection.tls_peer == peer.proxy_id.hex
        _wait(lambda: peer.state == 'healthy', what='a heartbeat over TLS')
        assert json.loads(manager.set_proxy_log_level(peer, 'WARNING').get(timeout=5)) == {'level': 'WARNING'}
        health = manager.health()["('dummy', 'tls')"]
        assert health['connected'] and health['state'] == 'healthy'
        manager._cleanup_proxy_process(peer.process)
        assert peer.process.returncode == 0
    finally:
        if peer is not None and peer.process is not None and peer.process.poll() is None:
            peer.process.kill()
        if manager._heartbeat is not None:
            manager._heartbeat.kill()
        manager.stop()
        gevent.joinall([loop], timeout=2)
