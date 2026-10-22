"""The manager's heartbeat: PING every registered peer, mark it healthy on any reply, unhealthy on a miss, and lost
after enough misses (same path as a process exit), with health() reporting it all."""
import json
import time
from uuid import uuid4

import gevent
import pytest

from protocol_proxy.proxy import ProtocolProxy
from gevent import sleep

from protocol_proxy.ipc.gevent import GeventProtocolProxyPeer
from protocol_proxy.manager.gevent import GeventProtocolProxyManager
from protocol_proxy.proxy.gevent import GeventProtocolProxy
from test_manager import FakeProcess


class InProcessProxy(GeventProtocolProxy):
    @classmethod
    def get_unique_remote_id(cls, unique_remote_id):
        return unique_remote_id


@pytest.fixture
def pair():
    """A manager and a proxy in one process over real sockets; the proxy registers itself, as a launched one would."""
    manager = GeventProtocolProxyManager(proxy_class=InProcessProxy, heartbeat_interval=0.2, heartbeat_timeout=0.3,
                                         heartbeat_misses=3, min_port=23301, max_port=23399)
    manager.start()
    loop = gevent.spawn(manager.select_loop)
    proxy = InProcessProxy(proxy_id=uuid4(), token=uuid4(), proxy_name='inproc', manager_address='127.0.0.1',
                           manager_port=manager.inbound_params.port, manager_id=manager.proxy_id,
                           manager_token=manager.token, min_port=23301, max_port=23399, registration_timeout=2,
                           socket_logging=False)
    peer = GeventProtocolProxyPeer(proxy_id=proxy.proxy_id, token=proxy.token, process=FakeProcess(), name='inproc')
    manager.peers[peer.proxy_id] = peer
    greenlets = proxy.start()
    manager.wait_peer_registered(peer, 5)
    assert peer.socket_params is not None and peer.state == 'registered'
    yield manager, proxy, peer
    proxy.stop()
    manager.stop()
    if manager._heartbeat is not None:
        manager._heartbeat.kill()
    gevent.joinall(greenlets + [loop], timeout=2)


def _wait(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, 'timed out'
        sleep(0.02)


def test_ping_reply_carries_the_health_report(pair):
    manager, proxy, peer = pair
    reply = json.loads(manager.send(peer, manager.ping_message()).get(timeout=2))
    assert reply['uptime'] >= 0 and reply['remotes'] == 0 and reply['busy'] is False
    assert reply['last_activity'] is not None                 # the registration reply was activity
    assert peer.features == ProtocolProxy.FEATURES


def test_heartbeat_marks_a_live_peer_healthy_and_reports_it(pair):
    manager, proxy, peer = pair
    manager.start_heartbeat()
    _wait(lambda: peer.state == 'healthy')
    assert peer.missed == 0 and peer.health['uptime'] >= 0 and peer.last_seen is not None
    report = manager.health()['inproc']
    assert report['state'] == 'healthy' and report['features'] == list(ProtocolProxy.FEATURES)
    assert report['pid'] == peer.process.pid and report['report'] is peer.health and report['persistent'] is False


def test_stalled_proxy_is_lost_after_three_misses_and_listeners_hear_why(pair):
    manager, proxy, peer = pair
    lost = []
    manager.on_peer_lost(lambda p, reason: lost.append((p, reason)))
    manager.start_heartbeat()
    _wait(lambda: peer.state == 'healthy')
    manager.unregister_callback('PING')                        # nothing wrong with the manager side
    proxy.unregister_callback('PING')
    proxy.register_callback(lambda ipc, headers, raw: sleep(5), 'PING', provides_response=True, timeout=10)
    _wait(lambda: peer.state == 'unhealthy')
    assert peer.missed >= 1 and peer.proxy_id in manager.peers
    _wait(lambda: lost, timeout=8)
    assert lost[0][0] is peer and lost[0][1] == 'missed 3 heartbeats' and peer.state == 'lost'
    assert peer.proxy_id not in manager.peers and peer.process.terminated


def test_dead_proxy_is_lost_through_the_heartbeat(pair):
    manager, proxy, peer = pair
    lost = []
    manager.on_peer_lost(lambda p, reason: lost.append(reason))
    manager.start_heartbeat()
    _wait(lambda: peer.state == 'healthy')
    proxy.stop()                                               # listener closed: connects are refused (or time out)
    manager.heartbeat_timeout = 0.3
    _wait(lambda: lost, timeout=10)
    assert lost == ['missed 3 heartbeats'] and manager.health() == {}


def test_an_old_proxy_without_ping_still_counts_as_alive(pair):
    manager, proxy, peer = pair
    proxy.unregister_callback('PING')                         # answers with the unknown-method error
    manager.start_heartbeat()
    _wait(lambda: peer.state == 'healthy')
    assert peer.health is None                                 # an error reply is life, not a report


def test_heartbeat_disabled_with_a_zero_interval():
    manager = GeventProtocolProxyManager(proxy_class=InProcessProxy, heartbeat_interval=0)
    manager.start_heartbeat()
    assert manager._heartbeat is None
