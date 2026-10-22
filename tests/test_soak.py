"""Soak: thousands of requests over persistent connections, interleaved with connection losses and real proxy
relaunches, leave no pending state behind and keep answering."""
import gc
import json
import os
import time
from pathlib import Path
from uuid import uuid4

import gevent
import pytest
from gevent import sleep, spawn

from protocol_proxy.ipc import ProtocolProxyMessage
from protocol_proxy.ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer
from protocol_proxy.manager.gevent import GeventProtocolProxyManager


class Connector(GeventIPCConnector):
    pass


def test_loopback_soak_persistent_with_drops_and_compression_and_encryption():
    a = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='A', min_port=23401, max_port=23499)
    b = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='B', min_port=23401, max_port=23499)
    a.start(); b.start()
    loops = [spawn(a.select_loop), spawn(b.select_loop)]
    key = a.new_key()
    peer_a = GeventProtocolProxyPeer(proxy_id=a.proxy_id, token=a.token, features=('compress',), key=key)
    peer_b = GeventProtocolProxyPeer(proxy_id=b.proxy_id, token=b.token, socket_params=b.inbound_params,
                                     persistent=True, features=('compress',), key=key)
    a.peers[b.proxy_id], b.peers[a.proxy_id] = peer_b, peer_a
    b.register_callback(lambda ipc, h, raw: raw, 'ECHO', provides_response=True)
    a.register_callback(lambda ipc, h, raw: raw, 'ECHO', provides_response=True)
    try:
        total, failed, started = 0, 0, time.monotonic()
        bodies = [b'x' * 10, os.urandom(300), (b'{"v": 1}' * 800)]              # small, binary-ish, compressible
        for round_no in range(6):
            results = []
            for i in range(500):
                body = bodies[i % 3]
                results.append((body, a.send(peer_b, ProtocolProxyMessage(method_name='ECHO', payload=body,
                                                                           response_expected=True))))
                if i % 50 == 0 and peer_a.connection is not None:    # b answers back on the adopted connection
                    results.append((body, b.send(peer_a, ProtocolProxyMessage(method_name='ECHO', payload=body,
                                                                               response_expected=True))))
            for body, result in results:
                total += 1
                try:
                    assert result.get(timeout=10) == body
                except ConnectionError:
                    failed += 1
            # Drop the connection from one side or the other; the next round must redial and carry on.
            victim = peer_b.connection if round_no % 2 else peer_a.connection
            if victim is not None:
                victim.close()
            sleep(0.05)
        elapsed = time.monotonic() - started
        assert total >= 3000 and failed <= 6 * 2, (total, failed)       # at most the in-flight ones at each drop
        assert len(a.connections) <= 1 and len(b.connections) <= 1
        for conn in list(a.connections) + list(b.connections):
            assert not conn.pending
        del results, result
        gc.collect()
        assert len(a.response_results) == 0 and len(b.response_results) == 0      # weak dict: nothing retained
        print(f'\n{total} requests in {elapsed:.1f} s ({total / elapsed:.0f}/s), {failed} failed at drops')
    finally:
        a.stop(); b.stop()
        gevent.joinall(loops, timeout=2)


def test_real_proxy_relaunches_keep_answering(monkeypatch):
    """Kill the proxy process three times mid-traffic; the manager notices, users re-run setup, requests resume."""
    tests_dir = str(Path(__file__).resolve().parent)
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(filter(None, [tests_dir, os.environ.get('PYTHONPATH')])))
    import dummy_proxies as dummies
    manager = GeventProtocolProxyManager(proxy_class=dummies.AsyncioDummy, heartbeat_interval=0.5,
                                         heartbeat_timeout=0.5, heartbeat_misses=2)
    manager.start()
    loop = spawn(manager.select_loop)
    lost = []
    manager.on_peer_lost(lambda peer, reason: lost.append(reason))
    peer = None

    def setup():
        p = manager.get_proxy(('dummy', 'soak'), persistent=True, encrypt=True)
        manager.wait_peer_registered(p, 20)
        assert p.socket_params is not None, 'proxy did not register'
        return p
    try:
        peer = setup()
        pids = [peer.process.pid]
        for cycle in range(3):
            for _ in range(50):
                reply = manager.send(peer, manager.ping_message()).get(timeout=5)
                assert 'uptime' in json.loads(reply)
            os.kill(peer.process.pid, 9)                                   # a crash
            deadline = time.monotonic() + 10
            while peer.proxy_id in manager.peers and time.monotonic() < deadline:
                sleep(0.05)
            assert peer.proxy_id not in manager.peers, 'manager did not notice the exit'
            peer = setup()                                                 # as a driver interface does on peer-lost
            pids.append(peer.process.pid)
        assert len(set(pids)) == 4 and len(lost) == 3 and all('exited' in r for r in lost)
        assert len(manager.peers) == 1 and manager.health()["('dummy', 'soak')"]['pid'] == peer.process.pid
    finally:
        if peer is not None and peer.process is not None and peer.process.poll() is None:
            peer.process.kill()
        if manager._heartbeat is not None:
            manager._heartbeat.kill()
        manager.stop()
        gevent.joinall([loop], timeout=2)
