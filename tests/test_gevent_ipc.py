"""Loopback tests for the gevent IPC connector: two connectors in one process exchanging frames over real sockets."""
import json
import statistics
import time
from uuid import uuid4

import gevent
import pytest
from gevent import sleep, spawn
from gevent.event import Event

from protocol_proxy.ipc import callback, ProtocolProxyMessage, SocketParams
from protocol_proxy.ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer


class Connector(GeventIPCConnector):
    pass


def echo(ipc, headers, raw):
    return raw


@pytest.fixture
def pair():
    """Two started connectors that know each other as peers; ``a`` sends, ``b`` answers."""
    a = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='A', min_port=23101, max_port=23199)
    b = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='B', min_port=23101, max_port=23199)
    a.start()
    b.start()
    loops = [spawn(a.select_loop), spawn(b.select_loop)]
    peer_a = GeventProtocolProxyPeer(proxy_id=a.proxy_id, token=a.token, socket_params=a.inbound_params)
    peer_b = GeventProtocolProxyPeer(proxy_id=b.proxy_id, token=b.token, socket_params=b.inbound_params)
    a.peers[b.proxy_id], b.peers[a.proxy_id] = peer_b, peer_a
    yield a, b, peer_b
    a.stop()
    b.stop()
    gevent.joinall(loops, timeout=2)
    assert all(g.ready() for g in loops), 'accept loops did not exit after stop()'


def request(a, peer, method, payload=b'', timeout=5, **kwargs):
    result = a.send(peer, ProtocolProxyMessage(method_name=method, payload=payload, response_expected=True, **kwargs))
    return result.get(timeout=timeout)


@pytest.mark.parametrize('size', [0, 16, 20_000, 3_000_000])
def test_round_trip_returns_the_payload_whole(pair, size):
    """Exact-length reads: payloads larger than any single recv come back intact, including a 3 MB profile."""
    a, b, peer_b = pair
    b.register_callback(echo, 'ECHO', provides_response=True)
    body = bytes(range(256)) * (size // 256) + b'x' * (size % 256)
    assert request(a, peer_b, 'ECHO', body, timeout=20) == body


def test_messages_without_a_response_are_delivered_and_the_connection_closed(pair):
    a, b, peer_b = pair
    seen, got = [], Event()

    def record(ipc, headers, raw):
        seen.append((headers.method_name, headers.remote_id, raw))
        got.set()
    remote = uuid4()
    b.register_callback(record, 'PUSH', remote_id=remote)
    assert a.send(peer_b, ProtocolProxyMessage(method_name='PUSH', payload=b'p', remote_id=remote)) is True
    assert got.wait(2) and seen == [('PUSH', remote, b'p')]
    sleep(0.05)
    assert not a.connections and not b.connections


def test_handler_errors_and_timeouts_answer_with_a_json_error(pair):
    a, b, peer_b = pair

    def boom(ipc, headers, raw):
        raise ValueError('bad input')

    def slow(ipc, headers, raw):
        sleep(1)
        return b'late'
    b.register_callback(boom, 'BOOM', provides_response=True)
    b.register_callback(slow, 'SLOW', provides_response=True, timeout=0.1)
    error = json.loads(request(a, peer_b, 'BOOM'))
    assert error['status'] == 'error' and 'bad input' in error['error'] and error['method'] == 'BOOM'
    started = time.monotonic()
    error = json.loads(request(a, peer_b, 'SLOW'))
    assert error['status'] == 'error' and 'timed out' in error['error'] and time.monotonic() - started < 0.9


def test_unknown_method_closes_without_a_reply(pair):
    a, b, peer_b = pair
    result = a.send(peer_b, ProtocolProxyMessage(method_name='NOPE', payload=b'', response_expected=True))
    assert result.wait(0.3) is None and not result.ready()
    sleep(0.05)
    assert not b.connections


def test_unauthenticated_sender_gets_an_empty_reply(pair):
    """Handlers written with the ``callback`` decorator check the sender's token against the known peer."""
    a, b, peer_b = pair

    class Handler:
        @callback
        def echo(self, headers, raw):
            return raw
    b.register_callback(Handler().echo, 'ECHO', provides_response=True)
    assert request(a, peer_b, 'ECHO', b'known') == b'known'
    b.peers[a.proxy_id].token = uuid4()                          # wrong token
    assert request(a, peer_b, 'ECHO', b'secret') == b''
    del b.peers[a.proxy_id]                                      # unknown sender
    assert request(a, peer_b, 'ECHO', b'secret') == b''


def test_send_to_an_unreachable_peer_logs_and_leaves_the_result_unset(pair):
    a, b, peer_b = pair
    nobody = GeventProtocolProxyPeer(proxy_id=uuid4(), token=uuid4(), socket_params=SocketParams('127.0.0.1', 1))
    a.max_io_wait_seconds = 0.2                                  # the connect deadline, should the port not refuse
    result = a.send(nobody, ProtocolProxyMessage(method_name='ECHO', payload=b'', response_expected=True))
    assert result.wait(0.5) is None
    assert not a.connections


def test_second_loop_call_waits_for_the_running_one_and_stop_ends_both(pair):
    a, b, peer_b = pair
    extra = spawn(a.select_loop)
    sleep(0.05)
    assert not extra.ready()                                     # waiting, not accepting alongside the first loop
    b.register_callback(echo, 'ECHO', provides_response=True)
    assert request(a, peer_b, 'ECHO', b'still works') == b'still works'
    a.stop()
    assert extra.join(1) is not None or extra.ready()


def test_round_trips_are_not_quantised_by_a_poll_interval(pair):
    a, b, peer_b = pair
    b.register_callback(echo, 'ECHO', provides_response=True)
    durations = []
    for _ in range(20):
        started = time.monotonic()
        assert request(a, peer_b, 'ECHO', b'tick') == b'tick'
        durations.append(time.monotonic() - started)
    assert statistics.median(durations) < 0.05, f'median round trip {statistics.median(durations) * 1000:.1f} ms'


def test_concurrent_requests_complete_independently(pair):
    a, b, peer_b = pair

    def delayed_echo(ipc, headers, raw):
        sleep(0.2)
        return raw
    b.register_callback(delayed_echo, 'ECHO', provides_response=True)
    started = time.monotonic()
    results = [a.send(peer_b, ProtocolProxyMessage(method_name='ECHO', payload=str(i).encode(), response_expected=True))
               for i in range(10)]
    assert [r.get(timeout=5) for r in results] == [str(i).encode() for i in range(10)]
    assert time.monotonic() - started < 1.0                      # served concurrently, not 10 x 0.2 s
