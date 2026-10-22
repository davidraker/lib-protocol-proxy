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


@pytest.mark.parametrize('persistent', [False, True])
def test_requests_nobody_can_answer_fail_at_once(pair, persistent):
    """An unknown method, or a handler registered without a response, answers with a JSON error instead of leaving
    the caller to wait out its timeout; the per-message connection is closed as before."""
    a, b, peer_b = pair
    peer_b.persistent = persistent
    b.register_callback(lambda ipc, headers, raw: None, 'FIRE_AND_FORGET')
    started = time.monotonic()
    error = json.loads(request(a, peer_b, 'NOPE'))
    assert error['status'] == 'error' and 'Unknown method NOPE' in error['error'] and error['method'] == 'NOPE'
    error = json.loads(request(a, peer_b, 'FIRE_AND_FORGET'))
    assert 'provides no response' in error['error'] and error['method'] == 'FIRE_AND_FORGET'
    assert time.monotonic() - started < 1.0
    assert a.send(peer_b, ProtocolProxyMessage(method_name='FIRE_AND_FORGET', payload=b'')) is True   # no reply owed
    sleep(0.05)
    assert len(b.connections) == (1 if persistent else 0)


def test_peer_closing_without_an_answer_fails_the_result(pair):
    a, b, peer_b = pair

    class Rude(GeventIPCConnector):
        def _dispatch(self, conn, headers, payload):
            conn.close()                                            # an old or broken peer: no reply, just EOF
    b.__class__ = Rude
    result = a.send(peer_b, ProtocolProxyMessage(method_name='ECHO', payload=b'', response_expected=True))
    with pytest.raises(ConnectionError):
        result.get(timeout=2)


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


# ---- persistent connections ----------------------------------------------------------------------------------------

def _persistent_pair(pair):
    """``a`` keeps one connection to ``b``; ``b`` knows ``a`` only by id and token (no address), as a manager knows
    a proxy that dialled in from behind NAT."""
    a, b, peer_b = pair
    peer_b.persistent = True
    b.peers[a.proxy_id].socket_params = None
    b.register_callback(echo, 'ECHO', provides_response=True)
    return a, b, peer_b, b.peers[a.proxy_id]


def test_persistent_peer_reuses_one_connection_for_many_requests(pair):
    a, b, peer_b, peer_a = _persistent_pair(pair)
    for i in range(20):
        assert request(a, peer_b, 'ECHO', str(i).encode()) == str(i).encode()
    assert peer_b.connection is not None and peer_b.connection.alive and peer_b.connection.persistent
    assert len(a.connections) == 1 and len(b.connections) == 1
    assert b.peers[a.proxy_id].connection is not None            # b adopted the connection a dialled


def test_receiver_sends_back_on_the_adopted_connection_without_an_address(pair):
    a, b, peer_b, peer_a = _persistent_pair(pair)
    a.register_callback(lambda ipc, headers, raw: b'from a: ' + raw, 'ASK', provides_response=True)
    assert request(a, peer_b, 'ECHO', b'open it') == b'open it'
    assert request(b, peer_a, 'ASK', b'hi') == b'from a: hi'  # b has no address for a; the one connection carries it
    assert len(b.connections) == 1 and len(a.connections) == 1
    assert b.send(peer_a, ProtocolProxyMessage(method_name='ASK', payload=b'', response_expected=True)) is not False


def test_requests_interleave_on_a_persistent_connection(pair):
    a, b, peer_b, peer_a = _persistent_pair(pair)

    def slow_echo(ipc, headers, raw):
        sleep(0.3 if raw == b'slow' else 0)
        return raw
    b.register_callback(slow_echo, 'SLOW', provides_response=True)
    slow = a.send(peer_b, ProtocolProxyMessage(method_name='SLOW', payload=b'slow', response_expected=True))
    started = time.monotonic()
    assert request(a, peer_b, 'SLOW', b'fast') == b'fast'
    assert time.monotonic() - started < 0.25                    # not queued behind the slow handler
    assert slow.get(timeout=2) == b'slow'


def test_lost_connection_fails_requests_in_flight_and_the_next_send_redials(pair):
    a, b, peer_b, peer_a = _persistent_pair(pair)
    assert request(a, peer_b, 'ECHO', b'x') == b'x'
    first = peer_b.connection
    b.register_callback(lambda ipc, headers, raw: sleep(5), 'HANG', provides_response=True)
    hanging = a.send(peer_b, ProtocolProxyMessage(method_name='HANG', payload=b'', response_expected=True))
    sleep(0.05)
    peer_a.connection.close()                                   # b drops the connection
    with pytest.raises(ConnectionError):
        hanging.get(timeout=2)
    sleep(0.05)
    assert peer_b.connection is None or not peer_b.connection.alive
    assert request(a, peer_b, 'ECHO', b'again') == b'again'   # redialled on demand
    assert peer_b.connection is not first and peer_b.connection.alive


def test_large_frames_take_their_own_connection(pair):
    a, b, peer_b, peer_a = _persistent_pair(pair)
    a.persistent_max_frame = 10_000
    assert request(a, peer_b, 'ECHO', b'small') == b'small'
    link = peer_b.connection
    big = bytes(50_000)
    assert request(a, peer_b, 'ECHO', big, timeout=10) == big
    assert peer_b.connection is link and link.alive            # the persistent connection was not used or disturbed
    sleep(0.05)
    assert len(a.connections) == 1                              # the dedicated connection is closed again


def test_per_message_sender_and_persistent_receiver_interoperate(pair):
    """A peer that closes after one frame works against a persistent-capable receiver, and the other way round."""
    a, b, peer_b = pair
    b.register_callback(echo, 'ECHO', provides_response=True)
    a.register_callback(echo, 'ECHO', provides_response=True)
    b.peers[a.proxy_id].persistent = True
    assert request(a, peer_b, 'ECHO', b'per message') == b'per message'     # a per message, b persistent-capable
    assert request(b, b.peers[a.proxy_id], 'ECHO', b'persistent') == b'persistent'
    assert request(a, peer_b, 'ECHO', b'still per message') == b'still per message'
    sleep(0.05)
    assert len(b.connections) == 1 and b.peers[a.proxy_id].connection.alive   # only b's dialled connection remains


def test_stop_closes_persistent_connections_on_both_sides(pair):
    a, b, peer_b, peer_a = _persistent_pair(pair)
    assert request(a, peer_b, 'ECHO', b'x') == b'x'
    a.stop()
    sleep(0.05)
    assert not a.connections and not b.connections
    assert peer_a.connection is None


def test_send_to_an_unreachable_persistent_peer_fails_the_result(pair):
    a, b, peer_b = pair
    nobody = GeventProtocolProxyPeer(proxy_id=uuid4(), token=uuid4(), socket_params=SocketParams('127.0.0.1', 1),
                                     persistent=True)
    a.max_io_wait_seconds = 0.2
    result = a.send(nobody, ProtocolProxyMessage(method_name='ECHO', payload=b'', response_expected=True))
    with pytest.raises(ConnectionError):
        result.get(timeout=2)
    assert nobody.connection is None and not a.connections
