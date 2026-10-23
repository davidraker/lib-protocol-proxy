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


# ---- compression ---------------------------------------------------------------------------------------------------

def test_large_payloads_are_compressed_only_toward_peers_that_advertised_it(pair):
    from unittest import mock
    a, b, peer_b = pair
    seen = []

    def echo_noting(ipc, headers, raw):
        seen.append((headers.method_name, headers.compressed, len(raw)))
        return raw
    b.register_callback(echo_noting, 'ECHO', provides_response=True)
    big, small = bytes(range(256)) * 400, b'tiny'
    assert request(a, peer_b, 'ECHO', big) == big                    # peer_b's features unknown: never compressed
    assert seen[-1] == ('ECHO', False, len(big))
    peer_b.features = ('compress',)
    b.peers[a.proxy_id].features = ('compress',)
    with mock.patch.object(a, 'decode_payload', wraps=a.decode_payload) as decode:
        assert request(a, peer_b, 'ECHO', big) == big
        assert seen[-1] == ('ECHO', True, len(big))                 # compressed on the way out...
        assert decode.call_args.args[0].compressed                   # ...and the reply came back compressed too
        assert request(a, peer_b, 'ECHO', small) == small
        assert seen[-1] == ('ECHO', False, len(small)) and not decode.call_args.args[0].compressed
    a.compress_threshold = 0
    assert request(a, peer_b, 'ECHO', small) == small and seen[-1][1] is True
    peer_b.persistent = True
    assert request(a, peer_b, 'ECHO', big) == big and seen[-1][1] is True   # same on a persistent connection


def test_corrupt_compressed_payload_fails_the_request_not_the_connector(pair):
    a, b, peer_b = pair
    b.register_callback(echo, 'ECHO', provides_response=True)
    peer_b.features = ('compress',)
    a.compress_threshold = 0
    import zlib
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(zlib, 'compress', lambda data: b'not zlib at all')
        result = a.send(peer_b, ProtocolProxyMessage(method_name='ECHO', payload=b'x', response_expected=True))
        with pytest.raises(ConnectionError):
            result.get(timeout=2)
    assert request(a, peer_b, 'ECHO', b'fine afterwards') == b'fine afterwards'


# ---- encryption ----------------------------------------------------------------------------------------------------

def _share_key(a, b, peer_b):
    key = a.new_key()
    peer_b.key = key
    b.peers[a.proxy_id].key = key
    return key


def test_seal_and_open_authenticate_the_header_and_detect_tampering(pair):
    from cryptography.exceptions import InvalidTag
    a, b, peer_b = pair
    _share_key(a, b, peer_b)
    message = ProtocolProxyMessage(method_name='M', payload=b'secret ' * 100, request_id=5, response_expected=True)
    frame = a._frame(message, remote=peer_b)
    assert b'secret' not in frame
    version = int.from_bytes(frame[:2], 'big')
    protocol = a.PROTOCOL_VERSION[version]
    header_len = 2 + protocol.HEADER_LENGTH
    headers = protocol.unpack(frame[2:header_len])
    assert headers.encrypted and headers.data_length == len(frame) - header_len
    assert b.open_frame(headers, frame[:header_len], frame[header_len:]) == message.payload
    tampered = bytearray(frame)
    tampered[2 + 8 + 1] ^= 0x01                                     # flip a bit of the method name in the header
    with pytest.raises(InvalidTag):
        b.open_frame(protocol.unpack(bytes(tampered[2:header_len])), bytes(tampered[:header_len]), frame[header_len:])
    corrupted = bytearray(frame)
    corrupted[-1] ^= 0x01                                           # and of the tag
    with pytest.raises(InvalidTag):
        b.open_frame(headers, frame[:header_len], bytes(corrupted[header_len:]))
    b.peers[a.proxy_id].key = a.new_key()                           # the wrong key
    with pytest.raises(InvalidTag):
        b.open_frame(headers, frame[:header_len], frame[header_len:])


def test_encrypted_peers_exchange_in_both_directions_and_refuse_mismatches(pair):
    a, b, peer_b = pair
    peer_a = b.peers[a.proxy_id]
    seen = []

    def echo_noting(ipc, headers, raw):
        seen.append((headers.encrypted, headers.compressed))
        return raw
    b.register_callback(echo_noting, 'NOTE', provides_response=True)
    a.register_callback(echo_noting, 'NOTE', provides_response=True)
    assert request(a, peer_b, 'NOTE', b'clear') == b'clear' and seen[-1] == (False, False)
    _share_key(a, b, peer_b)
    for persistent in (False, True):
        peer_b.persistent = peer_a.persistent = persistent
        assert request(a, peer_b, 'NOTE', b'hidden') == b'hidden' and seen[-1] == (True, False)
        assert request(b, peer_a, 'NOTE', b'back') == b'back' and seen[-1] == (True, False)
    peer_b.features = peer_a.features = ('compress',)
    big = bytes(range(256)) * 400
    assert request(a, peer_b, 'NOTE', big) == big and seen[-1] == (True, True)      # compressed, then encrypted
    # b shares a key with a, so a clear-text frame from a is refused (and the request fails).
    peer_b.key = None
    result = a.send(peer_b, ProtocolProxyMessage(method_name='NOTE', payload=b'plain', response_expected=True))
    with pytest.raises(ConnectionError):
        result.get(timeout=2)
    # ...and an encrypted frame from a peer b shares no key with is refused too.
    peer_b.key, peer_a.key = a.new_key(), None
    result = a.send(peer_b, ProtocolProxyMessage(method_name='NOTE', payload=b'x', response_expected=True))
    with pytest.raises(ConnectionError):
        result.get(timeout=2)
    peer_b.key = None
    assert request(a, peer_b, 'NOTE', b'clear again') == b'clear again'


# ---- write priority ---------------------------------------------------------------------------------------------

def test_low_priority_frames_wait_for_ordinary_ones(pair):
    """A LOG batch on a persistent connection is written only when no ordinary frame is waiting."""
    from unittest import mock
    a, b, peer_b = pair
    peer_b.persistent = True
    b.register_callback(echo, 'ECHO', provides_response=True)
    assert request(a, peer_b, 'ECHO', b'open') == b'open'
    conn = peer_b.connection
    order = []
    real_sock = conn.sock

    class SlowSocket:
        """The real socket, with a sendall that records who is writing and takes a while."""
        def __getattr__(self, name):
            return getattr(real_sock, name)

        def sendall(self, data):
            order.append(('urgent' if conn._urgent else 'low', len(data)))
            sleep(0.05)
            return real_sock.sendall(data)
    with mock.patch.object(conn, 'sock', SlowSocket()):
        low = spawn(conn.write, a._frame(ProtocolProxyMessage(method_name='LOG', payload=b'l' * 10, request_id=1,
                                                              low_priority=True), keep_alive=True), True)
        sleep(0.01)                                               # the low-priority write is in its sendall
        urgent = [spawn(conn.write, a._frame(ProtocolProxyMessage(method_name='PING', payload=b'', request_id=i),
                                             keep_alive=True)) for i in range(2, 5)]
        sleep(0.01)
        second_low = spawn(conn.write, a._frame(ProtocolProxyMessage(method_name='LOG', payload=b'l' * 10, request_id=5,
                                                                     low_priority=True), keep_alive=True), True)
        gevent.joinall([low, *urgent, second_low], timeout=5)
    kinds = [kind for kind, _ in order]
    assert kinds[0] == 'low' and kinds[-1] == 'low' and kinds[1:4] == ['urgent'] * 3   # the waiting LOG went last


# ---- cipher choice -------------------------------------------------------------------------------------------------

def test_cipher_detection_and_configuration():
    from protocol_proxy.ipc import IPCConnector
    x86 = 'processor\t: 0\nflags\t\t: fpu vme sse2 aes avx2\n'
    arm = 'processor\t: 0\nFeatures\t: fp asimd aes pmull sha2\n'
    old = 'processor\t: 0\nflags\t\t: fpu vme sse2\n'
    assert IPCConnector.cpu_has_aes(x86) and IPCConnector.cpu_has_aes(arm) and not IPCConnector.cpu_has_aes(old)
    assert not IPCConnector.cpu_has_aes('')
    assert IPCConnector.resolve_cipher('aes-256-gcm') == 'aes-256-gcm'
    assert IPCConnector.resolve_cipher('chacha20-poly1305') == 'chacha20-poly1305'
    assert IPCConnector.resolve_cipher('auto') in IPCConnector.CIPHERS
    with pytest.raises(ValueError):
        IPCConnector.resolve_cipher('rot13')


def test_each_side_encrypts_with_its_own_cipher_and_falls_back_for_a_peer_without_aes(pair):
    a, b, peer_b = pair
    peer_a = b.peers[a.proxy_id]
    a.cipher, b.cipher = 'aes-256-gcm', 'chacha20-poly1305'
    key = a.new_key()
    peer_b.key = peer_a.key = key
    peer_b.features = peer_a.features = ('aead-chacha20poly1305', 'aead-aes256gcm')
    seen = {}

    def note(ipc, headers, raw):
        seen[ipc.proxy_name] = (headers.encrypted, headers.aes_gcm)
        return raw
    a.register_callback(note, 'NOTE', provides_response=True)
    b.register_callback(note, 'NOTE', provides_response=True)
    assert request(a, peer_b, 'NOTE', b'to b') == b'to b' and seen['B'] == (True, True)      # a sends AES-GCM
    assert request(b, peer_a, 'NOTE', b'to a') == b'to a' and seen['A'] == (True, False)     # b sends ChaCha20
    peer_b.features = ('aead-chacha20poly1305',)                     # a peer that only accepts the baseline
    assert request(a, peer_b, 'NOTE', b'again') == b'again' and seen['B'] == (True, False)
    assert a.cipher_for(peer_b) == 'chacha20-poly1305' and a.cipher_for(peer_a) == 'aes-256-gcm'
