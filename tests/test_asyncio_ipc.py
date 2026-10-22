"""Loopback tests for the asyncio IPC connector, and one gevent-to-asyncio pair (a manager and an asyncio proxy)."""
import asyncio
import json
import threading
import time
from uuid import uuid4

import gevent
import pytest

from protocol_proxy.ipc import ProtocolProxyMessage, SocketParams
from protocol_proxy.ipc.asyncio import AsyncioIPCConnector, AsyncioProtocolProxyPeer
from protocol_proxy.ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer


class Connector(AsyncioIPCConnector):
    pass


def echo(ipc, headers, raw):
    return raw


async def make_pair(**b_options):
    a = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='A', min_port=23201, max_port=23299)
    b = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='B', min_port=23201, max_port=23299, **b_options)
    await a.start()
    await b.start()
    peer_a = AsyncioProtocolProxyPeer(proxy_id=a.proxy_id, token=a.token, socket_params=a.inbound_params)
    peer_b = AsyncioProtocolProxyPeer(proxy_id=b.proxy_id, token=b.token, socket_params=b.inbound_params)
    a.peers[b.proxy_id], b.peers[a.proxy_id] = peer_b, peer_a
    b.register_callback(echo, 'ECHO', provides_response=True)
    return a, b, peer_a, peer_b


async def request(sender, peer, method, payload=b'', timeout=5):
    result = await sender.send(peer, ProtocolProxyMessage(method_name=method, payload=payload, response_expected=True))
    return await asyncio.wait_for(result, timeout)


async def stop_all(*connectors):
    for c in connectors:
        await c.stop()
    await asyncio.sleep(0.05)


@pytest.mark.parametrize('size', [0, 16, 20_000, 3_000_000])
def test_per_message_round_trip(size):
    async def main():
        a, b, peer_a, peer_b = await make_pair()
        body = bytes(range(256)) * (size // 256) + b'x' * (size % 256)
        assert await request(a, peer_b, 'ECHO', body, timeout=20) == body
        await asyncio.sleep(0.05)
        assert not a.connections and not b.connections
        await stop_all(a, b)
    asyncio.run(main())


def test_persistent_peer_reuses_one_connection_and_the_receiver_sends_back_on_it():
    async def main():
        a, b, peer_a, peer_b = await make_pair()
        peer_b.persistent = True
        peer_a.socket_params = None                              # b cannot dial a: the adopted connection is the way
        a.register_callback(lambda ipc, h, raw: b'from a: ' + raw, 'ASK', provides_response=True)
        for i in range(20):
            assert await request(a, peer_b, 'ECHO', str(i).encode()) == str(i).encode()
        assert len(a.connections) == 1 and len(b.connections) == 1
        assert peer_b.connection.alive and peer_a.connection is not None and peer_a.connection.alive
        assert await request(b, peer_a, 'ASK', b'hi') == b'from a: hi'
        assert len(a.connections) == 1 and len(b.connections) == 1
        await stop_all(a, b)
        assert not a.connections and not b.connections and peer_b.connection is None
    asyncio.run(main())


def test_requests_interleave_and_a_lost_connection_fails_pending_then_redials():
    async def main():
        a, b, peer_a, peer_b = await make_pair()
        peer_b.persistent = True

        async def slow(ipc, headers, raw):
            await asyncio.sleep(0.3 if raw == b'slow' else 0)
            return raw
        b.register_callback(slow, 'SLOW', provides_response=True)
        slow_result = await a.send(peer_b, ProtocolProxyMessage(method_name='SLOW', payload=b'slow',
                                                                response_expected=True))
        loop = asyncio.get_running_loop()
        started = loop.time()
        assert await request(a, peer_b, 'SLOW', b'fast') == b'fast'
        assert loop.time() - started < 0.25
        assert await asyncio.wait_for(slow_result, 2) == b'slow'

        first = peer_b.connection

        async def hang(ipc, headers, raw):
            await asyncio.sleep(5)
        b.register_callback(hang, 'HANG', provides_response=True)
        hanging = await a.send(peer_b, ProtocolProxyMessage(method_name='HANG', payload=b'', response_expected=True))
        await asyncio.sleep(0.05)
        peer_a.connection.close()                               # b drops it
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(hanging, 2)
        await asyncio.sleep(0.05)
        assert await request(a, peer_b, 'ECHO', b'again') == b'again'
        assert peer_b.connection is not first and peer_b.connection.alive
        await stop_all(a, b)
    asyncio.run(main())


def test_large_frames_take_their_own_connection():
    async def main():
        a, b, peer_a, peer_b = await make_pair()
        peer_b.persistent = True
        a.persistent_max_frame = 10_000
        assert await request(a, peer_b, 'ECHO', b'small') == b'small'
        link = peer_b.connection
        big = bytes(50_000)
        assert await request(a, peer_b, 'ECHO', big, timeout=10) == big
        assert peer_b.connection is link and link.alive
        await asyncio.sleep(0.05)
        assert len(a.connections) == 1
        await stop_all(a, b)
    asyncio.run(main())


@pytest.mark.parametrize('persistent', [False, True])
def test_requests_nobody_can_answer_fail_at_once(persistent):
    async def main():
        a, b, peer_a, peer_b = await make_pair()
        peer_b.persistent = persistent
        b.register_callback(lambda ipc, headers, raw: None, 'FIRE_AND_FORGET')
        loop = asyncio.get_running_loop()
        started = loop.time()
        error = json.loads(await request(a, peer_b, 'NOPE'))
        assert error['status'] == 'error' and 'Unknown method NOPE' in error['error']
        error = json.loads(await request(a, peer_b, 'FIRE_AND_FORGET'))
        assert 'provides no response' in error['error']
        assert loop.time() - started < 1.0
        await stop_all(a, b)
    asyncio.run(main())


def test_peer_closing_without_an_answer_fails_the_result():
    async def main():
        a, b, peer_a, peer_b = await make_pair()

        async def rude(ipc, headers, raw):
            for protocol in list(b.connections):
                protocol.close()                                    # EOF instead of a reply
        b.register_callback(rude, 'RUDE', provides_response=True)
        result = await a.send(peer_b, ProtocolProxyMessage(method_name='RUDE', payload=b'', response_expected=True))
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(result, 2)
        await stop_all(a, b)
    asyncio.run(main())


def test_unreachable_persistent_peer_fails_the_result():
    async def main():
        a, b, peer_a, peer_b = await make_pair()
        a.connect_timeout = 0.5                                 # WSL: a closed loopback port may not refuse
        nobody = AsyncioProtocolProxyPeer(proxy_id=uuid4(), token=uuid4(), socket_params=SocketParams('127.0.0.1', 1),
                                          persistent=True)
        result = await a.send(nobody, ProtocolProxyMessage(method_name='ECHO', payload=b'', response_expected=True))
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(result, 5)
        await stop_all(a, b)
    asyncio.run(main())


class AsyncioSide:
    """An asyncio connector on its own loop in a thread: the proxy process of a cross-flavour pair."""

    def __init__(self, manager_id, manager_token, manager_params, persistent):
        self.ready = threading.Event()
        self.calls, self.connector, self.manager_peer = [], None, None
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, args=(manager_id, manager_token, manager_params, persistent),
                                       daemon=True)
        self.thread.start()
        assert self.ready.wait(5)

    def _run(self, manager_id, manager_token, manager_params, persistent):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._setup(manager_id, manager_token, manager_params, persistent))
        self.loop.run_forever()

    async def _setup(self, manager_id, manager_token, manager_params, persistent):
        self.connector = Connector(proxy_id=uuid4(), token=uuid4(), proxy_name='proxy', min_port=23201,
                                   max_port=23299, persistent=persistent)
        await self.connector.start()
        self.manager_peer = AsyncioProtocolProxyPeer(proxy_id=manager_id, token=manager_token,
                                                     socket_params=manager_params)
        self.connector.peers[manager_id] = self.manager_peer

        async def read_points(ipc, headers, raw):
            self.calls.append(raw)
            return b'{"result": ' + raw + b'}'
        self.connector.register_callback(read_points, 'READ_POINTS', provides_response=True)
        self.ready.set()

    def run(self, coro, timeout=5):
        """Wait for a coroutine on the asyncio thread while letting the gevent hub (the manager) keep running."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        deadline = time.monotonic() + timeout
        while not future.done():
            if time.monotonic() > deadline:
                future.cancel()
                raise TimeoutError(f'asyncio side did not finish within {timeout} s')
            gevent.sleep(0.005)
        return future.result()

    def close(self):
        self.run(self.connector.stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(2)


@pytest.mark.parametrize('persistent', [False, True])
def test_gevent_manager_and_asyncio_proxy_exchange_in_both_directions(persistent):
    """The proxy registers (dialling in), then the manager reads from it on the same connection when persistent, or
    by dialling the proxy's address when not. The manager never needs the proxy's address in persistent mode."""
    manager = GeventIPCConnector(proxy_id=uuid4(), token=uuid4(), proxy_name='manager', min_port=23201, max_port=23299)
    manager.start()
    loop = gevent.spawn(manager.select_loop)
    registered = []
    manager.register_callback(lambda ipc, h, raw: registered.append(raw) or b'true', 'REGISTER_PEER',
                              provides_response=True)
    proxy = AsyncioSide(manager.proxy_id, manager.token, manager.inbound_params, persistent)
    proxy_peer = GeventProtocolProxyPeer(proxy_id=proxy.connector.proxy_id, token=proxy.connector.token,
                                         socket_params=None if persistent else proxy.connector.inbound_params,
                                         persistent=persistent)
    manager.peers[proxy_peer.proxy_id] = proxy_peer
    try:
        async def register():
            result = await proxy.connector.send(proxy.manager_peer, ProtocolProxyMessage(
                method_name='REGISTER_PEER', payload=b'{"address": "x"}', response_expected=True))
            return await asyncio.wait_for(result, 5)
        assert proxy.run(register()) == b'true' and registered == [b'{"address": "x"}']
        gevent.sleep(0.05)
        assert (proxy_peer.connection is not None) is persistent      # adopted only when the proxy keeps it open
        for i in range(5):
            result = manager.send(proxy_peer, ProtocolProxyMessage(method_name='READ_POINTS', payload=b'%d' % i,
                                                                    response_expected=True))
            assert result.get(timeout=5) == b'{"result": %d}' % i
        assert proxy.calls == [b'0', b'1', b'2', b'3', b'4']
        gevent.sleep(0.05)
        assert len(manager.connections) == (1 if persistent else 0)
        assert len(proxy.connector.connections) == (1 if persistent else 0)
    finally:
        proxy.close()
        manager.stop()
        gevent.joinall([loop], timeout=2)


def test_compression_is_negotiated_per_peer_and_round_trips():
    from unittest import mock

    async def main():
        a, b, peer_a, peer_b = await make_pair()
        seen = []

        def echo_noting(ipc, headers, raw):
            seen.append(headers.compressed)
            return raw
        b.register_callback(echo_noting, 'NOTE', provides_response=True)
        big = bytes(range(256)) * 400
        assert await request(a, peer_b, 'NOTE', big) == big and seen[-1] is False
        peer_b.features = peer_a.features = ('compress',)
        for persistent in (False, True):
            peer_b.persistent = persistent
            with mock.patch.object(a, 'decode_payload', wraps=a.decode_payload):
                assert await request(a, peer_b, 'NOTE', big) == big and seen[-1] is True
                assert await request(a, peer_b, 'NOTE', b'tiny') == b'tiny' and seen[-1] is False
        await stop_all(a, b)
    asyncio.run(main())
