import asyncio
import json
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from gevent.event import AsyncResult

from protocol_proxy.ipc import callback, async_callback, ProtocolProxyPeer, SocketParams
from protocol_proxy.ipc.asyncio import AsyncioIPCConnector
from protocol_proxy.ipc.gevent import GeventIPCConnector
from protocol_proxy.proxy.asyncio import AsyncioProtocolProxy
from protocol_proxy.proxy.gevent import GeventProtocolProxy


class GeventDummy(GeventProtocolProxy):
    @classmethod
    def get_unique_remote_id(cls, unique_remote_id):
        return unique_remote_id


class AsyncioDummy(AsyncioProtocolProxy):
    @classmethod
    def get_unique_remote_id(cls, unique_remote_id):
        return unique_remote_id


def gevent_proxy():
    return GeventDummy(proxy_id=uuid4(), token=uuid4(), manager_address='127.0.0.1', manager_port=1,
                       manager_id=uuid4(), manager_token=uuid4(), registration_retry_delay=0, registration_timeout=0.1)


def test_gevent_registration_requires_start():
    p = gevent_proxy()
    assert p.registered is False
    with mock.patch.object(p, 'send') as send:
        assert p.send_registration(p.peers[p.manager]) is False    # get_local_socket_params raises; handled
        send.assert_not_called()
    assert p._stop is True


def test_gevent_registration_decodes_json_response_and_retries():
    p = gevent_proxy()
    p.inbound_server_socket = mock.Mock(getsockname=lambda: ('127.0.0.1', 5))
    responses = [b'false', b'true']

    def fake_send(remote, message):
        assert json.loads(message.payload)['port'] == 5
        result = AsyncResult()
        result.set(responses.pop(0))
        return result
    with mock.patch.object(p, 'send', fake_send):
        assert p.send_registration(p.peers[p.manager]) is True
    assert p.registered and not p._stop and responses == []


def test_gevent_registration_timeout_stops_proxy():
    p = gevent_proxy()
    p.inbound_server_socket = mock.Mock(getsockname=lambda: ('127.0.0.1', 5))
    with mock.patch.object(p, 'send', lambda remote, message: AsyncResult()):    # never resolved
        assert p.send_registration(p.peers[p.manager]) is False
    assert p._stop is True


def test_gevent_start_creates_socket_then_spawns_loops_and_run_returns_exit_code():
    p = gevent_proxy()
    p.inbound_params = SocketParams('127.0.0.1', 0)

    def fake_registration(remote):
        assert p.inbound_server_socket is not None
        p.registered = True
        p.stop()
        return True
    with mock.patch.object(p, 'send_registration', fake_registration):
        assert p.run() == 0
    p2 = gevent_proxy()
    with mock.patch.object(p2, 'send_registration', lambda remote: p2.stop()):
        assert p2.run() == 1


def test_gevent_send_rejects_non_peer_without_raising():
    class C(GeventIPCConnector):
        pass
    c = C(proxy_id=uuid4(), token=uuid4())
    assert c.send(SocketParams('127.0.0.1', 1), mock.Mock()) is False


def test_asyncio_registration_and_start_failure():
    async def main():
        p = AsyncioDummy(proxy_id=uuid4(), token=uuid4(), manager_address='127.0.0.1', manager_port=1,
                         manager_id=uuid4(), manager_token=uuid4(), registration_retry_delay=0,
                         registration_timeout=0.05)
        p.inbound_server = mock.Mock(sockets=[mock.Mock(getsockname=lambda: ('127.0.0.1', 9, 0, 0))])
        assert p.get_local_socket_params() == SocketParams('127.0.0.1', 9)

        async def ok(remote, message):
            fut = asyncio.get_running_loop().create_future()
            fut.set_result(b'true')
            return fut
        with mock.patch.object(p, 'send', ok):
            assert await p.send_registration(p.peers[p.manager]) is True

        async def never(remote, message):
            return asyncio.get_running_loop().create_future()
        p.registered = False
        with mock.patch.object(p, 'send', never):
            assert await p.send_registration(p.peers[p.manager]) is False

        # start() raises when registration fails, instead of serving forever.
        with mock.patch.object(AsyncioIPCConnector, 'start', mock.AsyncMock()), \
             mock.patch.object(p, 'send_registration', mock.AsyncMock(return_value=False)):
            try:
                await p.start()
            except RuntimeError:
                pass
            else:
                raise AssertionError('start() should fail when registration fails')
    asyncio.run(main())


def test_asyncio_run_callback_accepts_sync_and_async_callbacks():
    from protocol_proxy.ipc.asyncio import IPCProtocol

    async def main():
        connector = mock.Mock(proxy_name='c', PROTOCOL_VERSION={1: mock.Mock(HEADER_LENGTH=10)})
        protocol = IPCProtocol(connector=connector)
        protocol.transport = mock.Mock()
        protocol._message_to_bytes = lambda message: message.payload
        headers = SimpleNamespace(method_name='M', request_id=1)

        def sync_cb(conn, hdrs, data):
            return b'sync:' + data

        async def async_cb(conn, hdrs, data):
            return b'async:' + data

        def raising(conn, hdrs, data):
            raise ValueError('bad')
        for cb, expected in ((sync_cb, b'sync:x'), (async_cb, b'async:x')):
            info = SimpleNamespace(method=cb, provides_response=True, timeout=1)
            await protocol._run_callback(info, headers, memoryview(b'x'))
            assert protocol.transport.write.call_args.args[0] == expected
        info = SimpleNamespace(method=raising, provides_response=True, timeout=1)
        await protocol._run_callback(info, headers, memoryview(b'x'))
        assert json.loads(protocol.transport.write.call_args.args[0])['status'] == 'error'
    asyncio.run(main())
