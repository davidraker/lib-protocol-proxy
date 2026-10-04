"""Header versions and callback dispatch: version 2 carries a remote id, and connectors dispatch on it when a
callback is registered for that remote, falling back to the method-only callback."""
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

import asyncio

from protocol_proxy.ipc import HeadersV1, HeadersV2, ProtocolProxyMessage
from protocol_proxy.ipc.asyncio import AsyncioIPCConnector, IPCProtocol
from protocol_proxy.proxy.gevent import GeventProtocolProxy


class GeventDummy(GeventProtocolProxy):
    @classmethod
    def get_unique_remote_id(cls, unique_remote_id):
        return unique_remote_id


def gevent_proxy():
    return GeventDummy(proxy_id=uuid4(), token=uuid4(), manager_address='127.0.0.1', manager_port=1,
                       manager_id=uuid4(), manager_token=uuid4(), registration_retry_delay=0, registration_timeout=0.1)


def test_v1_round_trip_has_no_remote():
    sender, token = uuid4(), uuid4()
    packed = HeadersV1(42, 'READ_POINTS', 7, sender, token, True).pack()
    assert len(packed) == 2 + HeadersV1.HEADER_LENGTH
    headers = HeadersV1.unpack(packed[2:])
    assert (headers.data_length, headers.method_name, headers.request_id) == (42, 'READ_POINTS', 7)
    assert headers.sender_id == sender and headers.sender_token == token and headers.response_expected is True
    assert headers.remote_id is None


def test_v2_round_trip_with_and_without_remote():
    sender, token, remote = uuid4(), uuid4(), uuid4()
    packed = HeadersV2(5, 'RECEIVE_UNSOLICITED', 9, sender, token, False, remote).pack()
    assert len(packed) == 2 + HeadersV2.HEADER_LENGTH == 2 + HeadersV1.HEADER_LENGTH + 16
    assert packed[:2] == b'\x00\x02'
    headers = HeadersV2.unpack(packed[2:])
    assert headers.remote_id == remote and headers.method_name == 'RECEIVE_UNSOLICITED' and headers.response_expected is False
    assert 'remote_id' in repr(headers)
    bare = HeadersV2.unpack(HeadersV2(0, 'M', 1, sender, token).pack()[2:])
    assert bare.remote_id is None


def test_message_picks_the_header_version_from_its_remote():
    assert ProtocolProxyMessage('M', b'').protocol_version == 1
    assert ProtocolProxyMessage('M', b'', remote_id=uuid4()).protocol_version == 2


def test_connector_dispatches_by_remote_then_method():
    p = gevent_proxy()
    remote_a, remote_b = uuid4(), uuid4()
    default, for_a = mock.Mock(name='default'), mock.Mock(name='a')
    p.register_callback(default, 'PUSH')
    p.register_callback(mock.Mock(name='second-default'), 'PUSH')             # first registration wins
    p.register_callback(for_a, 'PUSH', remote_id=remote_a)
    assert p.find_callback(SimpleNamespace(method_name='PUSH', remote_id=remote_a)).method is for_a
    assert p.find_callback(SimpleNamespace(method_name='PUSH', remote_id=remote_b)).method is default    # unknown remote
    assert p.find_callback(SimpleNamespace(method_name='PUSH', remote_id=None)).method is default
    assert p.find_callback(SimpleNamespace(method_name='PUSH')).method is default                       # a V1 header
    assert p.find_callback(SimpleNamespace(method_name='OTHER', remote_id=remote_a)) is None
    replacement = mock.Mock(name='a2')
    p.register_callback(replacement, 'PUSH', remote_id=remote_a)                  # a remote's handler is replaceable
    assert p.find_callback(SimpleNamespace(method_name='PUSH', remote_id=remote_a)).method is replacement
    assert p.unregister_callback('PUSH', remote_id=remote_a) and not p.unregister_callback('PUSH', remote_id=remote_a)
    assert p.find_callback(SimpleNamespace(method_name='PUSH', remote_id=remote_a)).method is default
    assert p.unregister_callback('PUSH') and p.find_callback(SimpleNamespace(method_name='PUSH', remote_id=None)) is None


def test_gevent_sends_v2_only_when_the_message_has_a_remote():
    p = gevent_proxy()
    sock = mock.Mock()
    remote = uuid4()
    p._send_headers(sock, 3, 1, False, 'M', ProtocolProxyMessage('M', b'', remote_id=remote).protocol_version, remote)
    v2 = sock.send.call_args.args[0]
    assert v2[:2] == b'\x00\x02' and HeadersV2.unpack(v2[2:]).remote_id == remote
    p._send_headers(sock, 3, 1, False, 'M')
    v1 = sock.send.call_args.args[0]
    assert v1[:2] == b'\x00\x01' and len(v1) == 2 + HeadersV1.HEADER_LENGTH


def test_asyncio_frames_dispatch_by_their_own_header_version():
    """One connection receives a V2 frame for remote A, then a V1 frame; each reaches the right callback."""
    async def main():
        connector = AsyncioIPCConnector(proxy_id=uuid4(), token=uuid4(), proxy_name='c')
        remote = uuid4()
        got = []
        connector.register_callback(lambda conn, headers, data: got.append(('default', headers.remote_id, data)), 'PUSH')
        connector.register_callback(lambda conn, headers, data: got.append(('a', headers.remote_id, data)), 'PUSH', remote_id=remote)
        protocol = IPCProtocol(connector=connector)
        protocol.transport = mock.Mock()
        frames = (protocol._message_to_bytes(ProtocolProxyMessage('PUSH', b'for-a', request_id=1, remote_id=remote))
                  + protocol._message_to_bytes(ProtocolProxyMessage('PUSH', b'plain', request_id=2)))
        assert frames[:2] == b'\x00\x02'
        buffer = protocol.get_buffer(len(frames))
        buffer[:len(frames)] = frames
        protocol.buffer_updated(len(frames))           # first frame
        protocol.buffer_updated(0)                     # second frame, already buffered
        await asyncio.sleep(0)
        assert got == [('a', remote, b'for-a'), ('default', None, b'plain')]
    asyncio.run(main())
