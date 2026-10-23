"""tests/test_vectors.json must match the implementation: regenerate it and decode every frame independently."""
import json
import zlib
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from protocol_proxy.ipc import HeadersV1, HeadersV2
from protocol_proxy.logs import record_from_line

import make_vectors

VECTORS = Path(__file__).with_name('test_vectors.json')


def test_vector_file_is_current():
    assert json.loads(VECTORS.read_text()) == make_vectors.vectors(), 'run python tests/make_vectors.py'


@pytest.mark.parametrize('name', list(json.loads(VECTORS.read_text())['frames']))
def test_every_frame_decodes_from_its_hex_alone(name):
    data = json.loads(VECTORS.read_text())
    vector, ids = data['frames'][name], data['identities']
    wire = bytes.fromhex(vector['frame_hex'])
    version = int.from_bytes(wire[:2], 'big')
    cls = {1: HeadersV1, 2: HeadersV2}[version]
    header_len = 2 + cls.HEADER_LENGTH
    assert wire[:header_len].hex() == vector['header_hex']
    headers = cls.unpack(wire[2:header_len])
    assert headers.method_name == vector['method_name'] and headers.request_id == vector['request_id']
    assert headers.sender_id == UUID(ids['sender_id']) and headers.sender_token == UUID(ids['sender_token'])
    assert (headers.response_expected, headers.keep_alive, headers.compressed, headers.encrypted, headers.aes_gcm) == \
        (vector['response_expected'], vector['keep_alive'], vector['compressed'], vector['encrypted'], vector['aes_gcm'])
    if version == 2:
        assert (str(headers.remote_id) if headers.remote_id else None) == vector['remote_id']
    payload = wire[header_len:]
    assert len(payload) == headers.data_length
    if headers.encrypted:
        nonce, body = payload[:12], payload[12:]
        assert nonce.hex() == ids['nonce_hex']
        aead = (AESGCM if headers.aes_gcm else ChaCha20Poly1305)(bytes.fromhex(ids['key_hex']))
        payload = aead.decrypt(nonce, body, wire[:header_len])
    if headers.compressed:
        payload = zlib.decompress(payload)
    assert payload.decode('utf8') == vector['payload_utf8']


def test_log_channel_vectors():
    log = json.loads(VECTORS.read_text())['log_channel']
    record = record_from_line(log['json_line'], logger_name='protocol_proxy.proxies.X.y')
    assert record.remote_name == 'protocol_proxy.protocol.example' and record.getMessage() == 'device d1 offline'
    assert record.levelno == 30 and record.lineno == 42 and record.funcName == 'poll' and record.process == 4242
    for plain in log['plain_lines']:
        rec = record_from_line(plain['line'], logger_name='L', stream_name=plain.get('stream', 'stderr'))
        assert rec.levelname == plain['level'] and rec.getMessage() == plain.get('message', plain['line'])
