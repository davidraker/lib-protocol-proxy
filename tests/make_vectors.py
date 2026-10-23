"""Generate tests/test_vectors.json: byte-exact examples of the wire protocol for other implementations to check
against. Deterministic: fixed ids, tokens, key and nonce. Run ``python tests/make_vectors.py`` to regenerate;
tests/test_protocol_vectors.py fails if the file and the implementation disagree."""
import json
import struct
import sys
import zlib
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from protocol_proxy.ipc import HeadersV1, HeadersV2
from protocol_proxy.logs import JsonLineFormatter, SYSLOG_LEVELS
import logging

SENDER = UUID('11111111-2222-3333-4444-555555555555')
TOKEN = UUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
REMOTE = UUID('99999999-8888-7777-6666-555555555555')
KEY = bytes(range(32))
NONCE = bytes(range(12))


def frame(cls, method, payload, request_id, *, response_expected=False, keep_alive=False, compressed=False,
          encrypted=False, remote_id=None, compress=False, key=None, aes_gcm=False):
    """A frame as the Python connectors build it, with the compressed and encrypted transforms applied in order."""
    plain = payload
    if compress:
        payload, compressed = zlib.compress(payload), True
    extra = {'remote_id': remote_id} if cls is HeadersV2 else {}
    if key is not None:
        header = cls(len(payload) + 12 + 16, method, request_id, SENDER, TOKEN, response_expected,
                     keep_alive=keep_alive, compressed=compressed, encrypted=True, aes_gcm=aes_gcm, **extra).pack()
        aead = AESGCM(key) if aes_gcm else ChaCha20Poly1305(key)
        wire = header + NONCE + aead.encrypt(NONCE, payload, header)
    else:
        header = cls(len(payload), method, request_id, SENDER, TOKEN, response_expected, keep_alive=keep_alive,
                     compressed=compressed, encrypted=False, **extra).pack()
        wire = header + payload
    return {'header_hex': header.hex(), 'frame_hex': wire.hex(), 'payload_utf8': plain.decode('utf8'),
            'method_name': method, 'request_id': request_id, 'response_expected': response_expected,
            'keep_alive': keep_alive, 'compressed': compressed, 'encrypted': key is not None,
            'remote_id': str(remote_id) if remote_id else None, 'header_version': cls.VERSION, 'aes_gcm': aes_gcm}


def vectors() -> dict:
    record = logging.LogRecord('protocol_proxy.protocol.example', logging.WARNING, '/srv/proxy/example.py', 42,
                               'device %s offline', ('d1',), None, func='poll')
    record.created, record.msecs, record.relativeCreated, record.process, record.thread = 1_760_000_000.5, 500.0, 12.0, 4242, 1
    record.threadName, record.processName, record.taskName = 'MainThread', 'MainProcess', None
    return {
        'about': 'protocol-proxy wire vectors; see PROTOCOL.md. sender_id, sender_token, key and nonce are fixed test values.',
        'constants': {
            'header_length_v1': HeadersV1.HEADER_LENGTH, 'header_length_v2': HeadersV2.HEADER_LENGTH,
            'version_word_bytes': 2, 'bit_response_expected': HeadersV1.RESPONSE_EXPECTED_BIT,
            'bit_compressed': HeadersV1.COMPRESSED_BIT, 'bit_encrypted': HeadersV1.ENCRYPTED_BIT,
            'bit_keep_alive': HeadersV1.KEEP_ALIVE_BIT, 'bit_aes_gcm': HeadersV1.AES_GCM_BIT,
            'request_id_max_v1': HeadersV1.REQUEST_ID_MAX,
            'request_id_max_v2': HeadersV2.REQUEST_ID_MAX, 'nonce_bytes': 12, 'tag_bytes': 16, 'key_bytes': 32,
            'stdin_layout': 'proxy token hex (32) + manager token hex (32) [+ key hex (64) with --encrypt true]',
            'syslog_prefix_levels': {f'<{n}>': logging.getLevelName(level) for n, level in SYSLOG_LEVELS.items()},
        },
        'identities': {'sender_id': str(SENDER), 'sender_token': str(TOKEN), 'remote_id': str(REMOTE),
                       'key_hex': KEY.hex(), 'nonce_hex': NONCE.hex()},
        'frames': {
            'v1_request': frame(HeadersV1, 'READ_POINTS', b'{"topics": ["a", "b"]}', 7, response_expected=True),
            'v2_request_with_remote': frame(HeadersV2, 'READ_POINTS', b'{"topics": ["a", "b"]}', 70000,
                                            response_expected=True, remote_id=REMOTE),
            'v2_response': frame(HeadersV2, 'RESPONSE', b'{"result": {"a": 1}, "error": {}}', 70000),
            'v2_push_keep_alive': frame(HeadersV2, 'RECEIVE_UNSOLICITED', b'{"a": 1}', 3, keep_alive=True,
                                        remote_id=REMOTE),
            'v2_register_peer': frame(HeadersV2, 'REGISTER_PEER', json.dumps(
                {'address': '127.0.0.1', 'port': 22802, 'proxy_id': SENDER.hex, 'token': TOKEN.hex,
                 'features': ['ping', 'log', 'set_log_level', 'compress', 'aead-chacha20poly1305', 'aead-aes256gcm'],
                 'cipher': 'chacha20-poly1305'}).encode(), 1,
                response_expected=True),
            'v2_compressed': frame(HeadersV2, 'REGISTER_REMOTE', (b'{"points": [' + b', '.join(
                b'{"name": "p%d", "index": %d}' % (i, i) for i in range(200)) + b']}'), 8, response_expected=True,
                remote_id=REMOTE, compress=True),
            'v2_encrypted': frame(HeadersV2, 'WRITE_POINTS', b'{"values": {"a": 1}}', 9, response_expected=True,
                                  remote_id=REMOTE, key=KEY),
            'v2_compressed_encrypted': frame(HeadersV2, 'LOG', (b'{"records": [' + b', '.join(
                b'{"name": "x", "levelno": 20, "msg": "tick %d"}' % i for i in range(300)) + b'], "dropped": 0}'), 10,
                compress=True, key=KEY),
            'v2_encrypted_aes_gcm': frame(HeadersV2, 'WRITE_POINTS', b'{"values": {"a": 1}}', 12, response_expected=True,
                                          remote_id=REMOTE, key=KEY, aes_gcm=True),
            'v2_error_reply': frame(HeadersV2, 'RESPONSE', json.dumps(
                {'status': 'error', 'error': 'Unknown method NOPE', 'method': 'NOPE'}).encode(), 11),
        },
        'log_channel': {
            'json_line': JsonLineFormatter().format(record),
            'plain_lines': [{'line': '<7>very chatty', 'level': 'DEBUG', 'message': 'very chatty'},
                            {'line': 'Server listening.', 'stream': 'stderr', 'level': 'WARNING'},
                            {'line': 'Server listening.', 'stream': 'stdout', 'level': 'INFO'}],
            'log_batch_payload': json.dumps({'records': [json.loads(JsonLineFormatter().format(record))], 'dropped': 2}),
            'set_log_level_request': '{"level": "DEBUG"}', 'set_log_level_reply': '{"level": "DEBUG"}',
            'ping_reply_example': '{"uptime": 12.345, "remotes": 3, "busy": false, "last_activity": "2026-10-22T20:00:00+00:00"}',
            'register_peer_reply': '{"registered": true, "features": ["compress", "aead-chacha20poly1305", "aead-aes256gcm"]}',
        },
    }


def main(argv=None):
    out = Path(__file__).with_name('test_vectors.json')
    out.write_text(json.dumps(vectors(), indent=1) + '\n')
    print(f'wrote {out}')


if __name__ == '__main__':
    sys.exit(main())
