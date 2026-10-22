"""Logs over the IPC socket: the handler and batch reader, the manager's LOG endpoint, and real proxies whose records
reach the manager by stderr before registration, by LOG batches after it, and by stderr again at exit."""
import json
import logging
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import gevent
import pytest

from protocol_proxy import logs
from protocol_proxy.logs import SocketLogHandler, handle_log_batch, record_from_fields
from protocol_proxy.manager.gevent import GeventProtocolProxyManager


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def proxies_log():
    """Collects every record the manager handles for its proxies; INFO unless a test raises it."""
    logger, handler = logging.getLogger('protocol_proxy.proxies'), ListHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(logging.NOTSET)
        for name, child in list(logging.Logger.manager.loggerDict.items()):
            if name.startswith('protocol_proxy.proxies.') and isinstance(child, logging.Logger):
                child.setLevel(logging.NOTSET)


def _record(msg, level=logging.INFO, name='proxy.mod'):
    return logging.LogRecord(name, level, '/p/f.py', 3, msg, (), None)


def test_socket_handler_queues_without_io_and_counts_drops():
    handler = SocketLogHandler(maxlen=5, rate=1000, burst=1000)
    for i in range(8):
        handler.emit(_record('m%d' % i))
    assert len(handler) == 5 and handler.dropped == 3
    records, dropped = handler.drain(limit=2)
    assert [r['msg'] for r in records] == ['m0', 'm1'] and dropped == 3 and handler.dropped == 0
    assert records[0]['name'] == 'proxy.mod' and records[0]['levelno'] == logging.INFO and 'args' not in records[0]
    records, dropped = handler.drain()
    assert [r['msg'] for r in records] == ['m2', 'm3', 'm4'] and dropped == 0 and len(handler) == 0
    assert handler.total_dropped == 3


def test_socket_handler_rate_limits_with_a_token_bucket():
    handler = SocketLogHandler(maxlen=10_000, rate=10, burst=5)
    for i in range(20):
        handler.emit(_record('burst %d' % i))
    assert len(handler) == 5 and handler.dropped == 15           # the burst, then nothing until tokens refill
    time.sleep(0.25)
    handler.emit(_record('later'))
    assert len(handler) == 6                                      # ~2.5 tokens refilled at 10/s


def test_handle_log_batch_feeds_the_proxy_logger_and_reports_drops(proxies_log):
    logger = logging.getLogger('protocol_proxy.proxies.P.unit')
    handler = SocketLogHandler()
    handler.emit(_record('one'))
    handler.emit(_record('two', logging.ERROR, 'lib.x'))
    handler.emit(_record('too quiet', logging.DEBUG))
    handler.dropped = 4
    records, dropped = handler.drain()
    payload = json.dumps({'records': records, 'dropped': dropped}).encode()
    assert handle_log_batch(payload, logger, pid=77, process_name="('h', 1)") == 3
    messages = [(r.getMessage(), r.levelno, r.remote_name, r.channel) for r in proxies_log]
    assert messages[:2] == [('one', logging.INFO, 'proxy.mod', 'socket'), ('two', logging.ERROR, 'lib.x', 'socket')]
    assert proxies_log[0].name == 'protocol_proxy.proxies.P.unit' and proxies_log[0].processName == "('h', 1)"
    assert proxies_log[0].pathname == '/p/f.py' and proxies_log[0].lineno == 3
    assert 'dropped 4 log records' in messages[-1][0] and messages[-1][1] == logging.WARNING
    assert len(proxies_log) == 3                                  # the DEBUG record was gated by the logger's level


def test_record_from_fields_keeps_the_senders_pid_and_marks_the_channel():
    fields = logs.record_fields(_record('x'))
    fields['process'] = 4242
    record = record_from_fields(fields, logger_name='L', pid=1)
    assert record.process == 4242 and record.channel == 'socket' and record.remote_name == 'proxy.mod'


def test_switching_channels_restores_stderr_and_flushes_the_queue(monkeypatch, capsys):
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logs.JsonLineFormatter())
    monkeypatch.setattr(logs, '_configured', True)
    monkeypatch.setattr(logs, '_json_lines', True)
    monkeypatch.setattr(logs, '_stderr_handler', stderr_handler)
    root = logging.getLogger()
    root.addHandler(stderr_handler)
    handler = SocketLogHandler()
    try:
        assert logs.switch_to_socket(handler)
        assert handler in root.handlers and stderr_handler not in root.handlers
        handler.emit(_record('left in the queue'))
        handler.dropped = 2
        logs.switch_to_stderr(handler)
        assert stderr_handler in root.handlers and handler not in root.handlers
        lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.startswith('{')]
        assert lines[0]['msg'] == 'left in the queue' and '2 log records were dropped' in lines[1]['msg']
        monkeypatch.setattr(logs, '_json_lines', False)
        assert not logs.switch_to_socket(handler)                # a hand-run proxy keeps readable stderr
    finally:
        root.removeHandler(stderr_handler)
        root.removeHandler(handler)


def test_manager_log_endpoint_uses_the_peers_logger_and_set_level_gates_both_ends(proxies_log):
    from test_manager import DummyProxy, FakeProcess
    from unittest import mock
    from protocol_proxy.ipc import SocketParams
    manager = GeventProtocolProxyManager(proxy_class=DummyProxy)
    manager.inbound_params = SocketParams('127.0.0.1', 22801)
    with mock.patch('protocol_proxy.manager.gevent.Popen', FakeProcess), mock.patch('atexit.register'):
        peer = manager.get_proxy(('dummy', 'x'))
    assert peer.name == "('dummy', 'x')"
    headers = SimpleNamespace(sender_id=peer.proxy_id, sender_token=peer.token, request_id=1)
    fields = logs.record_fields(_record('hello'))
    fields['process'] = peer.process.pid                           # stamped by the proxy process itself
    batch = json.dumps({'records': [fields], 'dropped': 0}).encode()
    manager.handle_log(manager, headers, batch)
    assert [(r.getMessage(), r.name, r.process) for r in proxies_log] == \
        [('hello', 'protocol_proxy.proxies.DummyProxy.dummy_x', peer.process.pid)]
    with mock.patch.object(manager, 'send', return_value=True) as send:
        assert manager.set_proxy_log_level(peer, logging.DEBUG) is True
        message = send.call_args.args[1]
        assert message.method_name == 'SET_LOG_LEVEL' and json.loads(message.payload) == {'level': 'DEBUG'}
    assert logging.getLogger('protocol_proxy.proxies.DummyProxy.dummy_x').level == logging.DEBUG
    wrong = SimpleNamespace(sender_id=peer.proxy_id, sender_token=peer.proxy_id, request_id=2)
    manager.handle_log(manager, wrong, batch)                      # unauthenticated: dropped by the callback guard
    assert len(proxies_log) == 1


def _wait(predicate, timeout=10, what='condition'):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f'timed out waiting for {what}')
        gevent.sleep(0.05)


@pytest.mark.parametrize('proxy_class_name', ['GeventDummy', 'AsyncioDummy'])
def test_real_proxy_logs_by_stderr_then_socket_then_stderr_at_exit(proxy_class_name, proxies_log, monkeypatch):
    tests_dir = str(Path(__file__).resolve().parent)         # the child imports dummy_proxies from here
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(filter(None, [tests_dir, os.environ.get('PYTHONPATH')])))
    import dummy_proxies as dummies
    manager = GeventProtocolProxyManager(proxy_class=getattr(dummies, proxy_class_name))
    manager.start()
    loop = gevent.spawn(manager.select_loop)
    peer = None
    try:
        peer = manager.get_proxy(('dummy', 'x'))
        manager.wait_peer_registered(peer, 20)
        assert peer.socket_params is not None, 'proxy did not register'
        def by_socket():
            return [r for r in proxies_log if r.channel == 'socket']
        _wait(lambda: any(r.getMessage().startswith('tick') for r in by_socket()), what='a tick over the socket')
        tick = next(r for r in by_socket() if r.getMessage().startswith('tick'))
        assert tick.remote_name == 'dummy_proxies' and tick.levelno == logging.INFO
        assert tick.process == peer.process.pid and tick.name == 'protocol_proxy.proxies.%s.dummy_x' % proxy_class_name
        assert tick.pathname.endswith('dummy_proxies.py') and tick.lineno > 0
        assert not any(r.levelno == logging.DEBUG for r in proxies_log)
        # Everything up to registration came by the pipe; the switch itself is the first record over the socket.
        assert any(r.channel == 'stderr' and 'Registered with manager' in r.getMessage() for r in proxies_log)
        assert any('logging over the IPC socket' in r.getMessage() for r in by_socket())
        reply = manager.set_proxy_log_level(peer, 'DEBUG').get(timeout=5)
        assert json.loads(reply) == {'level': 'DEBUG'}
        _wait(lambda: any(r.levelno == logging.DEBUG and r.getMessage().startswith('debug tick') for r in by_socket()),
              what='a debug tick after SET_LOG_LEVEL')
        manager._cleanup_proxy_process(peer.process)
        assert peer.process.returncode == 0
        _wait(lambda: any(r.channel == 'stderr' and 'stopping' in r.getMessage() for r in proxies_log),
              what='the stop record flushed to stderr at exit')
    finally:
        if peer is not None and peer.process is not None and peer.process.poll() is None:
            peer.process.kill()
        manager.stop()
        gevent.joinall([loop], timeout=2)
