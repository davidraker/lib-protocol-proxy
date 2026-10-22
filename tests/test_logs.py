"""The proxy log channel: JSON records on stderr, rebuilt by the manager; plain lines classified by stream and
prefix; warnings, prints, uncaught exceptions and greenlet failures captured as records."""
import io
import json
import logging
import os
import subprocess
import sys

import pytest

from protocol_proxy.logs import (JsonLineFormatter, LoggingWriter, STREAM_DEFAULT_LEVELS, log_entries,
                                 proxy_logger_name, record_from_line, remove_library_handlers)

LOGGER = 'protocol_proxy.proxies.TestProxy.unit'


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def collected():
    """A list of the records the proxy logger handled during the test."""
    logger, handler = logging.getLogger(LOGGER), ListHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(logging.NOTSET)
        logger.propagate = True


def test_plain_lines_take_the_streams_default_level_or_the_syslog_prefix():
    err = record_from_line(b'Server listening.\n', logger_name=LOGGER, stream_name='stderr', pid=42)
    assert (err.levelno, err.getMessage(), err.remote_name, err.process) == (logging.WARNING, 'Server listening.',
                                                                              'stderr', 42)
    out = record_from_line(b'Server listening.\n', logger_name=LOGGER, stream_name='stdout')
    assert out.levelno == logging.INFO and out.name == LOGGER and out.pathname == '<stdout>'
    assert STREAM_DEFAULT_LEVELS == {'stdout': logging.INFO, 'stderr': logging.WARNING}
    debug = record_from_line(b'<7>chatter\n', logger_name=LOGGER)
    assert debug.levelno == logging.DEBUG and debug.getMessage() == 'chatter'
    assert record_from_line(b'<3>bad\n', logger_name=LOGGER).levelno == logging.ERROR
    assert record_from_line(b'<2>worse\n', logger_name=LOGGER).levelno == logging.CRITICAL
    assert record_from_line(b'\n', logger_name=LOGGER) is None and record_from_line(b'   ', logger_name=LOGGER) is None
    # Braces that are not a record (or not JSON) are a plain line, never an exception.
    assert record_from_line(b'{not json}', logger_name=LOGGER).getMessage() == '{not json}'
    assert record_from_line(b'{"a": 1}', logger_name=LOGGER).getMessage() == '{"a": 1}'
    assert record_from_line(b'\xff\xfe raw', logger_name=LOGGER).levelno == logging.WARNING


def test_json_lines_rebuild_the_record_with_its_origin_and_traceback():
    try:
        raise ValueError('inner')
    except ValueError:
        record = logging.LogRecord('pymodbus.logging', logging.ERROR, '/lib/pymodbus/x.py', 7, 'failed %d', (3,),
                                   sys.exc_info(), func='connect')
    record.process = 4242
    line = JsonLineFormatter().format(record)
    assert '\n' not in line
    rebuilt = record_from_line(line.encode('utf8'), logger_name=LOGGER, pid=1, process_name="('h', 502)")
    assert rebuilt.name == LOGGER and rebuilt.remote_name == 'pymodbus.logging' and rebuilt.processName == "('h', 502)"
    assert rebuilt.getMessage() == 'failed 3' and rebuilt.levelno == logging.ERROR and rebuilt.levelname == 'ERROR'
    assert (rebuilt.pathname, rebuilt.lineno, rebuilt.funcName, rebuilt.process) == ('/lib/pymodbus/x.py', 7,
                                                                                     'connect', 4242)
    assert 'ValueError: inner' in rebuilt.exc_text
    # Formatting in the manager's process renders the proxy's traceback, as for a local record.
    assert 'ValueError: inner' in logging.Formatter('%(message)s').format(rebuilt)


def test_formatter_renders_unserializable_extras_with_str():
    record = logging.LogRecord('x', logging.INFO, 'p', 1, 'm', None, None)
    record.peer = object()
    assert 'object at' in json.loads(JsonLineFormatter().format(record))['peer']


def test_log_entries_gates_on_the_proxy_loggers_level(collected):
    logger = logging.getLogger(LOGGER)
    lines = [JsonLineFormatter().format(logging.LogRecord('p', level, 'f', 1, name, None, None)).encode() + b'\n'
             for name, level in (('debug', logging.DEBUG), ('info', logging.INFO), ('error', logging.ERROR))]
    lines += [b'plain\n', b'', b'<6>noted\n']
    logger.setLevel(logging.INFO)
    log_entries(lines, logger, stream_name='stderr', pid=9)
    assert [r.getMessage() for r in collected] == ['info', 'error', 'plain', 'noted']
    assert [r.levelno for r in collected] == [logging.INFO, logging.ERROR, logging.WARNING, logging.INFO]
    assert collected[2].process == 9 and collected[0].remote_name == 'p' and collected[2].remote_name == 'stderr'


def test_proxy_logger_name_is_logger_safe():
    assert proxy_logger_name('ModbusProxy', "('192.168.0.1', 502)") == \
        'protocol_proxy.proxies.ModbusProxy.192_168_0_1_502'
    assert proxy_logger_name('X', 'plain-name_ok') == 'protocol_proxy.proxies.X.plain-name_ok'
    assert proxy_logger_name('X', '...') == 'protocol_proxy.proxies.X.proxy'


def test_logging_writer_buffers_lines_and_blocks(collected):
    logger = logging.getLogger(LOGGER)
    writer = LoggingWriter(logger, logging.INFO, wrapped=sys.__stdout__, name='stdout')
    writer.write('partial')
    writer.write(' line\nsecond\n\nthird')
    assert [r.getMessage() for r in collected] == ['partial line', 'second']         # blank lines are dropped
    writer.flush()
    assert collected[-1].getMessage() == 'third' and collected[-1].pathname == '<stdout>'
    assert writer.fileno() == sys.__stdout__.fileno() and not writer.isatty()
    collected.clear()
    blocks = LoggingWriter(logger, logging.ERROR, name='gevent', blocks=True)
    blocks.write('Traceback (most recent call last):\n  File "x"\nValueError: boom\n')
    blocks.write('2026-10-22T00:00:00Z <Greenlet> failed with ValueError\n\n')
    assert len(collected) == 1 and collected[0].levelno == logging.ERROR
    assert collected[0].getMessage().startswith('Traceback') and 'failed with ValueError' in collected[0].getMessage()
    blocks.write('tail without blank line')
    blocks.flush()
    assert collected[-1].getMessage() == 'tail without blank line'
    with pytest.raises(io.UnsupportedOperation):
        blocks.fileno()


def test_remove_library_handlers_strips_and_names_them(caplog):
    lib = logging.getLogger('test_logs.somelib.sub')
    lib.addHandler(logging.StreamHandler(io.StringIO()))
    with caplog.at_level(logging.WARNING, logger='protocol_proxy.logs'):
        assert remove_library_handlers() == ['test_logs.somelib.sub']
    assert lib.handlers == [] and 'test_logs.somelib.sub' in caplog.text
    assert remove_library_handlers() == []


CHILD = r'''
import logging, sys, warnings
lib = logging.getLogger('somelib')
lib.addHandler(logging.StreamHandler(sys.stderr))          # what pymodbus_apply_logging_config does
if sys.argv[2] == 'gevent':
    from gevent import monkey                               # as launch.main does, before configure_logging
    monkey.patch_all(thread=False)
from protocol_proxy.logs import configure_logging, is_configured
configure_logging(sys.argv[1])
assert is_configured()
logging.getLogger('proxy.module').info('hello %s', 'world')
logging.getLogger('proxy.module').debug('too quiet')
warnings.warn('deprecated thing', DeprecationWarning)
print('printed line')
sys.stderr.write('<7>plain debug\n'); sys.stderr.flush()
try:
    1 / 0
except ZeroDivisionError:
    logging.getLogger('proxy.module').exception('failed')
if sys.argv[2] == 'gevent':
    import gevent
    def boom():
        raise ValueError('in greenlet')
    gevent.spawn(boom).join()
sys.stdout.flush()
raise RuntimeError('uncaught')
'''


def _run_child(mode: str, collected: list, level: str = 'INFO', env_marker: bool = True):
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)}
    env.pop('PROTOCOL_PROXY_LOG', None)
    env.pop('PROTOCOL_PROXY_LOG_LEVEL', None)
    if env_marker:
        env['_LAUNCHED_BY_PROXY_MANAGER'] = '1'
    process = subprocess.Popen([sys.executable, '-c', CHILD, level, mode], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.stdout, process.stderr = process.communicate(timeout=60)      # the pipes' whole contents, as bytes
    logger = logging.getLogger(LOGGER)
    log_entries(process.stderr.splitlines(keepends=True), logger, stream_name='stderr', pid=process.pid)
    log_entries(process.stdout.splitlines(keepends=True), logger, stream_name='stdout', pid=process.pid)
    return process


def test_child_process_logs_everything_as_records_on_stderr(collected):
    process = _run_child('plain', collected)
    assert process.returncode == 1, process.stderr
    assert process.stdout == b''                                    # prints went through the log channel
    by_message = {r.getMessage().splitlines()[0]: r for r in collected}
    hello = by_message['hello world']
    assert hello.remote_name == 'proxy.module' and hello.levelno == logging.INFO and hello.process == process.pid
    assert hello.lineno > 0 and hello.name == LOGGER
    assert 'too quiet' not in by_message
    warning = next(r for r in collected if r.remote_name == 'py.warnings')
    assert 'deprecated thing' in warning.getMessage() and warning.levelno == logging.WARNING
    printed = by_message['printed line']
    assert printed.remote_name == 'stdout' and printed.levelno == logging.INFO
    plain = by_message['plain debug']
    assert plain.remote_name == 'stderr' and plain.levelno == logging.DEBUG
    failed = by_message['failed']
    assert failed.levelno == logging.ERROR and 'ZeroDivisionError' in failed.exc_text
    uncaught = by_message['Uncaught exception']
    assert uncaught.remote_name == 'protocol_proxy.uncaught' and uncaught.levelno == logging.CRITICAL
    assert 'RuntimeError: uncaught' in uncaught.exc_text
    stripped = next(r for r in collected if r.remote_name == 'protocol_proxy.logs')
    assert 'somelib' in stripped.getMessage() and stripped.levelno == logging.WARNING
    # Every stderr line but the prefixed one was a record: nothing plain leaked (no duplicate library handler output).
    assert [r.getMessage() for r in collected if r.remote_name == 'stderr'] == ['plain debug']


def test_gevent_child_logs_greenlet_failures_as_one_record(collected):
    process = _run_child('gevent', collected)
    assert process.returncode == 1, process.stderr
    hub = [r for r in collected if r.remote_name == 'gevent.hub']
    assert len(hub) == 1 and hub[0].levelno == logging.ERROR
    assert 'ValueError: in greenlet' in hub[0].getMessage() and 'failed with ValueError' in hub[0].getMessage()


def test_child_without_the_marker_logs_readable_text(collected):
    process = _run_child('plain', collected, env_marker=False)
    text = process.stderr.decode()
    assert 'proxy.module INFO: hello world' in text and not text.lstrip().startswith('{')
    assert process.stdout == b'printed line\n'                     # stdout is left alone outside the JSON channel
    assert 'RuntimeError: uncaught' in text
