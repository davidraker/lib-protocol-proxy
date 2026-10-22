"""One logging pipeline for proxy processes and the manager that launched them.

A proxy launched by a ProtocolProxyManager writes every log record as one JSON object per line on **stderr** (the
same schema VOLTTRON agents use toward the platform: the ``LogRecord`` attributes ``logging.makeLogRecord`` needs).
The manager reads both of the child's pipes and rebuilds the records in its own process, so a proxy's records look
like any other record in the manager's log and carry the proxy's logger name, file, line and PID. Plain (non-JSON)
lines are classified by stream (stderr WARNING, stdout INFO) and an optional syslog-style ``<N>`` prefix.

Record schema (one line, JSON object, written to stderr): ``name``, ``levelno``, ``levelname``, ``pathname``,
``lineno``, ``funcName``, ``created``, ``msecs``, ``process``, ``msg`` (already interpolated; ``args`` are dropped)
and ``exc_text`` (the formatted traceback when there is one). Other ``LogRecord`` attributes are included as they
are; readers ignore attributes they do not know.

A proxy run by hand in a terminal (not launched by a manager, or stderr not a pipe) logs in a readable text format
instead, so the JSON channel is only used when something is reading it.
"""
import io
import json
import logging
import os
import re
import stat
import sys
import time
import traceback
import warnings

from collections import deque
from os import environ
from typing import Iterable, TextIO

_log = logging.getLogger(__name__)

# Set in a proxy's environment by the manager that launches it; with stderr a pipe, it selects the JSON channel.
LAUNCHED_BY_MANAGER_ENV = '_LAUNCHED_BY_PROXY_MANAGER'
LOG_FILE_ENV = 'PROTOCOL_PROXY_LOG'
LOG_LEVEL_ENV = 'PROTOCOL_PROXY_LOG_LEVEL'

# Logger (in the manager's process) under which every launched proxy's records are handled; one child logger per
# proxy class and proxy, so operators tune a proxy's verbosity like any other logger's.
PROXIES_LOGGER = 'protocol_proxy.proxies'

READABLE_FORMAT = '%(asctime)s %(name)s %(levelname)s: %(message)s'

# Default level of a plain (non-JSON) line, by the stream it arrived on.
STREAM_DEFAULT_LEVELS = {'stdout': logging.INFO, 'stderr': logging.WARNING}

# A plain line may start with a syslog-style severity, ``<7>`` (debug) to ``<0>`` (emergency), which sets its level.
SYSLOG_LEVELS = {7: logging.DEBUG, 6: logging.INFO, 5: logging.INFO, 4: logging.WARNING, 3: logging.ERROR,
                 2: logging.CRITICAL, 1: logging.CRITICAL, 0: logging.CRITICAL}

# Record attributes that are not part of the wire schema: ``args`` are already applied to ``msg``, ``exc_info`` is
# rendered to ``exc_text``, ``message`` is a formatter's cache.
_UNSERIALIZED = ('args', 'exc_info', 'message')


def isapipe(stream) -> bool:
    """Whether a stream (or file descriptor) is a pipe, i.e. something is reading it."""
    try:
        fd = stream.fileno() if hasattr(stream, 'fileno') else stream
        return stat.S_ISFIFO(os.fstat(fd).st_mode)
    except (OSError, ValueError, io.UnsupportedOperation):
        return False


def record_fields(record: logging.LogRecord) -> dict:
    """The wire form of a record: its attributes with ``msg`` interpolated and the traceback rendered to
    ``exc_text``. The same dict travels as a JSON line on stderr and inside a LOG batch over the socket."""
    fields = {k: v for k, v in record.__dict__.items() if k not in _UNSERIALIZED}
    fields['msg'] = record.getMessage()
    if record.exc_info and not record.exc_text:
        fields['exc_text'] = ''.join(traceback.format_exception(*record.exc_info))
    return fields


class JsonLineFormatter(logging.Formatter):
    """Emit a record as one JSON object per line with the ``LogRecord`` attribute names, so a reader rebuilds it with
    ``logging.makeLogRecord``. Every value is JSON-escaped; values JSON cannot carry are rendered with ``str``."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record_fields(record), default=str)


class SocketLogHandler(logging.Handler):
    """Queues records for a proxy to ship to its manager in LOG batches over the IPC socket. ``emit`` never blocks
    and never does I/O: it renders the record to its wire fields and appends them to a bounded queue, subject to a
    token bucket (``rate`` records per second sustained, ``burst`` at once). Records beyond the queue or the bucket
    are dropped and counted; the count travels in the next batch so the manager can say how many were lost.
    The proxy's flusher calls ``drain`` on an interval or when ``len`` reaches its batch size."""

    def __init__(self, maxlen: int = 2000, rate: float = 50.0, burst: int = 200):
        super().__init__()
        self.queue: deque = deque()
        self.maxlen = maxlen
        self.rate, self.burst = rate, burst
        self._tokens = float(burst)
        self._refilled = time.monotonic()
        self.dropped = 0
        self.total_dropped = 0

    def _take_token(self) -> bool:
        now = time.monotonic()
        self._tokens = min(self.burst, self._tokens + (now - self._refilled) * self.rate)
        self._refilled = now
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False

    def emit(self, record: logging.LogRecord):
        try:
            fields = record_fields(record)
        except Exception:
            self.handleError(record)
            return
        if len(self.queue) >= self.maxlen or not self._take_token():
            self.dropped += 1
            self.total_dropped += 1
            return
        self.queue.append(fields)

    def __len__(self) -> int:
        return len(self.queue)

    def drain(self, limit: int | None = None) -> tuple[list[dict], int]:
        """Take up to ``limit`` queued records (all when None) and the count dropped since the last drain."""
        count = len(self.queue) if limit is None else min(limit, len(self.queue))
        records = [self.queue.popleft() for _ in range(count)]
        dropped, self.dropped = self.dropped, 0
        return records, dropped


class LoggingWriter(io.TextIOBase):
    """A line-buffering text stream that logs each complete line to a logger at a fixed level.

    Wraps ``sys.stdout`` (library prints become INFO records) and gevent's hub ``exception_stream`` (greenlet
    tracebacks become one ERROR record each). In ``blocks`` mode lines accumulate until a blank line, so a multi-line
    traceback is one record (gevent ends each failure report with a blank line). ``fileno`` still answers with the
    wrapped stream's descriptor, so code which hands the descriptor to a child process keeps working (what the child
    writes then bypasses logging)."""

    def __init__(self, logger: logging.Logger, level: int, wrapped: TextIO | None = None, name: str = 'stdout',
                 blocks: bool = False):
        super().__init__()
        self.logger, self.level, self.wrapped, self.stream_name, self.blocks = logger, level, wrapped, name, blocks
        self._buffer = ''
        self._block: list[str] = []

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        if not isinstance(text, str):
            text = text.decode('utf8', errors='replace')
        self._buffer += text
        *lines, self._buffer = self._buffer.split('\n')
        for line in lines:
            if not self.blocks:
                self._emit(line)
            elif line.strip():
                self._block.append(line)
            elif self._block:
                self._emit('\n'.join(self._block))
                self._block = []
        return len(text)

    def flush(self):
        if self._buffer:
            self._block.append(self._buffer) if self.blocks else self._emit(self._buffer)
            self._buffer = ''
        if self._block:
            self._emit('\n'.join(self._block))
            self._block = []

    def _emit(self, line: str):
        if line.strip():
            record = self.logger.makeRecord(self.logger.name, self.level, f'<{self.stream_name}>', 0, line.rstrip(),
                                            (), None)
            self.logger.handle(record)

    def fileno(self) -> int:
        if self.wrapped is None:
            raise io.UnsupportedOperation('fileno')
        return self.wrapped.fileno()

    def isatty(self) -> bool:
        return False


_configured: bool = False
_json_lines: bool = False
_stderr_handler: logging.Handler | None = None


def is_configured() -> bool:
    """Whether configure_logging has run in this process (i.e. this is a launched proxy, not a test or a library user)."""
    return _configured


def uses_json_lines() -> bool:
    """Whether this process writes the JSON record channel (launched by a manager that reads it)."""
    return _configured and _json_lines


def switch_to_socket(handler: SocketLogHandler) -> bool:
    """Route the root logger to ``handler`` instead of the stderr channel, once a proxy has registered and can
    ship LOG batches. Only in a manager-launched process on the JSON channel; returns whether it switched."""
    if not uses_json_lines() or _stderr_handler is None:
        return False
    root = logging.getLogger()
    if _stderr_handler in root.handlers:
        root.removeHandler(_stderr_handler)
    if handler not in root.handlers:
        root.addHandler(handler)
    return True


def switch_to_stderr(handler: SocketLogHandler | None = None):
    """Route the root logger back to the stderr channel (at exit, or when the socket cannot be used) and write what
    ``handler`` still holds as JSON lines on stderr, so nothing queued is lost."""
    root = logging.getLogger()
    if handler is not None and handler in root.handlers:
        root.removeHandler(handler)
    if _stderr_handler is not None and _stderr_handler not in root.handlers:
        root.addHandler(_stderr_handler)
    if handler is not None:
        records, dropped = handler.drain()
        for fields in records:
            write_json_line(fields)
        if dropped:
            write_json_line(record_fields(logging.LogRecord(__name__, logging.WARNING, __file__, 0,
                                                            f'{dropped} log records were dropped (rate or queue limit)',
                                                            (), None)))


def write_json_line(fields: dict):
    """One record, in wire form, straight to the stderr channel (used when the socket is not available)."""
    stream = _stderr_handler.stream if isinstance(_stderr_handler, logging.StreamHandler) else sys.stderr
    try:
        stream.write(json.dumps(fields, default=str) + '\n')
        stream.flush()
    except (OSError, ValueError):
        pass


def _log_uncaught(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logging.getLogger('protocol_proxy.uncaught').critical('Uncaught exception', exc_info=(exc_type, exc_value,
                                                                                           exc_traceback))


def _capture_gevent_exceptions():
    """gevent prints greenlet tracebacks straight to the hub's exception_stream (stderr); log them instead."""
    gevent = sys.modules.get('gevent')
    if gevent is None:      # not a gevent proxy; importing gevent here would be pointless and slow
        return
    try:
        if isinstance(getattr(gevent.get_hub(), 'exception_stream', None), LoggingWriter):
            return
        gevent.get_hub().exception_stream = LoggingWriter(logging.getLogger('gevent.hub'), logging.ERROR,
                                                          name='gevent', blocks=True)
    except Exception as e:  # pragma: no cover - depends on the gevent version
        _log.debug(f'Unable to redirect the gevent exception stream: {e}')


def configure_logging(level: str | int | None = None, *, json_lines: bool | None = None) -> logging.Handler:
    """Configure the root logger of a proxy process.

    Records go to the file named by ``PROTOCOL_PROXY_LOG`` if set, otherwise to stderr: as JSON lines when launched
    by a manager (``_LAUNCHED_BY_PROXY_MANAGER`` in the environment and stderr a pipe) or when ``json_lines`` is
    True; readable text otherwise. ``level`` (the ``--log-level`` option) wins over ``PROTOCOL_PROXY_LOG_LEVEL``;
    the default is INFO. Also routes what would bypass logging: Python warnings, uncaught exceptions, gevent's
    greenlet tracebacks and, on the JSON channel, anything printed to stdout. Returns the handler installed.
    """
    global _configured, _json_lines, _stderr_handler
    level = level or environ.get(LOG_LEVEL_ENV) or logging.INFO
    if isinstance(level, str) and level.isdigit():
        level = int(level)
    elif isinstance(level, str):
        level = level.upper()
    if json_lines is None:
        json_lines = LAUNCHED_BY_MANAGER_ENV in environ and isapipe(sys.stderr)
    if log_file := environ.get(LOG_FILE_ENV):
        handler: logging.Handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(READABLE_FORMAT))
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonLineFormatter() if json_lines else logging.Formatter(READABLE_FORMAT))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    logging.captureWarnings(True)
    warnings.simplefilter('default')        # once per location, instead of Python's default of hiding most of them
    sys.excepthook = _log_uncaught
    _capture_gevent_exceptions()
    if json_lines and not isinstance(sys.stdout, LoggingWriter):
        # Library prints would otherwise be plain lines on the manager's stdout pipe; as records they keep the
        # proxy's logger hierarchy and level gate.
        sys.stdout = LoggingWriter(logging.getLogger('stdout'), logging.INFO, wrapped=sys.stdout, name='stdout')
    _configured = True
    _json_lines = bool(json_lines) and not log_file
    _stderr_handler = handler
    remove_library_handlers()
    return handler


def remove_library_handlers() -> list[str]:
    """Remove handlers that libraries installed on non-root loggers, so each record reaches the configured channel
    once (a library's StreamHandler would print a second, plain copy to stderr, which the manager would then log as a
    warning). Returns the names of the loggers that had handlers; one WARNING names them."""
    stripped = []
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and logger.handlers:
            logger.handlers.clear()
            stripped.append(name)
    if stripped:
        _log.warning(f'Removed handlers a library installed on logger(s) {sorted(stripped)}; proxies log through'
                     f' the root handler only.')
    return sorted(stripped)


def guard_logging():
    """Called when a proxy starts, after its protocol library is imported: re-apply the handler rule to any logger
    the library configured at import time. Does nothing unless configure_logging has run (a test or library user
    keeps its own logging)."""
    if _configured:
        remove_library_handlers()
        _capture_gevent_exceptions()        # gevent may have been imported after configure_logging ran


# --- Reader side (the manager) ------------------------------------------------------------------------------------

def proxy_logger_name(proxy_class_name: str, proxy_name: str) -> str:
    """The manager-side logger for one launched proxy: ``protocol_proxy.proxies.<ProxyClass>.<proxy name>``, the
    proxy name reduced to logger-safe characters (dots would create further hierarchy)."""
    safe = '_'.join(filter(None, re.split(r'[^A-Za-z0-9\-]+', str(proxy_name)))) or 'proxy'
    return f'{PROXIES_LOGGER}.{proxy_class_name}.{safe}'


def record_from_fields(fields: dict, *, logger_name: str, channel: str = 'socket', pid: int | None = None,
                       process_name: str | None = None) -> logging.LogRecord:
    """Rebuild a record from its wire fields (a JSON line or one entry of a LOG batch), attributed to
    ``logger_name`` with its own logger name in ``remote_name`` and the channel it arrived by in ``channel``."""
    fields = dict(fields)
    fields.pop('args', None)        # already interpolated into msg by the sender
    record = logging.makeLogRecord(fields)
    record.remote_name = record.name
    record.name = logger_name
    record.channel = channel
    if pid is not None and not getattr(record, 'process', None):
        record.process = pid
    if process_name is not None:
        record.processName = process_name
    return record


def record_from_line(raw_line: bytes | str, *, logger_name: str, stream_name: str = 'stderr',
                     default_level: int | None = None, pid: int | None = None,
                     process_name: str | None = None) -> logging.LogRecord | None:
    """Turn one line read from a proxy's stdout or stderr into a LogRecord for ``logger_name``.

    A JSON line is rebuilt with ``logging.makeLogRecord``; its own logger name moves to ``remote_name`` and the
    record is attributed to ``logger_name``. A plain line becomes a record at ``default_level`` (by default the
    stream's: stderr WARNING, stdout INFO), or at the level a leading ``<N>`` syslog prefix names, with
    ``remote_name`` set to the stream. Returns None for an empty line.
    """
    if isinstance(raw_line, bytes):
        line = raw_line.decode('utf8', errors='replace')
    else:
        line = raw_line
    line = line.rstrip('\r\n')
    if not line.strip():
        return None
    if default_level is None:
        default_level = STREAM_DEFAULT_LEVELS.get(stream_name, logging.WARNING)
    if line.startswith('{') and line.endswith('}'):
        try:
            fields = json.loads(line)
            if isinstance(fields, dict) and 'msg' in fields:
                return record_from_fields(fields, logger_name=logger_name, channel=stream_name, pid=pid,
                                          process_name=process_name)
        except (ValueError, TypeError):
            pass
    level = default_level
    if len(line) > 2 and line[0] == '<' and line[2] == '>' and line[1].isdigit():
        level, line = SYSLOG_LEVELS.get(int(line[1]), default_level), line[3:]
    record = logging.LogRecord(logger_name, level, f'<{stream_name}>', 0, line, (), None)
    record.remote_name = stream_name
    record.channel = stream_name
    if pid is not None:
        record.process = pid
    if process_name is not None:
        record.processName = process_name
    return record


def handle_log_batch(payload: bytes | str, logger: logging.Logger, *, pid: int | None = None,
                     process_name: str | None = None) -> int:
    """Handle one LOG batch from a proxy: ``{"records": [fields...], "dropped": n}``. Each record goes through
    ``logger`` like a line from the proxy's stderr; a dropped count becomes one WARNING. Returns the records handled."""
    message = json.loads(payload if isinstance(payload, str) else payload.decode('utf8'))
    handled = 0
    for fields in message.get('records', []):
        try:
            record = record_from_fields(fields, logger_name=logger.name, channel='socket', pid=pid,
                                        process_name=process_name)
        except Exception as e:  # pragma: no cover - defensive: one bad record must not lose the batch
            _log.error(f'Unable to rebuild a log record from {logger.name}: {e}')
            continue
        if logger.isEnabledFor(record.levelno):
            logger.handle(record)
        handled += 1
    if dropped := message.get('dropped'):
        logger.warning(f'{process_name or logger.name} dropped {dropped} log records (rate or queue limit).',
                       extra={'remote_name': __name__, 'channel': 'socket'})
    return handled


def log_entries(stream: Iterable[bytes], logger: logging.Logger, *, stream_name: str = 'stderr',
                pid: int | None = None, process_name: str | None = None):
    """Read a proxy's pipe line by line and handle each record through ``logger`` (gated by its effective level).
    Blocks (or, under gevent, yields) until the stream ends."""
    for raw_line in stream:
        try:
            record = record_from_line(raw_line, logger_name=logger.name, stream_name=stream_name, pid=pid,
                                      process_name=process_name)
        except Exception as e:  # pragma: no cover - defensive: a reader must never die on a bad line
            _log.error(f'Unable to parse a log line from {logger.name} {stream_name}: {e}')
            continue
        if record is not None and logger.isEnabledFor(record.levelno):
            logger.handle(record)
