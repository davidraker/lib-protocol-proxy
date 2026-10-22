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
import traceback
import warnings

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


class JsonLineFormatter(logging.Formatter):
    """Emit a record as one JSON object per line with the ``LogRecord`` attribute names, so a reader rebuilds it with
    ``logging.makeLogRecord``. Every value is JSON-escaped; values JSON cannot carry are rendered with ``str``."""

    def format(self, record: logging.LogRecord) -> str:
        fields = {k: v for k, v in record.__dict__.items() if k not in _UNSERIALIZED}
        fields['msg'] = record.getMessage()
        if record.exc_info and not record.exc_text:
            fields['exc_text'] = ''.join(traceback.format_exception(*record.exc_info))
        return json.dumps(fields, default=str)


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


def is_configured() -> bool:
    """Whether configure_logging has run in this process (i.e. this is a launched proxy, not a test or a library user)."""
    return _configured


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
    global _configured
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
    record = None
    if line.startswith('{') and line.endswith('}'):
        try:
            fields = json.loads(line)
            if isinstance(fields, dict) and 'msg' in fields:
                fields.pop('args', None)        # already interpolated into msg by the sender
                record = logging.makeLogRecord(fields)
                record.remote_name = record.name
        except (ValueError, TypeError):
            record = None
    if record is None:
        level = default_level
        if len(line) > 2 and line[0] == '<' and line[2] == '>' and line[1].isdigit():
            level, line = SYSLOG_LEVELS.get(int(line[1]), default_level), line[3:]
        record = logging.LogRecord(logger_name, level, f'<{stream_name}>', 0, line, (), None)
        record.remote_name = stream_name
        if pid is not None:
            record.process = pid
    record.name = logger_name
    if process_name is not None:
        record.processName = process_name
    return record


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
