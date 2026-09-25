import json
import logging
import sys

from argparse import ArgumentParser, ArgumentTypeError
from asyncio import iscoroutinefunction, run
from importlib import import_module
from os import environ
from typing import Callable
from uuid import UUID

from ..ipc import SocketParams

_log = logging.getLogger(__name__)

TOKEN_HEX_LENGTH = 32


class JsonLineFormatter(logging.Formatter):
    """Emit one JSON object per line. ProtocolProxyManager.log_subprocess_output_line parses these
    and re-logs them in the manager's process, so every field must be JSON-escaped."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            message = f'{message}\n{self.formatException(record.exc_info)}'
        return json.dumps({'name': record.name, 'lineno': record.lineno, 'level': record.levelname,
                           'message': message})


def configure_logging(level: str | int | None = None):
    """Route all logging to stdout (or the file named by PROTOCOL_PROXY_LOG) as JSON lines."""
    level = level or environ.get('PROTOCOL_PROXY_LOG_LEVEL', 'INFO')
    if log_file := environ.get('PROTOCOL_PROXY_LOG'):
        handler: logging.Handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLineFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


SENSITIVE_KEYS = ('password', 'token', 'secret', 'credential')


def redact(options: dict) -> dict:
    """Mask credential-like values before they reach the logs."""
    return {k: ('***' if any(s in k.lower() for s in SENSITIVE_KEYS) and v else v) for k, v in options.items()}


def str2bool(value: str | bool) -> bool:
    """argparse type for boolean options that are always passed with a value
    (the ProtocolProxyManager passes every parameter as ``--name value``)."""
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in ('1', 'true', 't', 'yes', 'y', 'on'):
        return True
    if lowered in ('0', 'false', 'f', 'no', 'n', 'off', ''):
        return False
    raise ArgumentTypeError(f'Expected a boolean value, got "{value}".')


def proxy_command_parser(parser: ArgumentParser = None):
    parser = parser if parser else ArgumentParser()
    parser.add_argument('--proxy-id', type=UUID, required=True)
    parser.add_argument('--proxy-name', type=str, required=True)
    parser.add_argument('--manager-id', type=UUID, required=True)
    parser.add_argument('--manager-address', type=str, default='localhost',
                        help='Address of the outbound socket to the Proxy Manager.')
    parser.add_argument('--manager-port', type=int, default=22801,
                        help='Port of the outbound socket to the Proxy Manager.')
    parser.add_argument('--encrypt', type=str2bool, default=False,
                        help='Whether to use encryption on the socket connections with the Manager.')
    parser.add_argument('--inbound-address', type=str, default='localhost',
                        help='Address of the inbound socket from the Proxy Manager')
    parser.add_argument('--inbound-port', type=int, default=None,
                        help='Port of the inbound socket from the Proxy Manager. Chosen automatically if omitted.')
    parser.add_argument('--log-level', type=str, default=None,
                        help='Logging level for the proxy process (default: PROTOCOL_PROXY_LOG_LEVEL or INFO).')
    return parser


def _read_tokens() -> tuple[UUID, UUID]:
    """The manager writes the proxy token followed by its own token, as hex, to the proxy's stdin."""
    data = sys.stdin.buffer.read(2 * TOKEN_HEX_LENGTH)
    if len(data) != 2 * TOKEN_HEX_LENGTH:
        raise ValueError(f'Expected {2 * TOKEN_HEX_LENGTH} hex characters (proxy token + manager token) on stdin,'
                         f' got {len(data)} bytes. Proxies are meant to be launched by a ProtocolProxyManager.')
    return UUID(hex=data[:TOKEN_HEX_LENGTH].decode('utf8')), UUID(hex=data[TOKEN_HEX_LENGTH:].decode('utf8'))


def launch(launcher_func: Callable, argv: list[str] | None = None) -> int:
    """Parse arguments, read tokens, and run the proxy. Returns the process exit code.

    ``launcher_func`` receives the base parser and returns ``(parser, proxy_runner)`` where
    ``proxy_runner`` is a function or coroutine function taking the parsed options as kwargs.
    """
    parser = proxy_command_parser()
    parser, proxy_runner = launcher_func(parser)
    opts = vars(parser.parse_args(argv))    # argparse exits itself on --help or bad arguments.
    configure_logging(opts.pop('log_level'))
    inbound_address, inbound_port = opts.pop('inbound_address'), opts.pop('inbound_port')
    opts['inbound_params'] = SocketParams(inbound_address, inbound_port) if inbound_port else None
    _log.info(f'Launching Proxy with parameters: {redact(opts)}')
    try:
        proxy_token, manager_token = _read_tokens()
        if iscoroutinefunction(proxy_runner):
            result = run(proxy_runner(token=proxy_token, manager_token=manager_token, **opts))
        else:
            result = proxy_runner(token=proxy_token, manager_token=manager_token, **opts)
    except KeyboardInterrupt:
        _log.info('Proxy Launch: interrupted.')
        return 0
    except Exception:
        _log.exception('Proxy Launch: proxy terminated with an unhandled exception.')
        return 1
    return int(result) if isinstance(result, int) else 0


USAGE = 'usage: python -m protocol_proxy.proxy [--gevent] <module>:<ProxyClass> [proxy options...]'


def default_launcher(proxy_class: type) -> Callable:
    """Launcher for proxies which declare no LAUNCHER: no extra options; ``proxy_class(**options).start()``."""
    def launcher(parser: ArgumentParser) -> tuple[ArgumentParser, Callable]:
        if iscoroutinefunction(proxy_class.start):
            async def runner(**options) -> int:
                proxy = proxy_class(**options)    # Must be created inside the running event loop.
                await proxy.start()
                return 0
        else:
            def runner(**options) -> int:
                proxy_class(**options).start()
                return 0
        return parser, runner
    return launcher


def resolve_launcher(proxy_ref: str) -> Callable:
    """Import ``module:ProxyClass`` (once, under its real name) and return the launcher for that class.

    The class's LAUNCHER attribute names a module-level launcher function; when it is None, a default launcher
    which takes no protocol options is used.
    """
    module_name, _, class_name = proxy_ref.partition(':')
    if not module_name or not class_name:
        raise ValueError(f'Proxy reference must be <module>:<ProxyClass>, got {proxy_ref!r}')
    module = import_module(module_name)
    proxy_class = getattr(module, class_name)
    launcher_name = getattr(proxy_class, 'LAUNCHER', None)
    if launcher_name is None:
        return default_launcher(proxy_class)
    launcher = getattr(module, launcher_name, None)
    if not callable(launcher):
        raise ValueError(f'{proxy_ref}: LAUNCHER names {launcher_name!r}, which is not a function in {module_name}')
    return launcher


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m protocol_proxy.proxy``: the command a ProtocolProxyManager launches.

    Launching through this module (rather than ``python -m <proxy module>``) means the proxy module is imported
    exactly once, under its own name, however its package's ``__init__`` is written. ``--gevent`` monkey-patches
    the process before the proxy module (and its protocol library) is imported.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    patch_gevent = False
    while argv and argv[0] == '--gevent':
        patch_gevent = True
        argv.pop(0)
    if not argv or argv[0].startswith('-'):
        print(USAGE, file=sys.stderr)
        return 2
    proxy_ref = argv.pop(0)
    if patch_gevent:
        from gevent import monkey
        monkey.patch_all(thread=False)
    try:
        launcher = resolve_launcher(proxy_ref)
    except (ImportError, AttributeError, ValueError) as e:
        print(f'Unable to load proxy {proxy_ref!r}: {e}', file=sys.stderr)
        return 2
    return launch(launcher, argv)
