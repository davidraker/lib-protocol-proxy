import logging
import sys

from argparse import ArgumentParser, ArgumentTypeError
from asyncio import iscoroutinefunction, run
from importlib import import_module
from typing import Callable
from uuid import UUID

from ..ipc import SocketParams
from ..logs import JsonLineFormatter, configure_logging    # noqa: F401  (re-exported; tests patch configure_logging)
from ..tls import TlsMaterial

_log = logging.getLogger(__name__)

TOKEN_HEX_LENGTH = 32


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
                        help='Encrypt every frame to and from the manager (ChaCha20-Poly1305) with the key the manager'
                             ' writes to stdin after the tokens. The manager passes the policy it applies itself.')
    parser.add_argument('--inbound-address', type=str, default='localhost',
                        help='Address of the inbound socket from the Proxy Manager')
    parser.add_argument('--inbound-port', type=int, default=None,
                        help='Port of the inbound socket from the Proxy Manager. Chosen automatically if omitted.')
    parser.add_argument('--ipc-tls', type=str2bool, default=False,
                        help='Every IPC connection with the manager is TLS, with the certificate, key and CA the manager'
                             ' writes to stdin after the tokens (and key). Both ends verify each other.')
    parser.add_argument('--manager-dials', type=str2bool, default=False,
                        help='Do not dial the manager: wait for it to connect to this proxy\'s listener (--inbound-port)'
                             ' and register over that connection. For a proxy that cannot reach the manager\'s address.')
    parser.add_argument('--persistent', type=str2bool, default=False,
                        help='Keep one connection open to the manager for every frame in both directions, instead of a'
                             ' connection per message. The manager passes the same policy it applies to this proxy.')
    parser.add_argument('--compress-threshold', type=int, default=None,
                        help='Compress payloads larger than this many bytes toward a peer that accepts compression'
                             ' (default 4096; 0 compresses everything).')
    parser.add_argument('--socket-logging', type=str2bool, default=True,
                        help='After registering, ship log records to the manager in LOG batches over the IPC socket'
                             ' instead of stderr (stderr still carries everything before registration and at exit).')
    parser.add_argument('--log-level', type=str, default=None,
                        help='Logging level for the proxy process (default: PROTOCOL_PROXY_LOG_LEVEL or INFO). A manager passes'
                             ' the effective level of its protocol_proxy.proxies.<Class>.<name> logger.')
    return parser


KEY_HEX_LENGTH = 64


def _read_tokens(encrypt: bool = False, ipc_tls: bool = False) -> tuple:
    """The manager writes the proxy token followed by its own token, as hex, to the proxy's stdin, after them the
    32-byte AEAD key (hex) when the proxy is launched with ``--encrypt``, and then one JSON line of TLS material
    (``{"ca", "cert", "key"}`` PEM) when launched with ``--ipc-tls``. Nothing secret is on the command line.
    Returns ``(proxy_token, manager_token, key, tls_material)``."""
    data = sys.stdin.buffer.read(2 * TOKEN_HEX_LENGTH)
    if len(data) != 2 * TOKEN_HEX_LENGTH:
        raise ValueError(f'Expected {2 * TOKEN_HEX_LENGTH} hex characters (proxy token + manager token) on stdin,'
                         f' got {len(data)} bytes. Proxies are meant to be launched by a ProtocolProxyManager.')
    tokens = UUID(hex=data[:TOKEN_HEX_LENGTH].decode('utf8')), UUID(hex=data[TOKEN_HEX_LENGTH:].decode('utf8'))
    key = None
    if encrypt:
        key_hex = sys.stdin.buffer.read(KEY_HEX_LENGTH)
        if len(key_hex) != KEY_HEX_LENGTH:
            raise ValueError(f'--encrypt is set but no {KEY_HEX_LENGTH // 2}-byte key followed the tokens on stdin'
                             f' (got {len(key_hex)} bytes).')
        key = bytes.fromhex(key_hex.decode('utf8'))
    material = None
    if ipc_tls:
        line = sys.stdin.buffer.readline()
        if not line.strip():
            raise ValueError('--ipc-tls is set but no TLS material (one JSON line) followed on stdin.')
        material = TlsMaterial.from_line(line)
    return *tokens, key, material


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
    if opts.get('compress_threshold') is None:
        opts.pop('compress_threshold', None)        # the connector's default applies
    opts['inbound_params'] = SocketParams(inbound_address, inbound_port) if inbound_port else None
    _log.info(f'Launching Proxy with parameters: {redact(opts)}')
    try:
        proxy_token, manager_token, key, material = _read_tokens(bool(opts.get('encrypt')), bool(opts.pop('ipc_tls', False)))
        if iscoroutinefunction(proxy_runner):
            result = run(proxy_runner(token=proxy_token, manager_token=manager_token, key=key, ipc_tls=material, **opts))
        else:
            result = proxy_runner(token=proxy_token, manager_token=manager_token, key=key, ipc_tls=material, **opts)
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
