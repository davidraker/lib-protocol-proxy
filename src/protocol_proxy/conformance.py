"""Conformance checks for a proxy executable: does it speak the protocol in PROTOCOL.md toward this Python manager?

The proxy under test is whatever a manifest launches (:mod:`protocol_proxy.manifest`), in any language. Each check
launches it through a real :class:`GeventProtocolProxyManager` with one combination of options and exercises the core
contract: registration with its feature list, PING, the error reply for an unknown method, SET_LOG_LEVEL when
advertised, header version 1, per-message and persistent connections, encryption with each AEAD the proxy advertises,
optionally TLS and manager-initiated registration, and a clean exit on SIGTERM. An ``echo`` method, if the proxy has
one, is used to round-trip payloads large enough to be compressed.

Run it from the command line (``protocol-proxy-conformance``) against a manifest file or a proxy name, or call
:func:`run` from a test. A port is expected to pass every check that is not skipped; a skipped check names what the
proxy did not advertise or the option that was not requested.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import gevent

from .ipc import ProtocolProxyMessage, ProtocolProxyPeer
from .manager.gevent import GeventProtocolProxyManager
from .manifest import Manifest, find

_log = logging.getLogger(__name__)


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ''
    skipped: bool = False

    @property
    def status(self) -> str:
        return 'skip' if self.skipped else ('pass' if self.passed else 'FAIL')


@dataclass
class Report:
    manifest: Manifest
    checks: list[Check] = field(default_factory=list)
    features: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return all(c.passed or c.skipped for c in self.checks)

    def add(self, name: str, passed: bool, detail: str = '') -> Check:
        self.checks.append(c := Check(name, passed, detail))
        return c

    def skip(self, name: str, detail: str) -> Check:
        self.checks.append(c := Check(name, True, detail, skipped=True))
        return c

    def text(self) -> str:
        width = max((len(c.name) for c in self.checks), default=10)
        lines = [f'{self.manifest.name}: {"all checks pass" if self.ok else "FAILURES"}'
                 f' ({sum(1 for c in self.checks if c.passed and not c.skipped)} passed,'
                 f' {sum(1 for c in self.checks if not c.passed)} failed, {sum(1 for c in self.checks if c.skipped)} skipped)']
        lines += [f'  {c.status:4} {c.name:{width}}  {c.detail}' for c in self.checks]
        return '\n'.join(lines)

    def as_dict(self) -> dict:
        return {'proxy': self.manifest.name, 'ok': self.ok, 'features': list(self.features),
                'checks': [{'name': c.name, 'status': c.status, 'detail': c.detail} for c in self.checks]}


class Session:
    """One launched proxy under one manager configuration."""

    def __init__(self, manifest: Manifest, manager_options: dict, launch_options: dict, timeout: float):
        self.manager = GeventProtocolProxyManager(manifest=manifest, heartbeat_interval=0, **manager_options)
        self.launch_options = launch_options
        self.timeout = timeout
        self.peer: ProtocolProxyPeer | None = None
        self._loop = None

    def __enter__(self) -> 'Session':
        self.manager.start()
        self._loop = gevent.spawn(self.manager.select_loop)
        self.peer = self.manager.get_proxy(('conformance',), **self.launch_options)
        self.manager.wait_peer_registered(self.peer, self.timeout)
        return self

    @property
    def registered(self) -> bool:
        return self.peer is not None and self.peer.state != 'launching' and self.peer.features != () or (
            self.peer is not None and self.peer.socket_params is not None)

    def request(self, method: str, payload: bytes = b'', timeout: float | None = None, **message_fields) -> bytes:
        """Send a request and return the raw reply (bytes)."""
        result = self.manager.send(self.peer, ProtocolProxyMessage(method_name=method, payload=payload,
                                                                   response_expected=True, **message_fields))
        return result.get(timeout=timeout or self.timeout)

    def request_json(self, method: str, body: Any = None, **kw) -> Any:
        reply = self.request(method, json.dumps(body).encode() if body is not None else b'', **kw)
        return json.loads(reply.decode('utf8')) if reply else None

    def exit_code(self, timeout: float = 10.0) -> int | None:
        """Stop the manager (SIGTERM to the proxy) and return the proxy's exit code, None if it did not exit."""
        process = self.peer.process if self.peer is not None else None
        self.manager.stop()
        if self._loop is not None:
            gevent.joinall([self._loop], timeout=2)
        if process is None:
            return None
        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            gevent.sleep(0.05)
        if process.poll() is None:
            process.kill()
            return None
        return process.returncode

    def __exit__(self, *exc):
        if self.peer is not None and self.peer.process is not None and self.peer.process.poll() is None:
            try:
                self.manager.stop()
            finally:
                if self.peer.process.poll() is None:
                    gevent.sleep(1)
                if self.peer.process.poll() is None:
                    self.peer.process.kill()
        if self._loop is not None:
            self._loop.kill(block=False)


def run(manifest: Manifest, *, launch_options: dict | None = None, echo_method: str | None = None,
        tls: bool = False, manager_dials: bool = False, timeout: float = 20.0) -> Report:
    """Run every check against the proxy the manifest launches and return the report."""
    launch_options = dict(launch_options or {})
    report = Report(manifest)

    def session(name: str, manager_options: dict | None = None, **launch) -> Iterator[Session | None]:
        """Yield a registered session or record the failure and yield None."""
        try:
            with Session(manifest, manager_options or {}, {**launch_options, **launch}, timeout) as s:
                if s.peer.socket_params is None and not launch.get('manager_dials'):
                    report.add(f'{name}: registration', False, f'no registration within {timeout}s')
                    yield None
                    return
                report.add(f'{name}: registration', True, f'features {list(s.peer.features)}')
                yield s
        except Exception as e:                                           # a launch or registration failure
            report.add(f'{name}: registration', False, f'{type(e).__name__}: {e}')
            yield None

    # ---- 1. per-message connections: the core contract ------------------------------------------------------------
    for s in session('per-message', persistent=False):
        if s is None:
            break
        report.features = tuple(s.peer.features)
        try:
            health = s.request_json('PING')
            ok = isinstance(health, dict) and isinstance(health.get('uptime'), (int, float)) \
                and isinstance(health.get('remotes'), int) and isinstance(health.get('busy'), bool) \
                and 'last_activity' in health
            report.add('ping reply', ok, f'{health}')
        except Exception as e:
            report.add('ping reply', False, f'{type(e).__name__}: {e}')
        try:
            reply = s.request_json('NO_SUCH_METHOD_CONFORMANCE', {'x': 1})
            ok = isinstance(reply, dict) and reply.get('status') == 'error' and 'method' in reply and 'error' in reply
            report.add('unknown method answered with an error reply', ok, f'{reply}')
        except Exception as e:
            report.add('unknown method answered with an error reply', False, f'{type(e).__name__}: {e}')
        if 'set_log_level' in s.peer.features:
            try:
                reply = s.request_json('SET_LOG_LEVEL', {'level': 'DEBUG'})
                report.add('SET_LOG_LEVEL', isinstance(reply, dict) and reply.get('level') == 'DEBUG', f'{reply}')
                s.request_json('SET_LOG_LEVEL', {'level': 'INFO'})
            except Exception as e:
                report.add('SET_LOG_LEVEL', False, f'{type(e).__name__}: {e}')
        else:
            report.skip('SET_LOG_LEVEL', 'not advertised')
        try:
            health = s.request_json('PING', protocol_version=1)
            report.add('header version 1 accepted', isinstance(health, dict) and 'uptime' in health, f'{health}')
        except Exception as e:
            report.add('header version 1 accepted', False, f'{type(e).__name__}: {e}')
        if echo_method:
            try:
                small = json.dumps({'n': 1, 'text': 'héllo'}).encode()
                assert s.request(echo_method, small) == small
                large = json.dumps({'blob': 'x' * 65536}).encode()         # above the compression threshold
                assert s.request(echo_method, large) == large
                via = 'compressed on the wire' if 'compress' in s.peer.features else 'uncompressed (compress not advertised)'
                report.add('echo round trip, small and 64 KiB', True, via)
            except Exception as e:
                report.add('echo round trip, small and 64 KiB', False, f'{type(e).__name__}: {e}')
        else:
            report.skip('echo round trip, small and 64 KiB', 'no echo method given')
        code = s.exit_code()
        report.add('clean exit on SIGTERM', code == 0, f'exit code {code}')

    # ---- 2. persistent connection --------------------------------------------------------------------------------
    for s in session('persistent', persistent=True):
        if s is None:
            break
        try:
            replies = [s.request_json('PING') for _ in range(5)]
            ok = all(isinstance(r, dict) and 'uptime' in r for r in replies) and s.peer.connection is not None
            report.add('persistent: five pings on one connection', ok, 'connection held' if ok else f'{replies[-1]!r}')
        except Exception as e:
            report.add('persistent: five pings on one connection', False, f'{type(e).__name__}: {e}')
        if echo_method:
            try:
                large = json.dumps({'blob': 'y' * 300000}).encode()        # above persistent_max_frame: own connection
                assert s.request(echo_method, large) == large
                report.add('persistent: 300 KB frame takes its own connection', True, '')
            except Exception as e:
                report.add('persistent: 300 KB frame takes its own connection', False, f'{type(e).__name__}: {e}')
        code = s.exit_code()
        report.add('persistent: clean exit on SIGTERM', code == 0, f'exit code {code}')

    # ---- 3. encryption, each AEAD the proxy advertises -------------------------------------------------------------
    advertised = report.features
    for cipher, feature in (('chacha20-poly1305', 'aead-chacha20poly1305'), ('aes-256-gcm', 'aead-aes256gcm')):
        if feature not in advertised:
            report.skip(f'encrypted ({cipher})', f'{feature} not advertised')
            continue
        for s in session(f'encrypted ({cipher})', {'encrypt': True, 'cipher': cipher}, persistent=True):
            if s is None:
                break
            try:
                health = s.request_json('PING')
                ok = isinstance(health, dict) and 'uptime' in health and s.peer.key is not None
                report.add(f'encrypted ({cipher}): ping', ok, f'{health}')
                if echo_method:
                    large = json.dumps({'blob': 'z' * 65536}).encode()
                    report.add(f'encrypted ({cipher}): 64 KiB echo (compress then encrypt)', s.request(echo_method, large) == large, '')
            except Exception as e:
                report.add(f'encrypted ({cipher}): ping', False, f'{type(e).__name__}: {e}')
            code = s.exit_code()
            report.add(f'encrypted ({cipher}): clean exit', code == 0, f'exit code {code}')

    # ---- 4. optional transports ----------------------------------------------------------------------------------
    if tls:
        for s in session('tls', {'ipc_tls': True}, persistent=True):
            if s is None:
                break
            try:
                health = s.request_json('PING')
                report.add('tls: ping', isinstance(health, dict) and 'uptime' in health and s.peer.tls, f'{health}')
            except Exception as e:
                report.add('tls: ping', False, f'{type(e).__name__}: {e}')
            code = s.exit_code()
            report.add('tls: clean exit', code == 0, f'exit code {code}')
    else:
        report.skip('tls', 'not requested (--tls)')
    if manager_dials:
        port = _free_port()
        for s in session('manager-dials', {}, manager_dials=True, inbound_address='127.0.0.1', inbound_port=port):
            if s is None:
                break
            try:
                health = s.request_json('PING')
                report.add('manager-dials: ping over the manager-initiated connection', isinstance(health, dict) and 'uptime' in health, f'{health}')
            except Exception as e:
                report.add('manager-dials: ping over the manager-initiated connection', False, f'{type(e).__name__}: {e}')
            code = s.exit_code()
            report.add('manager-dials: clean exit', code == 0, f'exit code {code}')
    else:
        report.skip('manager-dials', 'not requested (--manager-dials)')
    return report


def _free_port() -> int:
    import socket
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    """``protocol-proxy-conformance <manifest.toml | proxy name> [--echo METHOD] [--tls] [--manager-dials]
    [--option name=value ...] [--timeout S] [--json]``: exit 0 when every check passes or is skipped."""
    import argparse
    parser = argparse.ArgumentParser(prog='protocol-proxy-conformance', description=main.__doc__)
    parser.add_argument('proxy', help='a manifest file, or a proxy name found through the manifest search path')
    parser.add_argument('--echo', metavar='METHOD', help='a method of the proxy that replies with its payload')
    parser.add_argument('--tls', action='store_true', help='also launch with TLS material (--ipc-tls)')
    parser.add_argument('--manager-dials', action='store_true', help='also launch with manager-initiated registration')
    parser.add_argument('--option', action='append', default=[], metavar='NAME=VALUE', help='a launch option for the proxy')
    parser.add_argument('--timeout', type=float, default=20.0, help='seconds to wait for registration and replies')
    parser.add_argument('--json', action='store_true', help='machine-readable report')
    parser.add_argument('-v', '--verbose', action='store_true', help='show the manager and proxy logs')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stderr,
                        format='%(asctime)s %(name)s %(levelname)s: %(message)s')
    manifest = Manifest.load(args.proxy) if Path(args.proxy).suffix == '.toml' or os.sep in args.proxy else find(args.proxy)
    options = dict(item.split('=', 1) for item in args.option)
    report = run(manifest, launch_options=options, echo_method=args.echo, tls=args.tls,
                 manager_dials=args.manager_dials, timeout=args.timeout)
    print(json.dumps(report.as_dict(), indent=1) if args.json else report.text())
    return 0 if report.ok else 1


if __name__ == '__main__':
    sys.exit(main())
