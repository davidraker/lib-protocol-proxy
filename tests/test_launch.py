import asyncio
import io
import sys
import json
import logging
from unittest import mock
from uuid import uuid4

import pytest

from protocol_proxy.ipc import SocketParams
from protocol_proxy.manager.base import ProtocolProxyManager
import importlib

launch_module = importlib.import_module('protocol_proxy.proxy.launch')
from protocol_proxy.proxy.launch import (JsonLineFormatter, _read_tokens, default_launcher, launch, main,
                                         proxy_command_parser, resolve_launcher, str2bool)


def test_str2bool():
    assert str2bool('True') and str2bool('yes') and str2bool('1') and str2bool(True)
    assert not str2bool('False') and not str2bool('off') and not str2bool('') and not str2bool(False)
    with pytest.raises(Exception):
        str2bool('maybe')


def test_json_formatter_roundtrips_quotes_through_manager_parser(caplog):
    record = logging.LogRecord('some.proxy', logging.WARNING, __file__, 12, 'Namespace(name="x", y=\'z\')', None, None)
    line = JsonLineFormatter().format(record)
    parsed = json.loads(line)
    assert parsed == {'name': 'some.proxy', 'lineno': 12, 'level': 'WARNING', 'message': 'Namespace(name="x", y=\'z\')'}
    with caplog.at_level(logging.DEBUG):
        ProtocolProxyManager.log_subprocess_output_line(line.encode('utf8'))
    assert caplog.records[-1].name == 'some.proxy'
    assert caplog.records[-1].levelno == logging.WARNING
    assert 'Namespace(name="x"' in caplog.records[-1].getMessage()


def test_read_tokens():
    a, b = uuid4(), uuid4()
    with mock.patch.object(launch_module.sys, 'stdin', mock.Mock(buffer=io.BytesIO((a.hex + b.hex).encode()))):
        assert _read_tokens() == (a, b)
    with mock.patch.object(launch_module.sys, 'stdin', mock.Mock(buffer=io.BytesIO(b'short'))):
        with pytest.raises(ValueError):
            _read_tokens()


def test_parser_defaults_and_bool_handling():
    opts = proxy_command_parser().parse_args(['--proxy-id', uuid4().hex, '--proxy-name', 'n',
                                              '--manager-id', uuid4().hex, '--encrypt', 'False'])
    assert opts.encrypt is False and opts.inbound_port is None


def _launch_with(argv, runner, stdin=None):
    a, b = uuid4(), uuid4()
    stdin = stdin if stdin is not None else io.BytesIO((a.hex + b.hex).encode())
    with mock.patch.object(launch_module.sys, 'argv', ['prog'] + argv), \
         mock.patch.object(launch_module.sys, 'stdin', mock.Mock(buffer=stdin)), \
         mock.patch.object(launch_module, 'configure_logging'):
        return launch(lambda parser: (parser, runner)), a, b


BASE_ARGS = ['--proxy-id', uuid4().hex, '--proxy-name', 'n', '--manager-id', uuid4().hex]


def test_launch_passes_tokens_and_inbound_params_and_exit_codes():
    seen = {}

    def runner(**kwargs):
        seen.update(kwargs)
        return 0
    code, a, b = _launch_with(BASE_ARGS + ['--inbound-port', '5000', '--inbound-address', '10.0.0.1'], runner)
    assert code == 0 and seen['token'] == a and seen['manager_token'] == b
    assert seen['inbound_params'] == SocketParams('10.0.0.1', 5000)
    assert 'inbound_address' not in seen and 'log_level' not in seen

    code, *_ = _launch_with(BASE_ARGS, lambda **kw: 3)
    assert code == 3

    def failing(**kwargs):
        raise RuntimeError('boom')
    code, *_ = _launch_with(BASE_ARGS, failing)
    assert code == 1

    async def async_runner(**kwargs):
        seen['async'] = kwargs['inbound_params']
        return 0
    code, *_ = _launch_with(BASE_ARGS, async_runner)
    assert code == 0 and seen['async'] is None


def test_launch_help_exits_via_system_exit():
    with pytest.raises(SystemExit) as exc:
        _launch_with(['--help'], lambda **kw: 0)
    assert exc.value.code == 0


def test_launch_missing_tokens_is_an_error():
    code, *_ = _launch_with(BASE_ARGS, lambda **kw: 0, stdin=io.BytesIO(b''))
    assert code == 1


def test_redact_masks_credentials_only():
    from protocol_proxy.proxy.launch import redact
    assert redact({'host': 'h', 'password': 'p', 'nats_token': 't', 'manager_token': None, 'tls': False}) == \
        {'host': 'h', 'password': '***', 'nats_token': '***', 'manager_token': None, 'tls': False}



class _NoOptionsProxy:
    """Stands in for a proxy class without a LAUNCHER (e.g., ModbusProxy)."""
    LAUNCHER = None
    created = []

    def __init__(self, **options):
        self.options = options
        _NoOptionsProxy.created.append(self)

    async def start(self):
        self.started = True


class _OptionsProxy:
    LAUNCHER = 'launch_with_options'


def launch_with_options(parser):
    parser.add_argument('--flavour', default='plain')
    return parser, lambda **options: 0


def test_resolve_launcher_uses_default_when_no_launcher_declared():
    launcher = resolve_launcher(f'{__name__}:_NoOptionsProxy')
    parser, runner = launcher(proxy_command_parser())
    assert vars(parser.parse_args(BASE_ARGS)).keys() >= {'proxy_id', 'manager_id'}
    assert asyncio.run(runner(token='t', manager_token='m')) == 0
    proxy = _NoOptionsProxy.created[-1]
    assert proxy.options == {'token': 't', 'manager_token': 'm'} and proxy.started


def test_resolve_launcher_uses_declared_module_function():
    assert resolve_launcher(f'{__name__}:_OptionsProxy') is launch_with_options


@pytest.mark.parametrize('ref, message', [
    ('nomodule', 'must be <module>:<ProxyClass>'),
    (f'{__name__}:Nope', "has no attribute 'Nope'"),
    ('protocol_proxy.no_such_module:X', 'No module named'),
])
def test_resolve_launcher_errors(ref, message):
    with pytest.raises((ValueError, AttributeError, ImportError), match=message):
        resolve_launcher(ref)


def test_main_requires_proxy_reference(capsys):
    assert main([]) == 2 and main(['--proxy-id', 'x']) == 2
    assert 'usage:' in capsys.readouterr().err
    assert main([f'{__name__}:Nope'] + BASE_ARGS) == 2


def test_main_launches_default_proxy_with_tokens():
    a, b = uuid4(), uuid4()
    with mock.patch.object(launch_module.sys, 'stdin', mock.Mock(buffer=io.BytesIO((a.hex + b.hex).encode()))), \
         mock.patch.object(launch_module, 'configure_logging'):
        assert main([f'{__name__}:_NoOptionsProxy'] + BASE_ARGS + ['--inbound-port', '7']) == 0
    proxy = _NoOptionsProxy.created[-1]
    assert proxy.options['token'] == a and proxy.options['manager_token'] == b
    assert proxy.options['inbound_params'] == SocketParams('localhost', 7)


def test_main_gevent_flag_patches_before_import(monkeypatch):
    patched = []
    fake_monkey = mock.Mock(patch_all=lambda **kw: patched.append(kw))
    monkeypatch.setitem(sys.modules, 'gevent', mock.Mock(monkey=fake_monkey))
    monkeypatch.setitem(sys.modules, 'gevent.monkey', fake_monkey)
    order = []
    with mock.patch.object(launch_module, 'resolve_launcher', side_effect=lambda ref: order.append(('resolve', ref)) or (lambda p: (p, lambda **o: 0))), \
         mock.patch.object(launch_module, 'launch', return_value=0):
        assert main(['--gevent', 'm:C', '--x']) == 0
    assert patched == [{'thread': False}] and order == [('resolve', 'm:C')]
