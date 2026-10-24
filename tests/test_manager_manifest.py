"""Managers built from manifests: the launch command, process keys, must_match and discovery by name."""
import os
import sys

import pytest

from protocol_proxy.ipc import SocketParams
from protocol_proxy.manager.gevent import GeventProtocolProxyManager
from protocol_proxy.manifest import ENV_MANIFEST_PATH, Manifest
from dummy_proxies import AsyncioDummy, GeventDummy

LISTEN = SocketParams('127.0.0.1', 22801)     # the command names the manager's listener; none is started here


@pytest.fixture(autouse=True)
def fresh_managers():
    GeventProtocolProxyManager.managers.clear()
    yield
    GeventProtocolProxyManager.managers.clear()


def test_manager_from_a_class_builds_the_same_command_as_before():
    manager = GeventProtocolProxyManager(proxy_class=GeventDummy)
    manager.inbound_params = LISTEN
    command, proxy_id, name = manager._setup_proxy_process_command(('dummy_x',))
    assert command[:4] == [sys.executable, '-m', 'protocol_proxy.proxy', '--gevent']
    assert command[4] == 'dummy_proxies:GeventDummy' and command[5:7] == ['--proxy-id', proxy_id.hex]
    assert name == "('dummy_x',)" and manager.manifest.name == 'GeventDummy'


def test_manager_from_a_manifest_file_by_name(tmp_path, monkeypatch):
    (tmp_path / 'echo.toml').write_text(
        '[proxy]\nname = "echo"\ncommand = ["{python}", "-m", "protocol_proxy.proxy", "dummy_proxies:AsyncioDummy"]\n'
        '[identity]\nkeys = ["host", "port"]\nmust_match = ["user"]\n[identity.normalize]\nhost = ["lowercase"]\n'
        'port = [{ default = 7 }]\n[environment]\nECHO_MODE = "loud"\n')
    monkeypatch.setenv(ENV_MANIFEST_PATH, str(tmp_path))
    manager = GeventProtocolProxyManager.get_manager('echo')
    manager.inbound_params = LISTEN
    assert manager is GeventProtocolProxyManager.get_manager('echo')          # one manager per manifest name
    assert manager.manifest.source == tmp_path / 'echo.toml'
    command, pid_a, name = manager._setup_proxy_process_command(('whatever',), host='Broker', user='u')
    assert command[0] == sys.executable and command[3] == 'dummy_proxies:AsyncioDummy'
    pairs = list(zip(command, command[1:]))
    assert ('--host', 'Broker') in pairs and ('--user', 'u') in pairs       # launch options still travel unchanged
    assert name == "('echo', 'broker', 7)"
    # Same broker spelled differently and the same user: the same process, so no new command.
    command2, pid_b, _ = manager._setup_proxy_process_command(('other',), host='broker', port=7, user='u')
    assert pid_b == pid_a and command2[:4] == command[:4]     # same process id; the peer is not registered here, so a command again
    assert manager.proxy_environment()['ECHO_MODE'] == 'loud'


def test_must_match_refuses_a_remote_that_would_share_wrongly(tmp_path, monkeypatch):
    (tmp_path / 'echo.toml').write_text(
        '[proxy]\nname = "echo"\ncommand = ["{python}", "-m", "protocol_proxy.proxy", "dummy_proxies:AsyncioDummy"]\n'
        '[identity]\nkeys = ["host"]\nmust_match = ["user", "password"]\n')
    monkeypatch.setenv(ENV_MANIFEST_PATH, str(tmp_path))
    manager = GeventProtocolProxyManager.get_manager('echo')
    manager.inbound_params = LISTEN
    manager._setup_proxy_process_command(('a',), host='b', user='alice', password='s')
    with pytest.raises(ValueError, match='differs in user'):
        manager._setup_proxy_process_command(('a',), host='b', user='bob', password='s')
    manager._setup_proxy_process_command(('a',), host='c', user='bob', password='s')   # another process: fine


def test_unknown_name_is_a_lookup_error(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_MANIFEST_PATH, str(tmp_path))
    with pytest.raises(LookupError, match='looked at'):
        GeventProtocolProxyManager.get_manager('no-such-proxy')
