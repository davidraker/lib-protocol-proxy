"""Launching a proxy through an SSH prefix: the same command, stdin and pipes, wrapped in ssh. Tested with a stub ssh
on PATH that drops the ssh arguments and runs the remote command locally (no sshd is needed)."""
import json
import os
import stat
import sys
import time
from pathlib import Path

import gevent
import pytest
from gevent import sleep, spawn

from protocol_proxy.ipc import SocketParams
from protocol_proxy.manager.gevent import GeventProtocolProxyManager
from test_manager import DummyProxy

STUB_SSH = '''#!/bin/sh
# A stand-in for ssh: skip options (-o X, -R X, -L X, -p X, -i X) and the host, then run the remote command here.
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-R|-L|-p|-i) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
shift   # the host
echo "stub-ssh ran: $*" >&2
exec "$@"
'''


def test_command_is_wrapped_in_ssh_with_the_reverse_forward_and_marker():
    manager = GeventProtocolProxyManager(proxy_class=DummyProxy)
    manager.inbound_params = SocketParams('10.1.1.1', 22850)
    command, *_ = manager._setup_proxy_process_command(('dummy', 'edge'), ssh_host='pi@edge-1', host='h',
                                                       ssh_options=['-i', '/keys/edge'], remote_python='/opt/venv/bin/python',
                                                       remote_env={'PYTHONPATH': '/opt/proxies'})
    assert command[:11] == ['ssh', '-o', 'BatchMode=yes', '-R', '22850:127.0.0.1:22850', '-i', '/keys/edge', 'pi@edge-1',
                            'env', '_LAUNCHED_BY_PROXY_MANAGER=1', 'PYTHONPATH=/opt/proxies']
    assert command[11:14] == ['/opt/venv/bin/python', '-m', 'protocol_proxy.proxy']
    assert command[command.index('--manager-address') + 1] == '127.0.0.1'          # the forwarded port on the remote
    assert command[command.index('--manager-port') + 1] == '22850'
    for option in ('--ssh-host', '--ssh-options', '--remote-python', '--remote-env', '--ssh-forward'):
        assert option not in command
    assert command[command.index('--host') + 1] == 'h'                                 # protocol options still travel
    plain, *_ = manager._setup_proxy_process_command(('dummy', 'local'))
    assert plain[0] == sys.executable and 'ssh' not in plain
    direct, *_ = manager._setup_proxy_process_command(('dummy', 'direct'), ssh_host='edge-2', ssh_forward=False,
                                                      manager_address='10.1.1.1')
    assert '-R' not in direct and direct[direct.index('--manager-address') + 1] == '10.1.1.1'


def _wait(predicate, timeout=20, what='condition'):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, f'timed out waiting for {what}'
        sleep(0.05)


def test_real_proxy_launched_through_the_ssh_prefix(tmp_path, monkeypatch):
    stub = tmp_path / 'ssh'
    stub.write_text(STUB_SSH)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv('PATH', f'{tmp_path}{os.pathsep}{os.environ["PATH"]}')
    tests_dir = str(Path(__file__).resolve().parent)
    import dummy_proxies as dummies
    manager = GeventProtocolProxyManager(proxy_class=dummies.AsyncioDummy, heartbeat_interval=0.3)
    manager.start()
    loop = spawn(manager.select_loop)
    records = []

    class Collect:
        def emit(self, record): records.append(record)
        handle = emit
        level = 0
        def __init__(self): pass
    import logging
    handler = logging.Handler(); handler.emit = lambda record: records.append(record)
    logger = logging.getLogger('protocol_proxy.proxies'); logger.addHandler(handler); logger.setLevel(logging.INFO)
    peer = None
    try:
        peer = manager.get_proxy(('dummy', 'edge'), ssh_host='edge-1', remote_python=sys.executable,
                                 remote_env={'PYTHONPATH': tests_dir}, encrypt=True)
        manager.wait_peer_registered(peer, 25)
        assert peer.socket_params is not None, 'the proxy launched over the ssh stub did not register'
        _wait(lambda: peer.state == 'healthy', what='a heartbeat reply through the ssh-launched proxy')
        # The stub announced itself on the pipe, which the manager read like any plain stderr line, and the proxy's
        # own records arrive over the socket (before the level is raised, which would gate the INFO ones).
        _wait(lambda: any('stub-ssh ran:' in r.getMessage() and r.channel == 'stderr' for r in records),
              what=f'the stub line on the stderr pipe (got {[r.getMessage()[:40] for r in records]})')
        _wait(lambda: any(r.channel == 'socket' for r in records), what='the proxy\'s own logs over the socket')
        assert json.loads(manager.set_proxy_log_level(peer, 'WARNING').get(timeout=5)) == {'level': 'WARNING'}
        manager._cleanup_proxy_process(peer.process)
        assert peer.process.returncode == 0
    finally:
        logger.removeHandler(handler); logger.setLevel(logging.NOTSET)
        if peer is not None and peer.process is not None and peer.process.poll() is None:
            peer.process.kill()
        if manager._heartbeat is not None:
            manager._heartbeat.kill()
        manager.stop()
        gevent.joinall([loop], timeout=2)
