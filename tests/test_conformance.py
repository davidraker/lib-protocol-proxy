"""The conformance harness against the Python proxies: the test dummies with an echo method, and the installed
protocol proxies that start without launch options."""
import os
from pathlib import Path

import pytest

from protocol_proxy.conformance import run
from protocol_proxy.manifest import Manifest, discover
import dummy_proxies as dummies


@pytest.fixture(autouse=True)
def tests_on_path(monkeypatch):
    tests_dir = str(Path(__file__).resolve().parent)
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(filter(None, [tests_dir, os.environ.get('PYTHONPATH')])))


@pytest.mark.parametrize('proxy_class', [dummies.AsyncioDummy, dummies.GeventDummy])
def test_dummies_pass_every_check(proxy_class):
    report = run(Manifest.for_proxy_class(proxy_class), echo_method='ECHO', tls=True, manager_dials=True, timeout=20)
    assert report.ok, report.text()
    assert not any(c.skipped and 'not requested' in c.detail for c in report.checks)
    assert any(c.name.startswith('encrypted (aes-256-gcm)') for c in report.checks), report.text()


STANDALONE = ('dnp3', 'ieee2030_5', 'modbus')      # proxies whose process starts with no protocol-specific options


@pytest.mark.parametrize('name', STANDALONE)
def test_installed_python_proxies_pass_the_core_checks(name):
    manifests = discover()
    if name not in manifests:
        pytest.skip(f'{name} proxy not installed here')
    report = run(manifests[name], tls=True, timeout=30)
    assert report.ok, report.text()
