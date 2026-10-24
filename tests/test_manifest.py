"""Proxy manifests: parsing, identity rules, discovery, and the launch command they produce."""
import os
import textwrap

import pytest

from protocol_proxy.manifest import (ENV_MANIFEST_PATH, Identity, Manifest, ManifestError, discover, find, locate,
                                     search_path)
from dummy_proxies import AsyncioDummy, GeventDummy

MQTT = textwrap.dedent('''
    [proxy]
    name = "mqtt"
    command = ["{python}", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy"]

    [identity]
    keys = ["host", "port"]
    must_match = ["username", "password"]

    [identity.normalize]
    host = ["strip", "lowercase"]
    port = [{ default = 1883 }]

    [environment]
    MQTT_LOG = "info"
''')
SINGLETON = textwrap.dedent('''
    [proxy]
    name = "dnp3"
    command = ["{python}", "-m", "protocol_proxy.proxy", "protocol_proxy.protocol.dnp3.dnp3_proxy:Dnp3Proxy"]
''')


def test_parses_every_section():
    m = Manifest.from_toml(MQTT)
    assert m.name == 'mqtt' and m.header_version == 2 and m.self_test is None
    assert m.command[0] == '{python}' and m.command[-1].endswith(':MQTTProxy')
    assert m.identity.keys == ('host', 'port') and m.identity.must_match == ('username', 'password')
    assert m.environment == {'MQTT_LOG': 'info'}


def test_identity_from_launch_options_is_normalised():
    m = Manifest.from_toml(MQTT)
    a = m.process_key(('ignored',), {'host': ' Broker.Example ', 'port': 1883})
    b = m.process_key(('other',), {'host': 'broker.example'})            # port takes the default
    assert a == b == ('mqtt', 'broker.example', 1883)
    assert m.process_key((), {'host': 'broker.example', 'port': 8883}) != a


def test_singleton_identity_is_the_callers_key_as_given():
    m = Manifest.from_toml(SINGLETON)
    assert m.identity.keys == ()
    assert m.process_key(('dnp3',), {'anything': 1}) == ('dnp3',)
    assert m.process_key(('dnp3', 'site-b'), {}) == ('dnp3', 'site-b')


def test_must_match_detects_a_remote_that_would_share_wrongly():
    ident = Manifest.from_toml(MQTT).identity
    first = {'host': 'b', 'username': 'alice', 'password': 's3'}
    assert ident.conflicts(first, {'host': 'b', 'username': 'alice', 'password': 's3'}) == []
    assert ident.conflicts(first, {'host': 'b', 'username': 'bob', 'password': 's3'}) == ['username']
    assert ident.conflicts(first, {'host': 'b'}) == ['username', 'password']


def test_launch_command_resolves_placeholders_and_appends_standard_options(tmp_path):
    path = tmp_path / 'mqtt.toml'
    path.write_text(MQTT)
    m = Manifest.load(path)
    argv = m.launch_command('/venv/bin/python', ['--proxy-id', 'abc'])
    assert argv[:4] == ['/venv/bin/python', '-m', 'protocol_proxy.proxy', '--gevent'] and argv[-2:] == ['--proxy-id', 'abc']
    dir_cmd = Manifest.from_dict({'proxy': {'name': 'x', 'command': ['{manifest_dir}/bin/x']}}, source=path)
    assert dir_cmd.launch_command('py') == [f'{tmp_path}/bin/x']


def test_for_proxy_class_mirrors_the_python_entry_point():
    g = Manifest.for_proxy_class(GeventDummy)
    a = Manifest.for_proxy_class(AsyncioDummy)
    assert g.command == ('{python}', '-m', 'protocol_proxy.proxy', '--gevent', 'dummy_proxies:GeventDummy')
    assert a.command == ('{python}', '-m', 'protocol_proxy.proxy', 'dummy_proxies:AsyncioDummy')
    assert g.name == 'GeventDummy' and g.process_key(('k', 1), {}) == ('k', 1)


@pytest.mark.parametrize('toml, message', [
    ('[identity]\nkeys = ["a"]', 'table is required'),
    ('[proxy]\nname = "x"\ncommand = []', 'non-empty list of strings'),
    ('[proxy]\nname = "x"\ncommand = ["{shell}"]', 'unknown placeholder'),
    ('[proxy]\nname = "x"\ncommand = ["x"]\n[identity]\nkeys = ["h"]\n[identity.normalize]\nh = ["eval"]', 'unknown normaliser'),
    ('[proxy]\nname = "x"\ncommand = ["x"]\n[identity]\nkeys = ["h"]\n[identity.normalize]\nq = ["strip"]', 'not in keys or must_match'),
    ('[proxy]\nname = "x"\ncommand = ["x"]\n[proxy.extra]\n', 'unknown keys'),
    ('[proxy]\nname = "bad name"\ncommand = ["x"]', 'short identifier'),
    ('[proxy]\nname = "x"\ncommand = ["x"]\nheader_version = 3', 'header_version must be 1 or 2'),
    ('not toml ===', 'not valid TOML'),
])
def test_rejects_what_it_must(toml, message):
    with pytest.raises(ManifestError, match=message):
        Manifest.from_toml(toml)


def test_discovery_searches_the_configured_directories(tmp_path, monkeypatch):
    (tmp_path / 'a').mkdir(); (tmp_path / 'b' / 'dnp3').mkdir(parents=True)
    (tmp_path / 'a' / 'mqtt.toml').write_text(MQTT)
    (tmp_path / 'b' / 'dnp3' / 'proxy.toml').write_text(SINGLETON)
    monkeypatch.setenv(ENV_MANIFEST_PATH, os.pathsep.join([str(tmp_path / 'a'), str(tmp_path / 'b')]))
    assert search_path() == [tmp_path / 'a', tmp_path / 'b']
    assert locate('mqtt') == tmp_path / 'a' / 'mqtt.toml'
    assert find('dnp3').command[-1].endswith(':Dnp3Proxy')
    assert {'mqtt', 'dnp3'} <= set(discover())
    with pytest.raises(LookupError, match='looked at'):
        locate('nothing')


def test_first_directory_wins_over_later_ones(tmp_path, monkeypatch):
    for d, name in (('a', 'first'), ('b', 'second')):
        (tmp_path / d).mkdir()
        (tmp_path / d / 'p.toml').write_text(f'[proxy]\nname = "p"\ncommand = ["{name}"]\n')
    monkeypatch.setenv(ENV_MANIFEST_PATH, os.pathsep.join([str(tmp_path / 'a'), str(tmp_path / 'b')]))
    assert find('p').command == ('first',)
