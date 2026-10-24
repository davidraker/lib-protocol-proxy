"""Proxy manifests: parsing, identity rules, discovery, and the launch command they produce."""
import os
import textwrap

import pytest

from pathlib import Path
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


def test_environment_values_resolve_the_same_placeholders_as_the_command(tmp_path):
    path = tmp_path / 'native' / 'proxy.toml'
    path.parent.mkdir()
    path.write_text('[proxy]\nname = "native"\ncommand = ["{manifest_dir}/bin/native"]\n'
                    '[environment]\nLD_LIBRARY_PATH = "{manifest_dir}/lib"\nPYTHON = "{python}"\nPLAIN = "x"\n')
    m = Manifest.load(path)
    assert m.environment['LD_LIBRARY_PATH'] == '{manifest_dir}/lib'                     # as written
    assert m.launch_environment('/venv/bin/python') == {'LD_LIBRARY_PATH': f'{path.parent}/lib',
                                                        'PYTHON': '/venv/bin/python', 'PLAIN': 'x'}


def test_shipped_dummy_manifests_load_and_put_the_tests_directory_on_the_path():
    tests_dir = Path(__file__).resolve().parent
    for name in ('GeventDummy', 'AsyncioDummy'):
        m = Manifest.load(tests_dir / 'manifests' / f'{name}.toml')
        assert m.name == name and m.command[-1] == f'dummy_proxies:{name}'
        assert Path(m.launch_environment('py')['PYTHONPATH']).resolve() == tests_dir


@pytest.mark.parametrize('toml, message', [
    ('[identity]\nkeys = ["a"]', 'table is required'),
    ('[proxy]\nname = "x"\ncommand = ["x"]\n[environment]\nHOME = "{home}"', 'unknown placeholder'),
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
    assert search_path()[:2] == [tmp_path / 'a', tmp_path / 'b']     # the variable comes first; defaults follow
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


def test_default_search_path_order_and_the_variable_prepends(tmp_path, monkeypatch):
    import sys
    from protocol_proxy.manifest import MANIFEST_SUBDIR, environment_directory
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('XDG_CONFIG_HOME', raising=False); monkeypatch.delenv('XDG_CONFIG_DIRS', raising=False)
    monkeypatch.delenv('XDG_DATA_DIRS', raising=False); monkeypatch.delenv(ENV_MANIFEST_PATH, raising=False)
    monkeypatch.setattr(sys, 'prefix', str(tmp_path / 'venv'))
    assert search_path() == [tmp_path / 'home' / '.config' / MANIFEST_SUBDIR, tmp_path / 'venv' / 'share' / MANIFEST_SUBDIR,
                             Path('/etc') / MANIFEST_SUBDIR, Path('/usr/local/share') / MANIFEST_SUBDIR, Path('/usr/share') / MANIFEST_SUBDIR]
    assert environment_directory() == tmp_path / 'venv' / 'share' / MANIFEST_SUBDIR
    monkeypatch.setenv(ENV_MANIFEST_PATH, os.pathsep.join([str(tmp_path / 'dev'), str(tmp_path / 'home' / '.config' / MANIFEST_SUBDIR)]))
    path = search_path()
    assert path[0] == tmp_path / 'dev' and path.count(tmp_path / 'home' / '.config' / MANIFEST_SUBDIR) == 1


def test_a_manifest_in_the_environment_directory_is_found_without_configuration(tmp_path, monkeypatch):
    import sys
    from protocol_proxy.manifest import environment_directory
    monkeypatch.delenv(ENV_MANIFEST_PATH, raising=False)
    monkeypatch.setattr(sys, 'prefix', str(tmp_path / 'venv'))
    target = environment_directory(); target.mkdir(parents=True)
    (target / 'dnp3.toml').write_text(SINGLETON)
    assert locate('dnp3') == target / 'dnp3.toml'


def test_export_copies_entry_point_manifests_with_the_package_directory_resolved(tmp_path, monkeypatch):
    import protocol_proxy.manifest as m
    pkg = tmp_path / 'pkg'; pkg.mkdir()
    (pkg / 'proxy.toml').write_text('[proxy]\nname = "mms"\ncommand = ["{manifest_dir}/bin/mms-proxy"]\n')
    monkeypatch.setattr(m, '_entry_point_manifests', lambda: {'mms': pkg / 'proxy.toml'})
    written = m.export(tmp_path / 'out')
    assert written == [tmp_path / 'out' / 'mms.toml']
    copied = Manifest.load(written[0])
    assert copied.command == (f'{pkg}/bin/mms-proxy',) and copied.launch_command('py') == [f'{pkg}/bin/mms-proxy']


def test_cli_lists_paths_and_exports(tmp_path, monkeypatch, capsys):
    import protocol_proxy.manifest as m
    monkeypatch.setenv(ENV_MANIFEST_PATH, str(tmp_path / 'dev'))
    (tmp_path / 'dev').mkdir(); (tmp_path / 'dev' / 'mqtt.toml').write_text(MQTT)
    assert m.main(['path']) == 0 and str(tmp_path / 'dev') in capsys.readouterr().out
    assert m.main(['list']) == 0 and 'mqtt' in capsys.readouterr().out
    monkeypatch.setattr(m, '_entry_point_manifests', lambda: {'mqtt': tmp_path / 'dev' / 'mqtt.toml'})
    assert m.main(['export', '--to', str(tmp_path / 'out')]) == 0 and (tmp_path / 'out' / 'mqtt.toml').is_file()
