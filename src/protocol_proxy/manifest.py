"""Proxy manifests: everything a manager needs to launch and key a proxy, as data.

A proxy ships a ``proxy.toml`` beside its code. A manager, in any language, reads it to learn the command that
starts the proxy, which launch options identify one process, and which options remotes sharing a process must agree
on. Nothing in a manifest is executable: identity values may only be normalised by the fixed set in
:data:`NORMALISERS` plus a ``default``.

.. code-block:: toml

    [proxy]
    name = "mqtt"
    command = ["{python}", "-m", "protocol_proxy.proxy", "--gevent", "protocol_proxy.protocol.mqtt.mqtt_proxy:MQTTProxy"]
    header_version = 2

    [identity]
    keys = ["host", "port"]            # launch options that select the process; absent: the caller's key, as given
    must_match = ["username", "password"]   # remotes sharing a process must agree on these

    [identity.normalize]
    host = ["strip", "lowercase"]
    port = [{ default = 1883 }]

    [environment]                      # added to the process environment
    MQTT_LOG = "info"

    [self_test]                        # optional: exits non-zero if the binary is not what the manifest says
    command = ["{python}", "-m", "protocol_proxy.protocol.mqtt", "--self-test"]

Discovery: directories named in the ``PROTOCOL_PROXY_MANIFESTS`` environment variable (``os.pathsep``-separated),
holding ``<name>.toml`` or ``<name>/proxy.toml``, then ``protocol_proxy.manifests`` entry points whose value is
``package.module:filename`` for manifests shipped as Python package data. A Python proxy class can also be described
without a file through :meth:`Manifest.for_proxy_class`, which is how tests and in-process proxies get one.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from importlib import import_module
from importlib.metadata import entry_points
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

try:
    import tomllib
except ModuleNotFoundError:     # Python 3.10
    import tomli as tomllib     # type: ignore[no-redef]

MANIFEST_FILENAME = 'proxy.toml'
ENV_MANIFEST_PATH = 'PROTOCOL_PROXY_MANIFESTS'
ENTRY_POINT_GROUP = 'protocol_proxy.manifests'
#: Placeholders a command may use; the manager resolves them at launch.
PLACEHOLDERS = frozenset({'python', 'manifest_dir'})
#: The identity normalisers a manifest may name. ``default`` is a table, ``{ default = <value> }``, not a name.
NORMALISERS: dict[str, Any] = {'lowercase': lambda v: v.lower() if isinstance(v, str) else v,
                               'strip': lambda v: v.strip() if isinstance(v, str) else v}
_PLACEHOLDER = re.compile(r'\{([a-z_]+)\}')


class ManifestError(ValueError):
    """A manifest that cannot be used: malformed, missing a required field, or asking for something not allowed."""


@dataclass(frozen=True)
class Identity:
    """How launch options select a proxy process and what remotes sharing one must agree on."""
    keys: tuple[str, ...] = ()
    normalize: Mapping[str, tuple[Any, ...]] = field(default_factory=dict)
    must_match: tuple[str, ...] = ()

    def normalized(self, key: str, value: Any) -> Any:
        """``value`` of option ``key`` after the manifest's normalisers for it (a missing value takes the default)."""
        for step in self.normalize.get(key, ()):
            if isinstance(step, Mapping):
                if value is None:
                    value = step['default']
            else:
                value = NORMALISERS[step](value)
        return value

    def key(self, name: str, unique_remote_id: tuple, options: Mapping[str, Any]) -> tuple:
        """The process key: the proxy name and the normalised identity options when the manifest names ``keys``,
        else the caller's ``unique_remote_id`` as given (every device shares a process unless the caller groups)."""
        if not self.keys:
            return tuple(unique_remote_id)
        return (name, *(self.normalized(k, options.get(k)) for k in self.keys))

    def conflicts(self, first: Mapping[str, Any], options: Mapping[str, Any]) -> list[str]:
        """The ``must_match`` options on which ``options`` differs from the ``first`` remote of a shared process."""
        return [k for k in self.must_match if self.normalized(k, first.get(k)) != self.normalized(k, options.get(k))]


@dataclass(frozen=True)
class Manifest:
    name: str
    command: tuple[str, ...]
    identity: Identity = field(default_factory=Identity)
    environment: Mapping[str, str] = field(default_factory=dict)
    self_test: tuple[str, ...] | None = None
    header_version: int = 2
    source: Path | None = None

    # ---- construction --------------------------------------------------------------------------------------------
    @classmethod
    def from_toml(cls, text: str, source: Path | None = None) -> 'Manifest':
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ManifestError(f'{source or "manifest"}: not valid TOML: {e}') from None
        return cls.from_dict(data, source)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], source: Path | None = None) -> 'Manifest':
        where = str(source or 'manifest')
        _only(data, {'proxy', 'identity', 'environment', 'self_test'}, where)
        proxy = _table(data, 'proxy', where, required=True)
        _only(proxy, {'name', 'command', 'header_version'}, f'{where} [proxy]')
        name = proxy.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
            raise ManifestError(f'{where} [proxy]: name must be a short identifier, got {name!r}')
        command = _command(proxy.get('command'), f'{where} [proxy] command')
        header_version = proxy.get('header_version', 2)
        if header_version not in (1, 2):
            raise ManifestError(f'{where} [proxy]: header_version must be 1 or 2, got {header_version!r}')
        identity = _identity(_table(data, 'identity', where), f'{where} [identity]')
        environment = _table(data, 'environment', where)
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in environment.items()):
            raise ManifestError(f'{where} [environment]: values must be strings')
        self_test = _table(data, 'self_test', where)
        _only(self_test, {'command'}, f'{where} [self_test]')
        test_command = _command(self_test['command'], f'{where} [self_test] command') if self_test else None
        return cls(name=name, command=command, identity=identity, environment=dict(environment),
                   self_test=test_command, header_version=int(header_version), source=source)

    @classmethod
    def load(cls, path: Path | str) -> 'Manifest':
        path = Path(path)
        return cls.from_toml(path.read_text(encoding='utf-8'), source=path)

    @classmethod
    def for_proxy_class(cls, proxy_class: type, name: str | None = None) -> 'Manifest':
        """A manifest for a Python proxy class in this environment: launched through the generic entry point, with
        ``--gevent`` when the class asks for monkey-patching. The identity is the caller's key as given."""
        module, class_name = proxy_class.__module__, proxy_class.__name__
        if module == '__main__':
            spec = getattr(sys.modules.get('__main__'), '__spec__', None)
            module = spec.name if spec else module
        entry_options = ('--gevent',) if getattr(proxy_class, 'PATCH_GEVENT', False) else ()
        return cls(name=name or class_name,
                   command=('{python}', '-m', 'protocol_proxy.proxy', *entry_options, f'{module}:{class_name}'))

    # ---- use -----------------------------------------------------------------------------------------------------
    def launch_command(self, python: str, standard_options: list[str] | tuple[str, ...] = ()) -> list[str]:
        """The argv to start the proxy: the manifest's command with placeholders resolved, then the manager's
        standard options (``--proxy-id`` and the rest)."""
        values = {'python': python, 'manifest_dir': str(self.source.parent) if self.source else ''}
        return [_PLACEHOLDER.sub(lambda m: values[m.group(1)], part) for part in self.command] + list(standard_options)

    def process_key(self, unique_remote_id: tuple, options: Mapping[str, Any]) -> tuple:
        return self.identity.key(self.name, unique_remote_id, options)


# ---- discovery ------------------------------------------------------------------------------------------------------
def search_path() -> list[Path]:
    """Directories searched for manifests, from ``PROTOCOL_PROXY_MANIFESTS``."""
    raw = os.environ.get(ENV_MANIFEST_PATH, '')
    return [Path(p).expanduser() for p in raw.split(os.pathsep) if p]


def _entry_point_manifests() -> dict[str, Path]:
    found = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        module_name, _, filename = ep.value.partition(':')
        try:
            path = Path(str(files(import_module(module_name)) / (filename or MANIFEST_FILENAME)))
        except Exception:   # a broken distribution must not hide the others
            continue
        found.setdefault(ep.name, path)
    return found


def locate(name: str) -> Path:
    """Where the manifest for ``name`` is: ``<dir>/<name>.toml`` or ``<dir>/<name>/proxy.toml`` in the search path
    (first match wins), else the entry point of that name. :raises LookupError: naming every place looked."""
    looked = []
    for directory in search_path():
        for candidate in (directory / f'{name}.toml', directory / name / MANIFEST_FILENAME):
            looked.append(str(candidate))
            if candidate.is_file():
                return candidate
    if (path := _entry_point_manifests().get(name)) is not None:
        return path
    looked.append(f'entry point {ENTRY_POINT_GROUP}:{name}')
    raise LookupError(f'No manifest for proxy {name!r}; looked at: {", ".join(looked)}')


def find(name: str) -> Manifest:
    return Manifest.load(locate(name))


def discover() -> dict[str, Manifest]:
    """Every manifest reachable: search-path directories first, then entry points, by proxy name."""
    manifests: dict[str, Manifest] = {}
    for directory in search_path():
        if not directory.is_dir():
            continue
        for path in sorted([*directory.glob('*.toml'), *directory.glob(f'*/{MANIFEST_FILENAME}')]):
            manifest = Manifest.load(path)
            manifests.setdefault(manifest.name, manifest)
    for name, path in _entry_point_manifests().items():
        if name not in manifests and path.is_file():
            manifests[name] = Manifest.load(path)
    return manifests


# ---- validation helpers ---------------------------------------------------------------------------------------------
def _only(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    if unknown := set(table) - allowed:
        raise ManifestError(f'{where}: unknown keys {sorted(unknown)}; allowed: {sorted(allowed)}')


def _table(data: Mapping[str, Any], key: str, where: str, required: bool = False) -> Mapping[str, Any]:
    table = data.get(key)
    if table is None:
        if required:
            raise ManifestError(f'{where}: the [{key}] table is required')
        return {}
    if not isinstance(table, Mapping):
        raise ManifestError(f'{where}: [{key}] must be a table')
    return table


def _command(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(p, str) or not p for p in value):
        raise ManifestError(f'{where}: must be a non-empty list of strings')
    for part in value:
        for placeholder in _PLACEHOLDER.findall(part):
            if placeholder not in PLACEHOLDERS:
                raise ManifestError(f'{where}: unknown placeholder {{{placeholder}}}; allowed: {sorted(PLACEHOLDERS)}')
    return tuple(value)


def _identity(table: Mapping[str, Any], where: str) -> Identity:
    _only(table, {'keys', 'must_match', 'normalize'}, where)
    keys = _names(table.get('keys', []), f'{where} keys')
    must_match = _names(table.get('must_match', []), f'{where} must_match')
    normalize: dict[str, tuple[Any, ...]] = {}
    for key, steps in (table.get('normalize') or {}).items():
        if key not in keys and key not in must_match:
            raise ManifestError(f'{where}.normalize: {key!r} is not in keys or must_match')
        if not isinstance(steps, list):
            raise ManifestError(f'{where}.normalize: {key} must be a list of steps')
        checked = []
        for step in steps:
            if isinstance(step, str):
                if step not in NORMALISERS:
                    raise ManifestError(f'{where}.normalize: unknown normaliser {step!r} for {key};'
                                        f' allowed: {sorted(NORMALISERS)} or {{ default = <value> }}')
            elif not (isinstance(step, Mapping) and set(step) == {'default'}):
                raise ManifestError(f'{where}.normalize: a step is a normaliser name or {{ default = <value> }}, got {step!r}')
            checked.append(step)
        normalize[key] = tuple(checked)
    return Identity(keys=keys, normalize=normalize, must_match=must_match)


def _names(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        raise ManifestError(f'{where}: must be a list of option names')
    return tuple(value)
