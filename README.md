# Protocol Proxy
![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
[![Passing?](https://github.com/eclipse-volttron/lib-protocol-proxy/actions/workflows/run-tests.yml/badge.svg)](https://github.com/eclipse-volttron/lib-protocol-proxy/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/protocol-proxy.svg)](https://pypi.org/project/protocol-proxy/)

This library provides the user with the ability to automatically deploy and manage proxy processes for handling
network communication with remote devices using various protocols. A proxy to each remote peer is established in 
a separate process from the managing application. A manager class handles socket communication between the proxy
subprocess and its owner. Individual protocols are implemented as plugins to this library. Integration with 
event and asyncio event loops are supported for each of the proxy and manager processes.


## Automatically installed dependencies
- python = ">=3.10,<4.0"

[//]: # (# Documentation)

[//]: # (More detailed documentation can be found on [ReadTheDocs]&#40;https://eclipse-volttron.readthedocs.io/en/latest/external-docs/lib-protocol-proxy/index.html. The RST source)

[//]: # (of the documentation for this component is located in the "docs" directory of this repository.)

# Installation
This library can be installed using pip:

```shell
pip install lib-protocol-proxy
```

Protocol Proxy plugins should include "protocol-proxy" as a requirement, so users of existing
plugins are encouraged to instead install the plugin for that package directly.

# Development
This library is maintained by the VOLTTRON Development Team.

Please see the following [guidelines](https://github.com/eclipse-volttron/volttron-core/blob/develop/CONTRIBUTING.md)
for contributing to this and/or other VOLTTRON repositories.

[//]: # (Please see the following helpful guide about [using the Protocol Proxy]&#40;https://github.com/eclipse-volttron/lib-protocol-proxy/blob/develop/developing_with_protocol_proxy.md&#41;)

[//]: # (in your VOLTTRON agent or other applications.)

# Process supervision

A `ProtocolProxyManager` launches one proxy process per proxy key and watches it. When a proxy process exits, the
manager logs the exit code, forgets the peer (so the next `get_proxy` for that key launches a fresh process) and calls
every listener registered with `manager.on_peer_lost(callback)` as `callback(peer, reason)`. Users of a proxy, such as
VOLTTRON driver interfaces, re-run their setup from that callback: `get_proxy`, `wait_peer_registered` and their own
registration message. A proxy that never registers within the `wait_peer_registered` timeout is treated the same way,
and its process is terminated.

Each proxy process watches its parent in turn (`manager_alive`, by parent PID, every `manager_watch_interval`
seconds, 1.0 by default). If the manager process dies, the proxy calls `on_manager_lost` (by default: log and stop),
so an orphaned proxy releases its sockets instead of competing with the replacement a restarted manager launches. A
protocol proxy that holds state may override `on_manager_lost` to flush it first.

## Connections

A connector sends a message by dialling a TCP connection, writing one frame (header then payload) and, when a reply
is expected, reading the `RESPONSE` frame back before closing: one connection per message. That is the default and
what every proxy did before persistent connections existed. Connection lifetime is a policy per peer
(`ProtocolProxyPeer.persistent`, defaulting to the connector's `persistent` option): a persistent peer has one
connection carrying frames in both directions, dialled on the first send and redialled on demand after a loss.
Responses are matched by request id, so requests interleave; handlers for frames on a persistent connection run
concurrently, so a slow one does not hold up the frames behind it. A frame larger than `persistent_max_frame`
(256 KiB) takes its own connection so a multi-megabyte registration does not delay the frames behind it. When a
connection is lost, the requests still awaiting responses on it fail with `ConnectionError` instead of waiting out
their timeouts.

A receiver reads frames until the sender closes, so either policy works against either peer. The sender sets the
header's keep-alive bit (bit 3 of `bitflags`) on frames it sends over a persistent connection; a receiver that sees
the bit on an accepted connection from an authenticated peer adopts that connection as its way back to the peer.
This is how a manager reaches a proxy whose address it cannot dial (a remote proxy that dialled in through NAT or an
SSH tunnel): the proxy registers over its persistent connection and every request to it travels back on the same
one. Persistent sockets have TCP keepalive enabled so a vanished peer is noticed within about a minute; the
heartbeat planned for liveness will shorten that.

A proxy that cannot reach the manager's address (behind NAT, or started where that address is not routable) is
launched with `get_proxy(key, manager_dials=True, inbound_address=..., inbound_port=..., ...)`: it listens on that
address and does not dial; the manager dials it (at `dial=(address, port)` when that differs from the listener), sends
`PING` on a persistent connection until the proxy registers over it, and from then on every request and push uses that
one connection. The proxy attaches only a connection whose frames authenticate as the manager it was launched for (id
on the command line, token on stdin), so nothing else can present itself as its manager.

To run a proxy persistently, pass `persistent=True` to `get_proxy` (it reaches the proxy as `--persistent True`, so
both ends apply the same policy). The driver interfaces default to persistent since 2026-10-22 (`persistent_connection`
per device turns it off).

## TLS for remote peers

`get_proxy(key, ipc_tls=True, ...)`, or a manager created with `ipc_tls=True`, makes every IPC connection with that
proxy TLS 1.3 with mutual authentication. The manager is the certificate authority: it creates a CA of its own the
first time, issues itself a certificate and issues each TLS proxy one naming the proxy's id, and writes
`{"ca", "cert", "key"}` as one JSON line to the proxy's stdin after the tokens (and the AEAD key, if any); the proxy is
launched with `--ipc-tls True`. The proxy verifies the manager's certificate against that CA and presents its own; the
manager requires the proxy's and checks that its common name is the proxy's id; a frame's sender id must match the
certificate it arrived under. The manager's listener tells TLS from plain by peeking at the first byte, so local plain
proxies and remote TLS proxies share it; a proxy with TLS material accepts TLS only. Nothing is written to disk beyond
the instant `ssl` needs the certificate chain in a file. `ipc_tls` is distinct from a protocol's own `tls` option (the
MQTT proxy's broker TLS). Use it for proxies reached over an untrusted network without an SSH tunnel; with the SSH
launcher it is unnecessary.

## Encryption

A manager launched with `encrypt=True` (or a proxy requested with `get_proxy(..., encrypt=True)`) generates a 32-byte
key per proxy and writes it, as hex, to the proxy's stdin after the two tokens; the proxy is launched with
`--encrypt True` and refuses to start if no key follows the tokens. Nothing secret is on the command line. From then
on every frame between the two, registration included, is ChaCha20-Poly1305: header bit 2 is set, the payload on the
wire is a 12-byte random nonce, the ciphertext and the 16-byte tag (`data_length` counts those bytes), and the whole
header, version word through `remote_id`, is the associated data, so the method name, request id, sender, remote and
flags cannot be altered or replayed onto another message without detection. Compression, when it applies, happens
before encryption. The mode is fixed per peer: a receiver refuses a clear-text frame from a peer it shares a key with
and an encrypted frame from one it does not; the refused request fails (or the connection is dropped) and nothing
else is affected. Peers advertise `aead-chacha20poly1305` in their features. Keys live for the proxy's lifetime; a
relaunch gets a fresh one. TLS for remote peers is a separate, later step.

## Compression

A payload larger than `compress_threshold` bytes (4096 by default; `--compress-threshold` on a proxy, 0 compresses
everything, None disables) is zlib-compressed toward a peer that advertised `compress`, and header bit 1 is set so the
receiver inflates it; `data_length` counts the wire bytes. Proxies advertise it in `REGISTER_PEER` `features`, the
manager in its reply (`{"registered": true, "features": ["compress"]}`; older managers reply plain `true`), so nothing
is compressed before registration or toward a peer whose features are unknown. Responses are compressed on the same
rule toward the requester. Receivers always accept both forms; corrupt compressed data fails that request (or that
connection) and nothing else.

## Heartbeat and health

The manager sends `PING` (response expected, empty payload) to every registered peer it launched, every
`heartbeat_interval` seconds (10 by default, 0 disables). A proxy answers with `{"uptime", "remotes", "busy",
"last_activity"}` (`ProtocolProxy.health_report`, which a protocol may override to report what it serves). Any reply
marks the peer `healthy`, even the unknown-method error an older proxy returns; no reply within `heartbeat_timeout`
(5 s) marks it `unhealthy`, and `heartbeat_misses` (3) consecutive misses mark it `lost` and run the same path as a
process exit: terminate, forget, tell the `on_peer_lost` listeners, relaunch on the next `get_proxy`. The parent-PID
watch in the proxy and TCP keepalive on persistent connections stay as the cheaper first signals. `manager.health()`
returns every peer's state (`launching`, `registered`, `healthy`, `unhealthy`, `lost`), last contact, consecutive
misses, advertised features (`REGISTER_PEER` now carries `"features": ["ping", "log", "set_log_level"]`), pid,
connection policy and last report.

## Remote proxies over SSH

`get_proxy(key, ssh_host='user@host', ssh_options=[...], remote_python='/path/python', remote_env={...})` launches
the proxy on another machine with the same command, wrapped as `ssh -o BatchMode=yes -R <manager port>:127.0.0.1:<manager
port> [options] host env _LAUNCHED_BY_PROXY_MANAGER=1 [remote_env...] <remote_python> -m protocol_proxy.proxy ...`.
Tokens and the key still travel on stdin (inside SSH), logs still arrive on the pipes, and the reverse forward lets the
proxy reach this manager at `127.0.0.1:<manager port>` on its own host (`--manager-address` is set to that; pass
`ssh_forward=False` and your own `manager_address` to dial directly). With the default persistent connection the manager
never needs to dial the proxy, so no forward in the other direction is required. These options are the manager's own
and are not passed to the proxy.


A proxy launched by a manager logs through one channel: every record is one JSON object per line on **stderr**, with
the `LogRecord` attribute names (`name`, `levelno`, `levelname`, `pathname`, `lineno`, `funcName`, `created`,
`msecs`, `process`, `msg` already interpolated, and `exc_text` holding the formatted traceback). The manager reads
both pipes (`protocol_proxy.logs.log_entries`) and rebuilds each record with `logging.makeLogRecord`, so proxy
records appear in the manager's log with the proxy's file, line and PID; the proxy's own logger name is kept in
`remote_name` and the record is handled by the logger `protocol_proxy.proxies.<ProxyClass>.<proxy name>` (the name
reduced to logger-safe characters). That logger's effective level gates the records and is passed to the proxy as
`--log-level`, so operators tune a proxy like any other logger. Plain lines are classified by stream (stdout INFO,
stderr WARNING) or by a syslog-style `<N>` prefix (`<7>` debug ... `<2>` critical), the same rules VOLTTRON applies
to agent output.

Once a proxy has registered, its records travel over the IPC socket instead: a non-blocking handler queues them and
the proxy sends a `LOG` message (no response) every 0.2 s or 64 records, `{"records": [fields...], "dropped": n}`,
which the manager feeds through the same reader (`channel` is `socket` on those records, `stderr` or `stdout`
otherwise). The queue is bounded (2000 records) and rate-limited (50 records/s sustained, bursts of 200); records
beyond that are dropped and counted, and the manager logs the count as a WARNING. stderr still carries everything
before registration and whatever is queued at exit, so a proxy that dies early is still heard. The socket is the
channel every launch mode has (a remote proxy's stderr may never reach the manager) and it will be the encrypted one.
`--socket-logging False` keeps stderr throughout. On a persistent connection LOG batches are written only when no
ordinary frame is waiting (gevent) or queued on the transport (asyncio), so logging never delays protocol traffic. `manager.set_proxy_log_level(peer, 'DEBUG')` sends
`SET_LOG_LEVEL` to a running proxy and gates the manager's logger for it at the same level, so a remote proxy's
verbosity can be raised for a while without a restart.

Inside the proxy, `configure_logging` (run by the launcher, re-checked at `start()`) also captures what would bypass
`logging`: Python warnings (`py.warnings`), uncaught exceptions (`protocol_proxy.uncaught`), gevent greenlet
tracebacks (`gevent.hub`, one record per failure) and anything printed to stdout (`stdout`, INFO). Handlers that a
library installs on its own loggers are removed, with a WARNING naming the logger, so each record reaches the channel
once; protocol proxies should set library log levels (`logging.getLogger('pymodbus').setLevel(...)`) rather than
call a library's logging setup. The JSON channel is used only when `_LAUNCHED_BY_PROXY_MANAGER` is in the
environment and stderr is a pipe; a proxy run by hand logs readable text. `PROTOCOL_PROXY_LOG` sends the readable
text to a file instead, and `PROTOCOL_PROXY_LOG_LEVEL` sets the level when no `--log-level` is given.

# Disclaimer Notice

This material was prepared as an account of work sponsored by an agency of the
United States Government.  Neither the United States Government nor the United
States Department of Energy, nor Battelle, nor any of their employees, nor any
jurisdiction or organization that has cooperated in the development of these
materials, makes any warranty, express or implied, or assumes any legal
liability or responsibility for the accuracy, completeness, or usefulness or any
information, apparatus, product, software, or process disclosed, or represents
that its use would not infringe privately owned rights.

Reference herein to any specific commercial product, process, or service by
trade name, trademark, manufacturer, or otherwise does not necessarily
constitute or imply its endorsement, recommendation, or favoring by the United
States Government or any agency thereof, or Battelle Memorial Institute. The
views and opinions of authors expressed herein do not necessarily state or
reflect those of the United States Government or any agency thereof.
