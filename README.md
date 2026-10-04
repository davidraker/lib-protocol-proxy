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
