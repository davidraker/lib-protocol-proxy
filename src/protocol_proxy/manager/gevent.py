import atexit
import logging
import os

from abc import ABC
from gevent import sleep, spawn, with_timeout
from gevent.subprocess import Popen, PIPE
from gevent.timeout import Timeout
from uuid import uuid4
from typing import IO, Type

from ..ipc import callback, ProtocolHeaders, ProtocolProxyPeer
from ..ipc.gevent import GeventIPCConnector, GeventProtocolProxyPeer
from ..proxy import ProtocolProxy
from . import ProtocolProxyManager

_log = logging.getLogger(__name__)


class GeventProtocolProxyManager(ProtocolProxyManager, GeventIPCConnector, ABC):
    def __init__(self, proxy_class: Type[ProtocolProxy], **kwargs):
        super().__init__(proxy_class=proxy_class, **kwargs)

    def wait_peer_registered(self, peer, timeout, func=None, *args, **kwargs):
        """ Waits for a peer to be ready, optionally calling a function when it is.
            If the peer does not register within the timeout, it is removed and a warning is logged.
        """
        def wait_for_peer_registration():
            while peer.socket_params is None:
                sleep(0.1)

        try:
            with peer.ready:
                with_timeout(timeout, wait_for_peer_registration)
        except Timeout:
            _log.warning(f"Peer {peer.proxy_id} did not register within {timeout} seconds. Removing peer.")
            self._lose_peer(peer, f'did not register within {timeout} seconds')
            return
        if func:
            try:
                func(*args, **kwargs)
            except Exception as e:
                # The peer itself is fine; only this caller's follow-up failed. Keep the peer for everyone else.
                _log.error(f"Error running post-registration function for peer {peer.proxy_id}: {e}")

    def _lose_peer(self, peer: ProtocolProxyPeer, reason: str):
        """Forget a peer and stop its process if it is still running, then tell the peer-lost listeners."""
        if self.peers.get(peer.proxy_id) is peer:
            del self.peers[peer.proxy_id]
        if (process := getattr(peer, 'process', None)) is not None and process.poll() is None:
            spawn(self._cleanup_proxy_process, process)
        self._notify_peer_lost(peer, reason)

    def _watch_proxy_process(self, proxy_id, peer: GeventProtocolProxyPeer):
        """Wait for a launched proxy process to exit; when it does, drop its peer (if it is still the current one for
        this proxy id) so the next get_proxy relaunches, and tell the listeners so they can re-register."""
        returncode = peer.process.wait()
        if self.peers.get(proxy_id) is peer:
            _log.warning(f'PPM: {self.proxy_class.__name__} process {peer.process.pid} (proxy {proxy_id}) exited with'
                         f' code {returncode}. It will be relaunched on the next request for it.')
            self._lose_peer(peer, f'process exited with code {returncode}')
        else:
            _log.debug(f'PPM: {self.proxy_class.__name__} process {peer.process.pid} (proxy {proxy_id}) exited with'
                       f' code {returncode} after its peer was already replaced or removed.')

    def get_proxy(self, unique_remote_id: tuple, **kwargs) -> ProtocolProxyPeer:
        #_log.debug('@@@@@@@ IN GET_PROXY @@@@@@@')
        command, proxy_id, proxy_name = self._setup_proxy_process_command(unique_remote_id, **kwargs) # , proxy_env
        #_log.debug(f'@@@@@@@ AFTER SETUP_PROXY_PROCESS_COMMAND: {(command, proxy_id, proxy_name)} @@@@@@@')
        if command:
            proxy_process = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            _log.info(f'proxy {proxy_name} has PID {proxy_process.pid}')
            spawn(self.log_subprocess_output, proxy_process.stdout)
            spawn(self.log_subprocess_output, proxy_process.stderr)
            # TODO: Ensure that logging as implemented fits with VOLTTRON logging once that is fixed..
            _log.info(f"PPM: Created new ProtocolProxy {proxy_name} with ID {str(proxy_id)}, pid: {proxy_process.pid}")
            new_peer_token = uuid4()
            proxy_process.stdin.write(new_peer_token.hex.encode())
            proxy_process.stdin.write(self.token.hex.encode())
            proxy_process.stdin.flush()
            proxy_process.stdin.close()
            proxy_process.stdin = open(os.devnull)
            self.peers[proxy_id] = GeventProtocolProxyPeer(process=proxy_process, proxy_id=proxy_id,
                                                           token=new_peer_token)
            atexit.register(self._cleanup_proxy_process, proxy_process)
            spawn(self._watch_proxy_process, proxy_id, self.peers[proxy_id])
            # Do NOT send to the proxy until it has registered and socket_params is set!
            _log.info(f"PPM: Proxy {proxy_id} created, waiting for registration before sending.")
        #_log.debug(f'@@@@@@@ GET_PROXY WILL RETURN PEER: {self.peers[proxy_id]} @@@@@@@')
        return self.peers[proxy_id]

    def log_subprocess_output(self, stream: IO[bytes]):
        """Reads lines from a pipe and logs them."""
        for raw_line in iter(stream.readline, b''):
            self.log_subprocess_output_line(raw_line)

    @callback
    def handle_peer_registration(self, headers: ProtocolHeaders, raw_message: bytes):
        return super().handle_peer_registration(headers, raw_message)

    def _cleanup_proxy_process(self, process: Popen, timeout: float = 5.0):
        # TODO: Waits may block. Check this and change to a method that yields if needed.
        if process.poll() is None:
            try:
                _log.info(f'Terminating {self.proxy_class.__name__} with PID: {process.pid}')
                process.terminate()
                if process.wait(timeout=timeout) is None:
                    _log.info(f'Killing {self.proxy_class.__name__} with PID: {process.pid}')
                    process.kill()
                    if process.wait(timeout=timeout) is None:
                        _log.warning(f'Failed to stop {self.proxy_class.__name__} with PID: {process.pid}')
            except Timeout:
                process.kill()
            except Exception as e:
                _log.warning(f'Exception encountered attempting to terminate proxy process ({process.pid}): {e}')
