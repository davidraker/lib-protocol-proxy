"""Minimal gevent and asyncio proxies for end-to-end tests that launch real processes through a manager.
Each logs an INFO 'tick' and a DEBUG 'debug tick' every 0.1 s once running."""
import asyncio
import logging

from gevent import sleep

from protocol_proxy.proxy.asyncio import AsyncioProtocolProxy
from protocol_proxy.proxy.gevent import GeventProtocolProxy

_log = logging.getLogger(__name__)


class GeventDummy(GeventProtocolProxy):
    LAUNCHER = 'launch_gevent_dummy'


    def main_loop(self):
        n = 0
        while not self._stop:
            _log.info('tick %d', n)
            _log.debug('debug tick %d', n)
            n += 1
            sleep(0.1)


def launch_gevent_dummy(parser):
    return parser, lambda **options: GeventDummy(**options).run()


class AsyncioDummy(AsyncioProtocolProxy):

    async def _ticker(self):
        n = 0
        while not self._stopping:
            _log.info('tick %d', n)
            _log.debug('debug tick %d', n)
            n += 1
            await asyncio.sleep(0.1)

    async def start(self):
        self.loop.create_task(self._ticker())
        await super().start()
