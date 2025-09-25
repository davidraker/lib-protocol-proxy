import sys

from argparse import ArgumentParser
from asyncio import iscoroutinefunction, run
from typing import Callable
from uuid import UUID

def proxy_command_parser(parser: ArgumentParser = None):
    parser = parser if parser else ArgumentParser()
    parser.add_argument('--proxy-id', type=UUID, required=True)
    parser.add_argument('--proxy-name', type=str, required=True)
    parser.add_argument('--manager-id', type=UUID, required=True)
    parser.add_argument('--manager-address', type=str, default='localhost',
                        help='Address of the outbound socket to the Proxy Manager.')
    parser.add_argument('--manager-port', type=int, default=22801,
                        help='Port of the outbound socket to the Proxy Manager.')
    parser.add_argument('--encrypt', type=bool, default=False,
                        help='Whether to use encryption on the socket connections with the Manager.')
    parser.add_argument('--inbound-address', type=str, default='localhost',
                        help='Address of the inbound socket from the Proxy Manager')
    parser.add_argument('--inbound-port', type=int, default=22802,
                        help='Port of the inbound socket from the Proxy Manager')
    return parser

def launch(launcher_func: Callable):
    parser = proxy_command_parser()
    parser, proxy_runner = launcher_func(parser)
    opts = parser.parse_args()
    proxy_token = UUID(hex=sys.stdin.read(32))
    manager_token = UUID(hex=sys.stdin.read(32))
    if iscoroutinefunction(proxy_runner):
        run(proxy_runner(token=proxy_token, manager_token=manager_token, **vars(opts)))
    else:
        proxy_runner(token=proxy_token, manager_token=manager_token, **vars(opts))
