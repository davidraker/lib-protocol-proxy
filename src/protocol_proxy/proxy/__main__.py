"""``python -m protocol_proxy.proxy [--gevent] <module>:<ProxyClass> [options]`` launches a protocol proxy."""
import sys

from .launch import main

sys.exit(main())
