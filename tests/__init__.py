"""Test package. Outbound network connections are blocked for the whole run."""

import socket

_real_connect = socket.socket.connect


def _guarded_connect(self, address):
    if self.family == getattr(socket, "AF_UNIX", None):
        return _real_connect(self, address)
    raise RuntimeError("network access attempted during tests: %r" % (address,))


socket.socket.connect = _guarded_connect
