from ctypes import *
from random import randint
from struct import pack, unpack

import socket
import array

from .base import ProtocolBase

class TCP(ProtocolBase):
    _fields_ = (
        ("sport",    c_ushort),
        ("dport",    c_ushort),
        ("seq",      c_uint),
        ("ack",      c_uint),
        ("_dataofs", c_byte),
        ("_flags",   c_byte),
        ("window",   c_ushort),
        ("chksum",   c_ushort),
        ("urgptr",   c_ushort),
    )

    def __init__(self, **kwargs):
        self.dataofs = 5
        self.window = 8192
        self.sport = randint(49152, 65535) # ephemeral port

        super().__init__(**kwargs)

    @property
    def flags(self):
        value = ""
        for i, f in enumerate("FSRPAU"):
            if self._flags & (1 << i):
                value += f
        return value

    @flags.setter
    def flags(self, value):
        self._flags = 0
        for i, f in enumerate("FSRPAU"):
            if f not in value:
                continue
            self._flags = self._flags | (1 << i)

    @property
    def dataofs(self):
        return (self._dataofs >> 4) & 0xf

    @dataofs.setter
    def dataofs(self, value):
        self._dataofs = (value << 4) & 0xff

    def __repr__(self):
        reps = ["# TCP", super().__repr__()]
        return "\n".join(reps)

    def bytes(self):
        if self.parent:
            self.update_chksum(self.parent.src, self.parent.dst)
        return super().bytes()

    def update_chksum(self, saddr, daddr):
        pseudo_ip_header = pack(
            "!4s4sBBH",
            socket.inet_aton(saddr),
            socket.inet_aton(daddr),
            0,
            socket.IPPROTO_TCP,
            self.size() + len("" if self.payload is None else self.payload)
        )

        headers = pseudo_ip_header + bytes(self)
        headers = headers.ljust((len(headers) + 1) // 2, b"\x00")
        headlen = len(headers)

        chksum = sum(array.array("H", headers))
        while chksum >> 16:
            chksum = (chksum >> 16) + (chksum & 0xffff)
        chksum = chksum >> 8 | (chksum << 8 & 0xff00)

        self.chksum = ~chksum & 0xffff