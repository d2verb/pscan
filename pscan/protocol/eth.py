from ctypes import *
from .base import ProtocolBase

class ETH(ProtocolBase):
    _fields_ = (
        ("_dst", c_ubyte * 6),
        ("_src", c_ubyte * 6),
        ("type", c_ushort)
    )

    # type: ipv4(0x0800)
    def __init__(self, **kwargs):
        self.type = 0x0800

        super().__init__(**kwargs)

    @property
    def src(self):
        return ":".join([f"{octet:02x}" for octet in self._src])

    @src.setter
    def src(self, value):
        src = [int(octet, 16) for octet in value.split(":")]
        self._src = (c_ubyte * 6)(*src)

    @property
    def dst(self):
        return ":".join([f"{octet:02x}" for octet in self._dst])

    @dst.setter
    def dst(self, value):
        dst = [int(octet, 16) for octet in value.split(":")]
        self._dst = (c_ubyte * 6)(*dst)

    def __repr__(self):
        reps = ["# Ethernet", super().__repr__()]
        return "\n".join(reps)