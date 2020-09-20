from ctypes import *
from struct import pack, unpack
from .base import ProtocolBase
import socket

class IP(ProtocolBase):
    _fields_ = (
        ("ihlver", c_ubyte),
        ("tos",    c_ubyte),
        ("len",    c_ushort),
        ("id",     c_ushort),
        ("flags",  c_ubyte),
        ("frag",   c_ubyte),
        ("ttl",    c_ubyte),
        ("proto",  c_ubyte),
        ("chksum", c_ushort),
        ("_src",   c_uint),
        ("_dst",   c_uint),
    )

    # proto: tcp(6), udp(17), icmp(1)
    # ihlver: 0b01000101 (69)
    #    ihl: 0b0101     ( 5) = ip header length (5 * 4 = 20 bytes)
    #    ver: 0b0100     ( 4) = ip version 4
    # id: mainly used for reassembly of fragmented IP datagrams
    def __init__(self, **kwargs):
        self.ihlver = 0b01000101
        self.id = 1
        self.ttl = 64
        self.proto = 6
        self.src = "127.0.0.1"
        self.dst = "127.0.0.1"

        super().__init__(**kwargs)

    @property
    def src(self):
        src = pack(">I", self._src)
        return socket.inet_ntoa(src)

    @src.setter
    def src(self, value):
        src = socket.inet_aton(value)
        self._src = unpack(">I", src)[0]

    @property
    def dst(self):
        dst = pack(">I", self._dst)
        return socket.inet_ntoa(dst)

    @dst.setter
    def dst(self, value):
        dst = socket.inet_aton(value)
        self._dst = unpack(">I", dst)[0]

    def __repr__(self):
        reps = ["# IP", super().__repr__()]
        return "\n".join(reps)