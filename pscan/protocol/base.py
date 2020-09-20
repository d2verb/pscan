from ctypes import BigEndianStructure, sizeof
import io

class ProtocolBase(BigEndianStructure):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payload = None
        self.parent = None

    def bytes(self):
        me = bytes(self)
        if self.payload:
            return me + self.payload.bytes()
        return me

    @classmethod
    def load(cls, data):
        buffer = io.BytesIO(data)
        c = cls()
        buffer.readinto(c)
        return c

    @classmethod
    def size(cls):
        return sizeof(cls)
        
    def __pow__(self, payload):
        self.payload = payload
        payload.parent = self
        return self

    def __repr__(self):
        reps = []
        for name, _ in self._fields_:
            if name.startswith("_"):
                name = name[1:]
            reps.append(f"  {name:<10} = {getattr(self, name)}")
        return "\n".join(reps)