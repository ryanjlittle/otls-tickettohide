"""Various small utility or helper stuff not TLS specific."""

import base64

class SetOnce:
    """Descriptor that allows setting but not getting an attribute value."""
    def __init__(self):
        self._values = {}

    def __set_name__(self, owner, name):
        self._name = name

    def __set__(self, obj, value):
        if id(obj) in self._values:
            raise ValueError(f"{self._name} is already set")
        self._values[id(obj)] = value

    def __get__(self, obj, objtype=None):
        try:
            return self._values[id(obj)]
        except KeyError:
            raise ValueError(f"{self._name} is not yet set") from None


class Memoized(SetOnce):
    """Descriptor that computes an attribute's value only once.
    To compute obj.x, obj._compute_x() is called.
    """
    def __set_name__(self, owner, name):
        super().__set_name__(owner, name)
        self._computer = getattr(owner, f"_compute_{name}")

    def __get__(self, obj, objtype=None):
        if not self._is_set:
            super().__set__(obj, self._computer(obj))
        return super().__get__(obj, objtype)


def b64enc(raw_bytes):
    return base64.b64encode(raw_bytes).decode('ascii')

def b64dec(b64_str):
    return base64.b64decode(b64_str)
