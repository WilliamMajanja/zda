"""Zero-copy buffer views and arena allocation primitives (stdlib only)."""

import array


class Arena:
    """Bump allocator over a pre-allocated byte buffer (arena pattern)."""

    def __init__(self, capacity=1 << 20):
        self.capacity = int(capacity)
        self._buf = bytearray(self.capacity)
        self._pos = 0

    def alloc(self, n):
        n = int(n)
        if n < 0:
            raise ValueError("negative allocation")
        if self._pos + n > self.capacity:
            raise MemoryError("arena exhausted")
        view = memoryview(self._buf)[self._pos : self._pos + n]
        self._pos += n
        return view

    def reset(self):
        self._pos = 0

    @property
    def used(self):
        return self._pos

    @property
    def remaining(self):
        return self.capacity - self._pos


class BufferView:
    """Zero-copy view over bytes-like data with bounds-safe slicing."""

    __slots__ = ("_mv",)

    def __init__(self, data):
        self._mv = memoryview(data) if not isinstance(data, memoryview) else data

    def __len__(self):
        return len(self._mv)

    def slice(self, start=0, end=None):
        if end is None:
            end = len(self._mv)
        start = max(0, min(start, len(self._mv)))
        end = max(start, min(end, len(self._mv)))
        return BufferView(self._mv[start:end])

    def raw(self):
        return bytes(self._mv)

    def memoryview(self):
        return self._mv

    def find(self, needle, start=0):
        needle = needle if isinstance(needle, (bytes, bytearray)) else bytes(needle)
        mv = self._mv
        n = len(needle)
        if n == 0:
            return start if 0 <= start <= len(mv) else -1
        for i in range(max(0, start), len(mv) - n + 1):
            if mv[i : i + n] == needle:
                return i
        return -1

    def split(self, sep):
        sep = sep if isinstance(sep, (bytes, bytearray)) else bytes(sep)
        out = []
        start = 0
        while True:
            idx = self.find(sep, start)
            if idx < 0:
                out.append(self.slice(start).raw())
                break
            out.append(self.slice(start, idx).raw())
            start = idx + len(sep)
        return out

    def decode(self, *a, **kw):
        return self._mv.decode(*a, **kw) if hasattr(self._mv, "decode") else bytes(self._mv).decode(*a, **kw)


def view(data):
    return BufferView(data)


def read_view(path, limit=None):
    with open(path, "rb") as fh:
        data = fh.read(limit) if limit is not None else fh.read()
    return BufferView(data)
