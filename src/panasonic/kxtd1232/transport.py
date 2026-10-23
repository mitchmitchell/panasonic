"""Transport interface. Phase A ships only in-process transports; serial comes in Phase B."""

from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    def send(self, data: bytes) -> None: ...

    def recv(self, timeout: float) -> bytes:
        """Return available bytes; raise TimeoutError if none arrive within ``timeout``."""
        ...

    def close(self) -> None: ...
