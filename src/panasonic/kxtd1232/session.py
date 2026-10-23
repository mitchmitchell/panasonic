"""Sans-I/O login state machine (handoff §1.2-1.3).

The caller feeds received bytes and sends whatever ``feed`` returns. Timing (sending CR LF
about 5 ms after XON, never inside the XOFF window) belongs to the transport.
"""

from __future__ import annotations

from enum import Enum, auto

XOFF = 0x13
XON = 0x11


class State(Enum):
    WAIT_XON = auto()
    WAIT_PROMPT = auto()
    WAIT_EIA = auto()
    WAIT_ECS_OK = auto()
    WAIT_PRG_OK = auto()
    BINARY = auto()
    FAILED = auto()


class LoginError(RuntimeError):
    pass


class Login:
    def __init__(self, password: str) -> None:
        if not password or "\r" in password or "\n" in password:
            raise ValueError("invalid password")
        self._password = password.encode("ascii")
        self.state = State.WAIT_XON
        self.failure: str | None = None
        self._buf = b""

    def __repr__(self) -> str:  # never expose the password
        return f"Login(state={self.state.name})"

    def feed(self, data: bytes) -> bytes:
        out = b""
        if self.state is State.WAIT_XON:
            idx = data.find(bytes([XON]))
            if idx < 0:
                return b""
            self.state = State.WAIT_PROMPT
            out += b"\r\n"
            data = data[idx + 1 :]
        if self.state in (State.BINARY, State.FAILED):
            return out
        self._buf += data
        while b"\n" in self._buf and self.state not in (State.BINARY, State.FAILED):
            line, self._buf = self._buf.split(b"\n", 1)
            out += self._line(line.strip(b"\r\x00 ").decode("ascii", "replace"))
        return out

    def _fail(self, why: str) -> bytes:
        self.state = State.FAILED
        self.failure = why
        return b""

    def _line(self, line: str) -> bytes:
        if not line:
            return b""
        if line.startswith("NG") or "Another Terminal Connected" in line:
            return self._fail(line)
        s = self.state
        if s is State.WAIT_PROMPT and line == "Enter Password":
            self.state = State.WAIT_EIA
            return self._password + b"\r"
        if s is State.WAIT_EIA:
            if line == "Enter Password":  # re-prompt: wrong-password reply is UNKNOWN (G5)
                return self._fail("password rejected")
            if line == "EIA Mode Start":
                self.state = State.WAIT_ECS_OK
                return b"ECS OF\r\n"
        if s is State.WAIT_ECS_OK and line == "OK":
            self.state = State.WAIT_PRG_OK
            return b"PRG\r\n"
        if s is State.WAIT_PRG_OK and line == "OK":
            self.state = State.BINARY
        return b""
