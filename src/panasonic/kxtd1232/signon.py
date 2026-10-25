"""Text sign-on strings used by the login state machine and the simulator.

Provenance: these are synthetic placeholders, not the PBX's real wording. The exact
banner and prompts are not reproduced in this repo (clean room, decision 74). A real
deployment supplies them from private configuration via ``Login(..., signon=...)``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SignOn:
    banner: str = "<SIGNON_BANNER>"
    password_prompt: str = "Password:"
    mode_start: str = "<MODE_START>"
    in_use: str = "<TERMINAL_IN_USE>"


DEFAULT_SIGNON = SignOn()
