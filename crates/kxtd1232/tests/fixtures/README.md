# Test fixtures (synthetic)

These files are **synthetic**. They were derived from the clean-room RE table spec, not
from any capture or database image. They hold frame headers, acks and rounded timing only.
There are no payload bytes and no ROM id. The sign-on banner and password are placeholders.

| file | source in the RE notes | changes |
|---|---|---|
| `exchanges.jsonl` | `fixtures/exchanges.jsonl` | The verbatim sign-on banner is replaced with `<SIGNON_BANNER>`, and the prompts with the `SignOn` placeholders (`Password:`, `<MODE_START>`). The XON/XOFF capture-timing notes (steps 0, 1, 7) are made generic. |
| `full-upload-headers.jsonl` | `fixtures/full-upload-headers.jsonl` | none (byte-identical) |

The spec they agree with is the RE table spec draft. Never add real
captures (`/workspace/re-sandbox`) or `EMPTY.DBH` content here.
