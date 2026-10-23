# Test fixtures (synthetic)

These files are **synthetic**. They were derived from the clean-room RE table spec, not
from any capture or database image. They hold frame headers and acks only; no timing.
There are no payload bytes and no ROM id. The sign-on banner and password are placeholders.

| file | source in the RE notes | changes |
|---|---|---|
| `exchanges.jsonl` | `fixtures/exchanges.jsonl` | The verbatim sign-on banner is replaced with `<SIGNON_BANNER>`, and the prompts with the `SignOn` placeholders (`Password:`, `<MODE_START>`). The XON/XOFF capture-timing notes (steps 0, 1, 7) are made generic. |
| `full-upload-headers.jsonl` | generated from the table spec (`TABLES`) | Only the 288 spec-derived header rows remain (table, record, word, payload length, header). The per-frame send and ack timings, the ack bytes and the two trailing pipelined-request rows were removed because they could not be shown to be synthetic. |

The spec they agree with is the RE table spec draft. Never add real
captures (`/workspace/re-sandbox`) or `EMPTY.DBH` content here.
