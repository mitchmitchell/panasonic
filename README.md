# panasonic

Provisioning tools for a Panasonic KX-TD1232 PBX (project **kx-provision**):

- `panasonic.kxtd1232`: protocol library (frame codec, login/session state machine, table reads, write-plan encoding) and CLI
- `panasonic.sim`: in-process PBX simulator with fault hooks (synthetic data only)
- `kxprovision`: daemon, web UI and MCP server (later phases)

Phase A runs only against the simulator. Nothing in this repo talks to real hardware by default.

## Clean room
Built only from behavior-level specifications. The repo contains no vendor code, binaries,
manuals, factory databases or captures. Test fixtures are synthetic.

## Development
```
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest && ruff check . && ruff format --check .
```
