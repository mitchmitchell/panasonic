# panasonic — kx-provision

Provisioning tool for a Panasonic KX-TD1232 PBX. The production app is Rust; see `docs/prototype.md`
for the Python A0 prototype.

## Workspace (Phase A1)

| crate | what |
|---|---|
| `crates/kxtd1232` | sync sans-I/O protocol core: frames, login/session, typed fields, WritePlan, guarded client |
| `crates/kxtd1232-sim` | simulated PBX with fault injection (virtual time) |
| `crates/kxprov` | thin CLI: `version`, `read`, `plan` (sim transport only in A1) |
| `crates/kxprovd`, `kxprov-api`, `kxprov-web`, `kxprov-mcp`, `kxprov-gw` | layout stubs for later phases |

The only tables you can write are 0x24 and 0x25. Commands 0x0A and 0x10 can't be expressed.
On tables 0x40 and up, record indexes >= Recs are refused.

```
cargo test --workspace
cargo run -p kxprov -- read cid_name --count 3
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.36 -p kxprov
```

All rights reserved; see LICENSE.
