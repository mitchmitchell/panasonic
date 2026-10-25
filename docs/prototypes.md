# A0 prototypes (decision 43)

All run on the box against the in-process simulator with synthetic data. Run
`python -m prototypes.measure` to reproduce the numbers.

| Id | Question | Built | Result | Proposed pick |
|---|---|---|---|---|
| PA | Transport concurrency | (a) blocking `Client` over a `Transport`; (b) `prototypes/pa_async.py`, asyncio over the same sans-I/O `Login` core | Both download the same bytes (test `test_pa_sync_and_async_agree`). (b) is ~48 lines on top of the core. Real-time pacing, XON jitter over 100 logins and Ctrl-C mid-write need a paced sim and serial transport (A2/A5). | (a) for library + CLI; (b) stays a thin add-on |
| PB | Edit API shape | (a) raw `Patch(table, offset, bytes)`; (b) typed `field_patch("cid_name", n, "...")`, both compiled to one `WritePlan` | A 200-case fuzz of typed edits changes 0 bytes outside the target span. Typed edit = 1 line; raw = 1 line plus manual encoding. | (b) for users, (a) as the expert escape hatch |
| PC | Write granularity, one-field edit | (a) changed chunk only; (b) whole table | One caller-ID name in a 50-record synthetic 0x25: (a) 1 frame / 201 wire bytes; (b) 5 frames / 845 bytes, about 1.4 s more with median acks. Only (a) is proven on hardware as a single-chunk write. | (a) |
| Q | Daemon queue model | One worker thread vs one asyncio worker (`prototypes/queue_models.py`) | Both serialize strictly (max 1 running), keep submit order and record failed jobs without stopping. asyncio needs `to_thread` for blocking serial I/O anyway. | Worker thread for `kxprovd` (blocking serial, sans-I/O core); asyncio only in the web/MCP process |

These picks are proposals for Architect's review.
