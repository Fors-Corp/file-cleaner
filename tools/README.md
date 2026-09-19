# tools/

Developer scripts. Nothing here is imported by File Cleaner or installed with it.
All are read-only with respect to your files; run them from the repository root.

| Script | What it is for |
|---|---|
| `safety_differential.py` | Proves a change to the deny-list is never *looser*: old vs new `safety.is_protected` over hundreds of thousands of real paths, adversarial respellings, and the conformance table, cross-checked against an inode-identity oracle. |
| `safety_1_3_0.py` | Frozen copy of `safety.py` as shipped in 1.3.0 — the default "before" for the differential. Known-vulnerable; never imported by the package. |
| `gen_safety_cases.py` | Regenerates `tests/safety_cases.json`, the language-neutral deny-list conformance table. |
| `port_parity.py` | The Rust port's gate (see `docs/PORT.md`). `protected`: `safety.is_protected` vs the Rust deny-list over real paths and respellings — zero differences allowed in either direction. `scan`: `scanner.run_scan` on the pure-Python walker vs the fully native `fclean-walk scan`. `scan-json` / `config-json`: what `fclean scan --json` and `fclean config show --json` print vs the port reading the same config for itself — byte for byte. `pyjson`: the port's JSON writer vs `json.dumps`. `tests/test_port_parity.py` runs the same code on a fixture tree. |
| `bench_scan.py` | Times one read-only scan, reporting wall **and** CPU (user+sys), directories listed, entries seen, and a fingerprint of the candidate list — so "faster" can be told apart from "did less". Calls `scanner.run_scan` directly, so nothing is appended to the audit log. |

```bash
PYTHONPATH=src python tools/bench_scan.py after "~/Library/Application Support"
FCLEAN_NATIVE_WALK=0 PYTHONPATH=src python tools/bench_scan.py python-walker ~
CAP=5000 PYTHONPATH=src python tools/safety_differential.py
PYTHONPATH=src python tools/port_parity.py protected --cap 30000
PYTHONPATH=src python tools/port_parity.py scan ~
PYTHONPATH=src python tools/port_parity.py scan-json ~
PYTHONPATH=src python tools/port_parity.py config-json
```
