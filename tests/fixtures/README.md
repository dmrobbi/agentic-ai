# tests/fixtures - shared layout (KA-F02)

One canonical fixture layout so `KA-*` builders never invent paths. Each dir
has a contract; a fixture belongs in exactly one.

| dir | contents | first consuming tasks |
|-----|----------|----------------------|
| `parsers/` | recorded parser outputs (nmap XML, sqlmap, nuclei, crackmapexec, msfrpc; `versioned/` for schema evolution) | KA-003, KA-004, KA-011, KA-027 |
| `scans/` | scan-to-plan corpora; kevstig `coverage.json` API-shape snapshots | KA-002, KA-022, KA-067 |
| `cve/` | CVE eval corpora: cve id -> expected exploit / metasploit module / reliability, `null` = out-of-DB | KA-001, KA-010 |
| `guard_corpus/` | hostile-input lists (control chars, unicode, shell tricks, nulls, oversize, nested quotes) | KA-008, KA-020 |
| `findings/` | findings -> remediation corpora (YAML/JSON) | KA-018, KA-066 |

Rules:

- Committed files only - tests hit no network; live-refresh variants live in
  scripts and are opt-in/nightly-gated, never in fixtures.
- snake_case filenames; JSON or YAML per the consuming op's shape; every
  fixture's schema is pinned by the consuming task's tests.
- Synthetic-but-realistic is fine; the consuming test's docstring records
  provenance (what it models, which task pins it).
- No credentials, no secrets, no payload strings - the catalog payload
  policy applies to fixtures.
- `.gitkeep` placeholders stay until the task populating that dir lands;
  that task removes or keeps them with its own files. Adding a dir = a
  `todo.md` task, not a drive-by.
