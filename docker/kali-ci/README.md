# KA-096 · Reproducible kali CI profile (`docker/kali-ci`)

A `kalilinux/kali-rolling` Dockerfile whose apt tool set is **fully version-pinned**, so CI batteries run against the same tool versions every time.

- **Image:** `docker/kali-ci/Dockerfile`
- **Lint:** `tests/test_kali_ci_dockerfile.py` (static, offline — no docker build, no network)
- **Tool-set source of truth:** `agentic_ai.agents.cyber.kali.KALI_TOOLS_DB` (52 tools, enumerated read-only on 2026-10-07)

## Why pinned

`kali-rolling` is a continuously updated suite: an unpinned `apt-get install nmap sqlmap` resolves to a *different* version every day. CI batteries must attribute a failure to the code under test, not to silent upstream tool churn — so every package here is pinned with `=<version>` measured from the upstream index. Refresh is an explicit, dated, auditable action (procedure below), never drift.

## Build + run

```bash
docker build -t kali-ci:local docker/kali-ci/
docker run --rm -t kali-ci:local nmap --version
docker run --rm -it kali-ci:local            # interactive shell as the non-root `kali` user
docker run --rm -it --user root --privileged kali-ci:local   # battery needs raw sockets (aircrack-ng, responder, kismet)
```

The image logs in as the non-root user `kali` (uid 1000, workdir `/home/kali/targets`). Elevated batteries opt in per-run with `--user root --privileged`; the default profile stays non-root.

## Pin provenance (measured, not guessed)

- **Fetch date:** 2026-10-07
- **Source:** `https://http.kali.org/kali/dists/kali-rolling/` — `Release` + `main/binary-amd64/Packages.gz` + `non-free/binary-amd64/Packages.gz`
- **Method:** one bounded polite fetch, UA `Mozilla/5.0 (compatible; ka096-aptpin/1.0)`, sequential with gaps
- **Integrity:** both fetched index archives verified byte-for-byte against the `MD5Sum` entries in the `Release` file; `Release` header: `Date: Wed, 07 Oct 2026 18:06:30 UTC`, `Suite: kali-rolling`, Components `main contrib non-free non-free-firmware`
- **Component note:** in the 2026-10-07 snapshot `nmap`, `ncat`, `nikto`, `wpscan` and `maltego` publish into `non-free`; the Dockerfile therefore enables all four components before installing.

## Tool set per phase

Phases = the tool categories of `KALI_TOOLS_DB`. Columns: DB tool → apt package pinned in the image. 48 of the 52 DB tools are apt-mapped; the remaining four are documented as "not packaged" below.

### reconnaissance (10 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| nmap | nmap | 7.99+dfsg-1kali1 |
| masscan | masscan | 2:1.3.2+ds1-2 |
| recon-ng | recon-ng | 5.1.2-2 |
| theHarvester | theharvester | 4.11.1-0kali2 |
| amass | amass | 5.1.1-0kali3 |
| subfinder | subfinder | 2.16.0-0kali1 |
| dnsrecon | dnsrecon | 1.6.0-1 |
| spiderfoot | spiderfoot | 4.0-0kali5 |
| maltego | maltego | 4.13.0-0kali1 |
| shodan | — not packaged | pip/upstream: https://github.com/achillean/shodan-python |

### vulnerability_analysis (3 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| nikto | nikto | 1:2.6.1-0kali1 |
| openvas | gvm-tools | 25.4.6-1 |
| nmap-vuln | nmap (NSE vuln scripts) | 7.99+dfsg-1kali1 |

### web_application (11 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| sqlmap | sqlmap | 1.10.9-1 |
| burpsuite | burpsuite | 2026.8-0kali1 |
| dirb | dirb | 2.22+dfsg-7 |
| gobuster | gobuster | 3.8.2-1 |
| wpscan | wpscan | 4.1.0-0kali1 |
| ffuf | ffuf | 2.2.1-1 |
| joomscan | joomscan | 0.0.7-0kali2 |
| whatweb | whatweb | 0.6.4-1 |
| sslscan | sslscan | 2.1.5-1 |
| testssl | testssl.sh | 3.2.4+dfsg-2 |
| zap_cli | — not packaged | pip/upstream: https://github.com/Grunny/zap-cli |

### password (8 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| john | john | 1.9.0-Jumbo-1+git20211102-0kali11 |
| hashcat | hashcat | 7.1.2+ds1-4 |
| hydra | hydra | 9.7-2 |
| medusa | medusa | 2.3-3 |
| cewl | cewl | 6.2.1-1 |
| crunch | crunch | 3.6-3.1 |
| hash-identifier | hash-identifier | 1.2+git20180314-0kali3 |
| rsmangler | rsmangler | 1.5-0kali3 |

### exploitation (3 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| metasploit | metasploit-framework | 6.5.3-0kali1 |
| searchsploit | exploitdb | 20260904-0kali1 |
| nmap-exploit | nmap (NSE exploit scripts) | 7.99+dfsg-1kali1 |

### post_exploitation (4 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| bloodhound | bloodhound.py | 1.9.0-0kali1 |
| empire | powershell-empire | 6.6.0-0kali1 |
| mimikatz | mimikatz | 2.2.0-git20220919-0kali1 |
| lazagne | — not packaged | upstream: https://github.com/AlessandroZ/LaZagne |

### forensics (4 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| exiftool | libimage-exiftool-perl | 13.55+dfsg-1 |
| foremost | foremost | 1.5.7-12+b1 |
| sleuthkit | sleuthkit ("fls") | 4.14.0+dfsg-0kali1 |
| volatility | — not packaged | upstream: https://github.com/volatilityfoundation/volatility |

### malware (1 tool)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| binwalk | binwalk | 2.4.3+dfsg1-3 |

### sniffing_spoofing (2 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| wireshark | tshark | 4.6.6-1 |
| responder | responder | 3.2.2.0-0kali2 |

### social_engineering (1 tool)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| setoolkit | set | 8.1.3+git20260604-0kali1 |

### wireless (5 tools)

| DB tool | apt package | pinned version |
| --- | --- | --- |
| aircrack-ng | aircrack-ng | 1:1.7+git20230807.4bf83f1a-3 |
| kismet | kismet | 2025.09.R1-0kali3 |
| mdk4 | mdk4 | 4.2-5+b1 |
| reaver | reaver | 1.6.6-2+b1 |
| wifite | wifite | 2.8.2-2 |

### runtime companion

| apt package | pinned version | why |
| --- | --- | --- |
| ncat | 7.99+dfsg-1kali1 | nmap-suite listener/relay used by batteries; installed alongside nmap |

## Not packaged in kali-rolling (4 of 52)

`shodan`, `zap_cli`, `lazagne`, `volatility` have no kali-rolling apt package in the 2026-10-07 snapshot (verified against both fetched indices). Policy: they are **not** installed in-image — no pip network installs, no curl-pipe-bash, no vendored payload blobs. A battery that needs one of them brings the binary via a runtime mount/wheel it controls, or a follow-up task changes this contract explicitly.

## Refresh procedure

1. Re-run the bounded polite index fetch (UA `Mozilla/5.0 (compatible; ka096-aptpin/1.0)`, one request per URL, sequential): the `Release` file and `main`/`non-free` `binary-amd64/Packages.gz` for `kali-rolling` from `https://http.kali.org/kali/dists/kali-rolling/`.
2. Verify the archives against the fresh `Release` `MD5Sum` entries.
3. Measure each pinned package's `Version:` from the index and update `docker/kali-ci/Dockerfile` (pins only — no new tools without a tool-DB task).
4. Update this README: fetch date above and the version columns of every phase table.
5. Run the offline lint: `python3 -m pytest tests/test_kali_ci_dockerfile.py` — expect all green.
6. If the live fetch fails, do **not** pin from memory: document the failure here and pin only apt-version shapes that the tool DB states, marked `unverified` — that is the documented fallback path, and it was not taken for the 2026-10-07 pins (this table is measured).

## Scope

`kali_v2.ENHANCED_KALI_TOOLS_DB` (cloud/AD/container extensions) is deliberately out of scope for this pinned CI image; the profile pins exactly the `KALI_TOOLS_DB` enumeration per phase. The static lint test owns the drift alarm: it pins the per-tool package table as constants and fails loudly if the Dockerfile or README diverges.