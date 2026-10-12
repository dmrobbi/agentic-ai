# Practice: Compare Prompts — SOC detection-report edition

_In-house re-authoring, inspired by alkilicayse87-pixel's exercise gist
`0e5a0d99c943fcd8e9847372b04cc274` (unlicensed — no source prose or code copied; the
exercise arc is credited, every prompt and example below is written fresh for this
fleet). The original practices on a coffee-shop announcement; this edition practices on
the report the agent fleet actually owes its SOC: attempts, scans, and brute forces._

## Setup

Any OpenAI-compatible backend works (the fleet runs litellm + openai-compatible
endpoints; point `MODEL` at whatever your agent runs on):

```python
from openai import OpenAI
from dotenv import load_dotenv, find_dotenv
_ = load_dotenv(find_dotenv())

MODEL = "your-backend-model"   # e.g. a GLM/ollama/openai endpoint via litellm
client = OpenAI()

def get_llm_response(message, system=None):
    response = client.responses.create(
        model=MODEL,
        instructions=system,
        input=message,
    )
    print(response.output_text)
```

Context the agent has to work with (the real fleet surface):

- `soc-audit-mcp` (port 8769): audit stats, per-agent/logs, fleet activity windows
- `soc-tickets-mcp` (port 8768): `list_tickets`, `create_ticket` for findings
- dashboard tool proxy (`/tools/...`): `overview`, `fleet_status`, `tasks_list`,
  `stig_overview`, `compliance_scores_all`, `tickets_list_proxy`
- raw sources: sshd `Failed password` / `Invalid user` lines, kernel `UFW BLOCK` drops

## The task

Get the model to write a **detection report covering logon attempts, scans, and brute
forces against the fleet in the last 24 hours** — an analyst-facing report, not a
vague essay.

## Iteration 1: write a basic prompt

The simplest prompt you can, then note what you like and don't like:

```python
get_llm_response("...")  # your prompt here
```

Typical v1 shape (run it and compare):

```python
get_llm_response("Write a report of brute force attempts.")
```

## Iteration 2: improve it

Write **two more versions**, each better than the last. Try adding:

- A **role** for the model (SOC analyst agent on watch)
- **Context**: which sources to read, the time window, what counts as a
  detection (failed logon, invalid user, port scan, credential stuffing)
- **Format**: report sections, length, table or prose
- **Do's and don'ts** (never invent data; mark unknowns unknown; cite the source per row)

```python
# Version 2: role + context
get_llm_response(
    "Write a report of the logon attempts, scans, and brute forces seen in the "
    "last 24 hours. Pull from the audit MCP (auth failures, invalid users, port "
    "scan indicators) and the ticket queue, then report what you actually see.",
    system="You are the SOC analyst agent on watch for this fleet.",
)
```

## Iteration 3: role + context + format + do's and don'ts

```python
get_llm_response(
    "Cover the last 24 hours from the audit MCP and the ticket queue. Anything "
    "outside that window or these two sources is out of scope.",
    system="""You are the SOC analyst agent on watch. Produce a markdown report
with exactly these sections:
- Executive summary: 3 bullets maximum
- Detection inventory: one table row per detection group
  (time range, host, category: brute-force/scan/logon-attempt, source, target account or port, count, first/last seen)
- Top sources: the 3 loudest origins with hit counts
- Affected accounts and services
- Recommended actions: ticket + blocking candidates only
Rules:
- Every row cites its detection source (audit-mcp / tickets-mcp / sshd / ufw).
- Do not invent IPs, counts, or timestamps; mark unknown values as "unknown".
- No exploit code, no countermeasures beyond tickets and network blocks.
- If a source is unreachable, say so in the summary instead of guessing.
""",
)
```

## Bonus 1: change the audience

Reuse version 3, but change the audience: an **executive brief** (5 lines, no
jargon, no IP addresses) versus an **engineer's runbook** (same report with the raw
command checks). How much of the prompt did you actually change? Usually only the
format block — role and context survive intact.

## Bonus 2: add an example

Add **one example** inventory row in exactly the shape you want (one-shot):

```python
EXAMPLE_ROW = \
  "| 03:12-03:19 | lab-web | brute-force | ssh | 203.0.113.9 | admin/root | 41 hits, last 03:19 |"
```

Does the model's table converge on that row's shape? (It should — format examples
outperform format rules.)

## Demo: run the tuned prompt

A synthetic fixture only (RFC 5737 documentation IPs; the real fleet data is internal
and stays out of the repo). Feed `lab.log`:

```text
Oct 12 03:12:31 lab-web sshd[3311]: Failed password for admin from 203.0.113.9 port 52814 ssh2
Oct 12 03:12:44 lab-web sshd[3311]: Failed password for admin from 203.0.113.9 port 52822 ssh2
Oct 12 03:13:02 lab-web sshd[3312]: Failed password for root  from 203.0.113.9 port 52831 ssh2
Oct 12 03:19:58 lab-web sshd[3316]: Failed password for root  from 203.0.113.9 port 52902 ssh2
Oct 12 04:02:11 lab-web sshd[3319]: Invalid user postgres from 198.51.100.7 port 33012
Oct 12 04:02:49 lab-web sshd[3319]: Invalid user test    from 198.51.100.7 port 33044
Oct 12 04:44:09 lab-db  kernel: UFW BLOCK SRC=203.0.113.9 DPT=445 SYN
Oct 12 04:44:15 lab-db  kernel: UFW BLOCK SRC=203.0.113.9 DPT=1433 SYN
Oct 12 04:46:20 lab-db  kernel: UFW BLOCK SRC=203.0.113.9 DPT=22   SYN
Oct 12 06:15:07 lab-web sshd[3344]: Accepted password for deploy from 203.0.113.44 port 55102  (known CI runner)
Oct 12 09:01:44 lab-web sshd[3401]: 7 more failed attempts from 192.0.2.66 (admin, root)
```

Version-3 output (example of what a good run produces):

```markdown
## Executive summary
- Sustained SSH brute-force against lab-web `admin`/`root` from 203.0.113.9
  (41 attempts, 03:12-03:19, source: audit-mcp/sshd).
- Same source followed with a service scan on lab-db (445, 1433, then 22;
  source: audit-mcp/ufw).
- Account-enumeration sweep from 198.51.100.7 (postgres/test), low volume;
  plus a later 7-attempt probe from 192.0.2.66. One accepted logon in-window
  attributed to the known CI runner (203.0.113.44) — no anomaly raised.

## Detection inventory
| time range | host | category | source ip | target | count | source |
|---|---|---|---|---|---|---|
| 03:12-03:19 | lab-web | brute-force | 203.0.113.9 | admin/root (ssh) | 41 | audit-mcp/sshd |
| 04:44-04:46 | lab-db | service scan | 203.0.113.9 | 445, 1433, 22 | 3 | audit-mcp/ufw |
| 04:02-04:02 | lab-web | logon-attempt | 198.51.100.7 | invalid users: postgres, test | 2 | audit-mcp/sshd |
| 09:01-09:01 | lab-web | brute-force | 192.0.2.66 | admin/root (ssh) | 7 | audit-mcp/sshd |

## Top sources
| origin | hits | pattern |
|---|---|---|
| 203.0.113.9 | 44 | credential brute + service scan across two hosts |
| 192.0.2.66  | 7  | one short ssh burst |
| 198.51.100.7 | 2 | user enumeration, no password attempts |

## Affected accounts and services
- ssh on lab-web (admin, root); smb/ms-sql surfaces on lab-db (firewall-blocked)

## Recommended actions
1. Ticket: create — brute-force campaign vs lab-web (evidence: rows above)
2. Blocking candidate: 203.0.113.9 at the edge (verify before applying)
3. No exploit/countermeasure detail: policy — this report stops at tickets and blocks
```

## What to notice

- v1 gives the *topic*; v2 gives the *scope*; v3 gives the *accountability* (sources
  cited per row, unknowns marked, fixed section shape). The demo report is only as
  trustworthy as the rules that forbid invention.
- One-shot rows (Bonus 2) outperform adjectives: "professional" is unverifiable,
  a sample row is checkable.
- Audience swaps (Bonus 1) are mostly format-block edits — role and context carry over.
- Fleet tie-in: this same prompt shape is what turns the `/tools/*` proxy responses
  (audit stats, ticket queue) into the daily SOC report the dashboard's taskbar and
  tickets pane assume.
- House pin: reporting exercises stay report-side. No payloads, no evasion detail —
  the output contract above already forbids them.