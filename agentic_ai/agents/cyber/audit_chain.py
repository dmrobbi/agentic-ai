r"""Agent audit log chain (KA-057): a pure, tamper-evident hash chain over
the agent's OWN audit-event records - the durable "what did the agent do
and decide" stream. Collision-avoidance sibling: KA-017's evidence_chain
chains engagement EVIDENCE entries (artifact bytes inside an evidence
package directory); THIS module chains structured audit EVENTS - two
roles, two chains - and shares no code or import with it by design.

CONTRACT:
- A record is a dict with exactly: {"seq": int, "ts": iso8601 str,
  "event": str, "payload": dict, "prev_hash": str, "hash": str}.
- CANONICAL FORM (serialization determinism pinned exactly):
    canonical(obj) = json.dumps(obj, sort_keys=True,
      separators=(",", ":"), ensure_ascii=True, allow_nan=False)
  sorted keys, compact separators, non-ASCII escaped to \uXXXX,
  NaN/Infinity rejected (ValueError).
- Hash algebra (each record binds its predecessor to its content):
    hash = sha256( (prev_hash + canonical(
        {"seq": .., "ts": .., "event": .., "payload": ..})).encode(
        "utf-8") ).hexdigest()
  prev_hash participates as the concat prefix and as the stored link
  field; the hashed core is exactly the four content keys. The first
  record's prev_hash is GENESIS; a custom anchor passes through
  append/verify via the `genesis` parameter.
- Seams (injected; no wall clock, no file I/O, no exec or network -
  source-scan pinned): append(...) takes the `now` datetime for THIS
  record (tz-ness is the caller's contract; ts = now.isoformat(),
  untouched) and the `sink` callable that owns ALL durability - it
  receives each fully formed record exactly once, e.g. a caller-side
  jsonl writer appending one canonical(record) text line per event. A
  validation failure raises before the sink is called; a sink failure
  propagates and aborts the extension (nothing is committed).
- verify(records, genesis=GENESIS) re-derives the chain over ANY
  iterable of record dicts (parsed jsonl included), checking seq
  contiguity, prev-link integrity, and hash integrity per record
  WITHOUT cascade, returning {"ok": bool,
  "breaks": [{"index", "problem"}...], "head"}:
  a payload/ts/event tamper flags only that record; a deletion flags
  its successor; a consistent mid-chain rewrite flags the successor's
  prev-link. head = the last usable stored digest (or genesis) - the
  single value to pin externally, since a whole-chain re-mine verifies
  clean but cannot forge a pinned head.
- from_records rehydrates the in-memory mirror from stored records
  (verify first; it checks nothing), so an agent restarts its audit log
  and keeps appending on the same chain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

GENESIS = "ka-audit-chain-genesis"

RECORD_KEYS = ("seq", "ts", "event", "payload", "prev_hash", "hash")
CONTENT_KEYS = ("seq", "ts", "event", "payload")


def canonical(obj: Any) -> str:
    """The canonical serialization (pinned): sorted keys, compact
    separators, non-ASCII escaped, NaN and Infinity rejected."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _content(record: Dict[str, Any]) -> Dict[str, Any]:
    """The exact four keys a digest binds (a missing key hashes as null)."""
    return {key: record.get(key) for key in CONTENT_KEYS}


def _digest(prev_hash: str, record: Dict[str, Any]) -> str:
    """sha256 over (previous digest + canonical content), one UTF-8 encode."""
    return hashlib.sha256(
        (prev_hash + canonical(_content(record))).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class AuditChain:
    """The chain's authoritative in-memory mirror: fully formed record
    dicts in order plus the head digest (the last stored hash, or the
    genesis anchor for an empty chain). Extension returns a NEW chain."""

    records: Tuple[Dict[str, Any], ...]
    head: str


def genesis_chain(genesis: str = GENESIS) -> AuditChain:
    """An empty chain anchored at the genesis digest."""
    return AuditChain(records=(), head=genesis)


def from_records(records: Iterable[Dict[str, Any]],
                 genesis: str = GENESIS) -> AuditChain:
    """Rehydrate the in-memory mirror from stored records (call verify
    first - this rehydrator checks nothing; head = the last usable
    stored digest, else the anchor)."""
    rows = tuple(records)
    head = genesis
    for row in rows:
        stored = row.get("hash") if isinstance(row, dict) else None
        if isinstance(stored, str):
            head = stored
    return AuditChain(records=rows, head=head)


def append(chain: AuditChain,
           event: str,
           payload: Optional[Dict[str, Any]] = None,
           *,
           now: datetime,
           sink: Callable[[Dict[str, Any]], Any],
           genesis: str = GENESIS) -> AuditChain:
    """Build the next audit record from the injected clock and commit it
    through the injected sink.

    - `now` (datetime, required): this record's timestamp; stored as
      now.isoformat() with tz-ness untouched.
    - `payload` (dict or None): None normalizes to {}; values must
      survive canonical() or the error propagates before the sink runs;
      stored by shallow copy - treat recorded payloads as frozen.
    - `sink` (required callable): receives the fully formed record dict
      exactly once (signature append(record)); the sink failure
      propagates and the extension aborts.
    - `genesis`: the anchor for a chain's first record (default GENESIS).

    Returns the NEW chain (original immutable)."""
    if not isinstance(event, str) or not event.strip():
        raise ValueError("event must be a non-empty string")
    if payload is None:
        stored_payload: Dict[str, Any] = {}
    elif isinstance(payload, dict):
        stored_payload = dict(payload)
    else:
        raise ValueError("payload must be a dict or None")
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if not callable(sink):
        raise TypeError("sink must be a callable")

    record: Dict[str, Any] = {
        "seq": len(chain.records),
        "ts": now.isoformat(),
        "event": event,
        "payload": stored_payload,
        "prev_hash": chain.head,
    }
    record["hash"] = _digest(record["prev_hash"], record)
    sink(record)
    return AuditChain(records=chain.records + (record,),
                      head=record["hash"])


def verify(records: Iterable[Dict[str, Any]],
           genesis: str = GENESIS) -> Dict[str, Any]:
    """Re-derive the chain over an iterable of record dicts and return
    {"ok", "breaks", "head"} per the module contract (no cascade;
    breaks localize the exact positions; head anchors externally)."""
    rows = tuple(records)
    breaks: List[Dict[str, Any]] = []
    prev = genesis
    head = genesis
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            breaks.append({"index": index,
                           "problem": "record is not an object"})
            continue
        if row.get("seq") != index:
            breaks.append({"index": index,
                           "problem": "seq out of sequence"})
        if row.get("prev_hash") != prev:
            breaks.append({"index": index,
                           "problem": "prev-link broken"})
        stored_hash = row.get("hash")
        if _digest(prev, row) != stored_hash:
            breaks.append({"index": index,
                           "problem": "hash mismatch"})
        if isinstance(stored_hash, str):
            prev = stored_hash
            head = stored_hash
        # a non-string stored hash cannot anchor its successor; the walk
        # keeps the last usable digest, so the successor's own link check
        # reports the discontinuity at its exact index
    return {"ok": not breaks, "breaks": breaks, "head": head}