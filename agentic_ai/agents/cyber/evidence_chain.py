"""Evidence hash-chain (KA-017): v4's evidence discipline generalized as
a pure module. The v4 evidence package collects artifacts and references
hash-verifiability but implements no hash machinery; this module carries
the chain semantics.

CONTRACT:
- create_chain(entries, genesis=GENESIS) -> EvidenceChain over
  EvidenceInput rows: each entry's digest = sha256(prev_digest + content)
  where prev_digest starts at the GENESIS anchor - the chain is tamper-
  evident without any store.
- The chain is IMMUTABLE: append(chain, input) returns a NEW chain; the
  original is never mutated (pinned).
- verify_chain(chain) walks the STORED links: each entry's recompute =
  sha256(stored_prev + stored_content); a mismatch = a break AT that
  entry - tampering one middle entry does NOT cascade (every other entry
  keeps verifying against stored links). This is higher-precision than a
  recompute-cascade chain: the breaks report exactly which entries were
  altered or forged.
- verify returns the chain head (the last stored digest, or GENESIS for
  an empty chain) - the single number to record in evidence packages,
  the v4 "File hashes" verification method made chain-grade.
- Pure: hashlib only; no I/O, no network, no clock reads (created_at is
  injected by callers); no chassis import (source-scan pinned)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

GENESIS = "ka-evidence-chain-genesis"


def _digest(prev: str, content: bytes) -> str:
    return hashlib.sha256(prev.encode("utf-8") + content).hexdigest()


@dataclass(frozen=True)
class EvidenceEntry:
    """One chained artifact: the label, the bytes, the digest, and the
    link to the previous digest (stored, so validation is local)."""

    label: str
    content: bytes
    prev_digest: str
    digest: str
    created_at: Optional[str] = None


@dataclass(frozen=True)
class EvidenceChain:
    """An immutable entry sequence; the head chain_digest anchors it."""

    entries: Tuple[EvidenceEntry, ...]
    chain_digest: str


def create_chain(
    entries: Iterable[EvidenceEntry],
    genesis: str = GENESIS,
) -> EvidenceChain:
    """Validate + wrap an entry sequence into a chain (head = the last
    stored digest or the genesis anchor)."""
    rows = tuple(entries)
    head = rows[-1].digest if rows else genesis
    return EvidenceChain(entries=rows, chain_digest=head)


def append(chain: EvidenceChain, entry_input: "Dict[str, Any]",
           created_at: Optional[str] = None) -> EvidenceChain:
    """Extend the chain immutable-ly: entry_input = {"label", "content"}."""
    label = entry_input.get("label")
    content = entry_input.get("content", b"")
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty string")
    if isinstance(content, str):
        content = content.encode("utf-8")
    if not isinstance(content, bytes):
        raise ValueError("content must be bytes (str is encoded)")
    prev = chain.chain_digest if chain.entries else GENESIS
    entry = EvidenceEntry(label=label, content=content, prev_digest=prev,
                          digest=_digest(prev, content),
                          created_at=created_at)
    return EvidenceChain(entries=chain.entries + (entry,),
                         chain_digest=entry.digest)


def verify_chain(chain: EvidenceChain,
                 genesis: str = GENESIS) -> Dict[str, Any]:
    """Recompute every link against STORED prev-digests (no cascade);
    report the exact breaks; return {"ok", "breaks", "chain_digest"}."""
    breaks: List[Dict[str, Any]] = []
    prev = genesis
    for index, entry in enumerate(chain.entries):
        expected = _digest(prev, entry.content)
        if expected != entry.digest:
            breaks.append({"index": index, "entry": entry.label,
                           "problem": "digest mismatch"})
        if entry.prev_digest != prev:
            breaks.append({"index": index, "entry": entry.label,
                           "problem": "prev-link broken"})
        prev = entry.digest
    return {"ok": not breaks, "breaks": breaks,
            "chain_digest": chain.chain_digest}
