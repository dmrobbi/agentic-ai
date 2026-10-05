"""KA-017 tests - evidence hash-chain: the exact digest algebra (each
link = sha256(stored-prev + content) from the genesis anchor), clean
verify, per-entry tamper detection WITHOUT cascade (the precision pin),
forged-digest detection, append immutability, the chain-head anchor,
and the purity scan (hashlib only; no I/O/network/clock/chassis)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.evidence_chain import (
    EvidenceChain,
    EvidenceEntry,
    GENESIS,
    append,
    create_chain,
    verify_chain,
)


def _entry_input(label, content):
    return {"label": label,
            "content": content if isinstance(content, bytes)
            else content.encode("utf-8")}


def test_digest_algebra_from_genesis():
    chain = append(create_chain([]),
                   _entry_input("scan.xml", b"first artifact"),
                   created_at="2026-10-05T01:00:00Z")
    expected = hashlib.sha256(
        GENESIS.encode("utf-8") + b"first artifact").hexdigest()
    assert chain.entries[0].digest == expected
    assert chain.entries[0].created_at == "2026-10-05T01:00:00Z"


def test_verify_clean_multi_entry_chain():
    chain = create_chain([])
    for label in ("01_git.txt", "02_scan.log", "03_audit.txt"):
        chain = append(chain, _entry_input(label, "content:" + label))
    result = verify_chain(chain)
    assert result["ok"] is True
    assert result["breaks"] == []
    assert result["chain_digest"] == chain.entries[-1].digest


def test_tamper_detection_no_cascade():
    chain = create_chain([])
    for label in ("a", "b", "c", "d"):
        chain = append(chain, _entry_input(label, "body-" + label))
    # tamper ONLY entry 1's content (rebuild the chain with new bytes)
    tampered_entries = list(chain.entries)
    tampered_entries[1] = tampered_entries[1].__class__(
        label=tampered_entries[1].label,
        content=b"body-b-TAMPERED",
        prev_digest=tampered_entries[1].prev_digest,
        digest=tampered_entries[1].digest,
        created_at=tampered_entries[1].created_at,
    )
    tampered = EvidenceChain(entries=tuple(tampered_entries),
                             chain_digest=chain.chain_digest)
    result = verify_chain(tampered)
    assert result["ok"] is False
    assert [b["entry"] for b in result["breaks"]] == ["b"]  # NO cascade
    assert result["breaks"][0]["index"] == 1


def test_forged_digest_detected():
    chain = create_chain([])
    chain = append(chain, _entry_input("legit", b"payload"))
    forged_entries = [chain.entries[0].__class__(
        label=chain.entries[0].label,
        content=b"payload",
        prev_digest=chain.entries[0].prev_digest,
        digest="0" * 64,  # forged by an attacker
        created_at=None)]
    forged = EvidenceChain(entries=tuple(forged_entries),
                           chain_digest=chain.chain_digest)
    result = verify_chain(forged)
    assert result["ok"] is False
    assert result["breaks"][0]["entry"] == "legit"


def test_append_immutability():
    chain = create_chain([])
    chain = append(chain, _entry_input("one", b"1"))
    snapshot = chain.entries
    chain2 = append(chain, _entry_input("two", b"2"))
    assert chain.entries == snapshot  # the original untouched
    assert len(chain2.entries) == len(chain.entries) + 1
    assert len(chain.entries) == 1
    assert verify_chain(chain2)["ok"] is True


def test_empty_chain_head_is_genesis():
    chain = create_chain([])
    result = verify_chain(chain)
    assert result["ok"] is True
    assert result["chain_digest"] == GENESIS
    assert chain.chain_digest == GENESIS


def test_input_validation():
    from pytest import raises
    with raises(ValueError):
        append(create_chain([]), {"label": "", "content": b"x"})
    with raises(ValueError):
        append(create_chain([]), {"label": "l", "content": 123})


def test_module_purity_source_scan():
    module = __import__(
        "agentic_ai.agents.cyber.evidence_chain",
        fromlist=["x"])
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket", "utcnow"):
        assert banned not in source, banned
    assert "agentic_ai" not in source  # no chassis import either
