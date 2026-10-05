"""KA-001 - CVE-matching eval corpus: pin CVEMatchingEngine.match_cve
against the committed real-CVE corpus; no network; schema-checked; and a
TWO-DIRECTIONAL pin against the live CVE_EXPLOIT_DB - adding, removing, or
editing a DB row without updating the corpus fails loudly here."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali_v2 import CVE_EXPLOIT_DB, CVEMatchingEngine

CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "cve" / "cve_eval_corpus.json"
)

CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
KNOWN = CORPUS["known"]
EDGE = CORPUS["edge"]
OUT_OF_DB = CORPUS["out_of_db"]

KNOWN_FIELDS = (
    "exploit_name", "exploit_db_id", "metasploit_module", "reliability",
    "rank", "disclosure_date", "platform", "port", "description",
)


def test_corpus_shape_and_minimum_size():
    assert set(CORPUS) == {"meta", "known", "edge", "out_of_db"}
    assert CORPUS["meta"]["size_at_curation"] == len(CVE_EXPLOIT_DB)
    total = len(KNOWN) + len(EDGE) + len(OUT_OF_DB)
    assert total >= 80, total  # the acceptance: 80+ corpus entries
    for entry in KNOWN:
        assert set(entry) == {"cve", *KNOWN_FIELDS}
        assert re.fullmatch(r"CVE-\d{4}-\d+", entry["cve"])
    for entry in EDGE:
        assert set(entry) >= {"raw", "outcome", "class"}
        assert entry["outcome"] in ("found", "null")
        if entry["outcome"] == "found":
            assert "expect_cve" in entry
    for entry in OUT_OF_DB:
        assert "cve" in entry
        assert re.fullmatch(r"CVE-\d{4}-\d+", entry["cve"])
        assert not (set(entry) & set(KNOWN_FIELDS))


def test_corpus_matches_live_db_both_directions():
    known = {e["cve"]: e for e in KNOWN}
    assert len(known) == len(KNOWN), "duplicate cve ids in the corpus"
    for cve, exp in known.items():
        row = CVE_EXPLOIT_DB.get(cve)
        assert row is not None, cve
        for field in KNOWN_FIELDS:
            assert getattr(row, field) == exp[field], (cve, field)
    assert set(CVE_EXPLOIT_DB) == set(known)


@pytest.mark.parametrize("entry", KNOWN, ids=[e["cve"] for e in KNOWN])
def test_known_cve_returns_exact_row(entry):
    engine = CVEMatchingEngine()
    match = engine.match_cve(entry["cve"])
    assert match is not None
    assert match.cve_id == entry["cve"]
    assert match is CVE_EXPLOIT_DB[entry["cve"]]  # identity: the same object
    for field in KNOWN_FIELDS:
        assert getattr(match, field) == entry[field], field


@pytest.mark.parametrize(
    "entry",
    EDGE,
    ids=["{}:{}".format(e["class"], e["raw"][:18]) for e in EDGE],
)
def test_edge_shaped_inputs(entry):
    engine = CVEMatchingEngine()
    match = engine.match_cve(entry["raw"])
    if entry["outcome"] == "found":
        assert match is CVE_EXPLOIT_DB[entry["expect_cve"]]
    else:
        assert match is None


@pytest.mark.parametrize(
    "entry",
    OUT_OF_DB,
    ids=[e["cve"] for e in OUT_OF_DB],
)
def test_out_of_db_real_cves_return_none(entry):
    engine = CVEMatchingEngine()
    assert engine.match_cve(entry["cve"]) is None
    assert engine.match_cve(entry["cve"].lower()) is None
