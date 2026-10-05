"""KA-028 - doc-claim matrix: every documented kali claim maps to its
proving test. Pins: the doc carries every claim-row; each claim's
SOURCE-TEXT exists verbatim in the cited file; each tested claim's test
exists in the suite (importlib + getattr); the untested claims are
marked in the doc, not hidden. No network."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CLAIMS_PATH = REPO / "tests" / "fixtures" / "doc_claims.json"
CLAIMS = json.loads(CLAIMS_PATH.read_text(encoding="utf-8"))["claims"]
DOC_PATH = REPO / "docs" / "KA-DOC-CLAIMS.md"

HARDCODED_CLAIMS = None  # the doc is rendered from the FIXTURE (committed)


def test_doc_exists_and_carries_every_claim():
    assert DOC_PATH.is_file()
    doc = DOC_PATH.read_text(encoding="utf-8")
    for row in CLAIMS:
        assert row["claim"] in doc, row["claim"]


@pytest.mark.parametrize("row", CLAIMS, ids=[r["claim"][:40] for r in CLAIMS])
def test_claim_source_text_exists(row):
    source = (REPO / row["source_file"]).read_text(encoding="utf-8")
    assert row["source_text"] in source, row["claim"]


@pytest.mark.parametrize("row", CLAIMS, ids=[r["claim"][:40] for r in CLAIMS])
def test_proving_test_exists(row):
    if not row["tested"]:
        # the untested claims are marked; nothing to prove
        assert row.get("tested_note")
        return
    module_name = row["test_file"].replace("/", ".").removesuffix(".py")
    module = importlib.import_module(module_name)
    if row["test_name"]:
        assert hasattr(module, row["test_name"]), row["claim"]


def test_untested_claims_marked():
    untested = [r for r in CLAIMS if not r["tested"]]
    assert len(untested) == 1  # only the 600+ docstring claim
    assert untested[0]["claim"].startswith("600+")
    doc = DOC_PATH.read_text(encoding="utf-8")
    assert "no - " in doc  # the doc marks it
