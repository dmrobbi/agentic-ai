"""KA-057 tests - agent audit log chain: the exact canonical form (string
pin + independently computed golden digest), genesis linkage, chaining
across appends with an injected clock, immutable extension, injected-sink
discipline (no commit on validation failure or sink raise), ts pass
through, verify's exact-break precision (payload/ts/event tamper, seq
tamper, deletion, reorder, consistent mid-chain rewrite, missing-hash
rows, non-object rows) WITHOUT cascade, a caller-side jsonl durability
round trip on tmp_path, rehydration + continuation, and the module
purity source-scan. No network."""
from __future__ import annotations

import hashlib
import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.audit_chain import (
    GENESIS,
    RECORD_KEYS,
    AuditChain,
    append,
    canonical,
    from_records,
    genesis_chain,
    verify,
)

UTC = timezone.utc
BASE = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)  # arbitrary fixed clock
NO_SINK = lambda _record: None  # noqa: E731 - explicit discard sink


def _build(count, genesis=GENESIS):
    """A chain of `count` records with an advancing injected clock."""
    chain = genesis_chain(genesis)
    for i in range(count):
        chain = append(chain, f"e.{i}", {"i": i},
                       now=BASE + timedelta(seconds=i), sink=NO_SINK,
                       genesis=genesis)
    return chain


def test_first_record_contract_and_genesis_link():
    sink = []
    chain = append(genesis_chain(), "engagement.started",
                   {"engagement_id": "ENG-1", "level": 3},
                   now=BASE, sink=sink.append)
    (record,) = chain.records
    assert sink == [record]  # the injected sink received the record itself
    assert sorted(record.keys()) == sorted(RECORD_KEYS)
    assert record["seq"] == 0
    assert record["ts"] == BASE.isoformat()
    assert record["event"] == "engagement.started"
    assert record["payload"] == {"engagement_id": "ENG-1", "level": 3}
    assert record["prev_hash"] == GENESIS
    assert chain.head == record["hash"]


def test_append_links_prior_hash_chain_wide():
    chain = _build(4)
    records = chain.records
    assert records[0]["prev_hash"] == GENESIS
    for prev_record, record in zip(records, records[1:]):
        assert record["prev_hash"] == prev_record["hash"]
        assert record["seq"] == prev_record["seq"] + 1
    assert chain.head == records[-1]["hash"]
    assert [r["ts"] for r in records] == [
        (BASE + timedelta(seconds=i)).isoformat() for i in range(4)]


def test_golden_digest_pins_canonical_algebra():
    payload = {"engagement_id": "ENG-9", "tool": "nmap"}
    chain = append(genesis_chain(), "recon.scoped", payload,
                   now=BASE, sink=NO_SINK)
    record = chain.records[0]
    core = {"seq": 0, "ts": BASE.isoformat(), "event": "recon.scoped",
            "payload": payload}
    expected = hashlib.sha256(
        (GENESIS + json.dumps(core, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=True,
                              allow_nan=False)).encode("utf-8")).hexdigest()
    assert record["hash"] == expected


def test_canonical_form_exact_string_pin():
    assert canonical({"b": 1, "a": "caf\u00e9"}) == '{"a":"caf\\u00e9","b":1}'
    assert canonical({"event": "e", "seq": 0}) == '{"event":"e","seq":0}'


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -float("inf")])
def test_canonical_rejects_non_finite_numbers(bad):
    with pytest.raises(ValueError):
        canonical({"x": bad})


def test_payload_key_order_does_not_change_digest():
    one = append(genesis_chain(), "e", {"k1": "v1", "k2": {"x": 1, "y": 2}},
                 now=BASE, sink=NO_SINK)
    two = append(genesis_chain(), "e", {"k2": {"y": 2, "x": 1}, "k1": "v1"},
                 now=BASE, sink=NO_SINK)
    assert one.records[0]["hash"] == two.records[0]["hash"]
    assert one.records[0] == two.records[0]


def test_payload_none_normalizes_to_empty_dict():
    chain = append(genesis_chain(), "note", None, now=BASE, sink=NO_SINK)
    assert chain.records[0]["payload"] == {}


def test_stored_payload_is_a_copy_of_the_callers_dict():
    payload = {"k": "v"}
    chain = append(genesis_chain(), "e", payload, now=BASE, sink=NO_SINK)
    payload["k"] = "MUTATED"
    assert chain.records[0]["payload"] == {"k": "v"}


@pytest.mark.parametrize("bad_event", ["", "   ", 7, None])
def test_event_must_be_non_empty_string(bad_event):
    with pytest.raises(ValueError):
        append(genesis_chain(), bad_event, {}, now=BASE, sink=NO_SINK)


@pytest.mark.parametrize("bad_payload", ["x", 5, ["list"], ("t",)])
def test_payload_must_be_dict_or_none(bad_payload):
    with pytest.raises(ValueError):
        append(genesis_chain(), "e", bad_payload, now=BASE, sink=NO_SINK)


@pytest.mark.parametrize("bad_now", ["2026-10-05", 0, None])
def test_injected_now_must_be_datetime(bad_now):
    with pytest.raises(TypeError):
        append(genesis_chain(), "e", {}, now=bad_now, sink=NO_SINK)


def test_sink_must_be_callable():
    with pytest.raises(TypeError):
        append(genesis_chain(), "e", {}, now=BASE, sink="not-callable")


def test_validation_failure_commits_nothing_and_skips_sink():
    sink = []
    chain = genesis_chain()
    with pytest.raises(ValueError):
        append(chain, "e", "not-a-dict", now=BASE, sink=sink.append)
    assert sink == []
    assert chain.records == () and chain.head == GENESIS


def test_unserializable_payload_fails_before_sink():
    sink = []
    chain = genesis_chain()
    with pytest.raises(TypeError):  # a datetime value never serializes
        append(chain, "e", {"at": BASE}, now=BASE, sink=sink.append)
    with pytest.raises(TypeError):  # mixed str/int keys never serialize
        append(chain, "e", {"a": 1, 2: "mixed"}, now=BASE, sink=sink.append)
    with pytest.raises(ValueError):  # NaN payload rejected by canonical
        append(chain, "e", {"reading": float("nan")}, now=BASE,
               sink=sink.append)
    assert sink == []
    assert chain.records == () and chain.head == GENESIS


def test_sink_failure_aborts_the_extension():
    good = []
    chain = append(genesis_chain(), "e.one", {}, now=BASE, sink=good.append)

    def failing(_record):
        raise RuntimeError("disk full")

    with pytest.raises(RuntimeError):
        append(chain, "e.two", {}, now=BASE + timedelta(seconds=1),
               sink=failing)
    assert [r["event"] for r in good] == ["e.one"]  # e.two never committed
    assert len(chain.records) == 1
    assert chain.head == chain.records[0]["hash"]


def test_extension_is_immutable():
    chain = _build(1)
    snapshot = (chain.records, chain.head)
    chain2 = append(chain, "e.next", {}, now=BASE + timedelta(seconds=5),
                    sink=NO_SINK)
    assert (chain.records, chain.head) == snapshot
    assert chain.head == chain.records[0]["hash"]  # original head never moved
    assert len(chain.records) == 1 and len(chain2.records) == 2
    assert verify(chain2.records)["ok"] is True


def test_ts_passes_injected_datetime_through_untouched():
    naive = datetime(2026, 10, 5, 12, 0, 0)
    r_naive = append(genesis_chain(), "e", {}, now=naive,
                     sink=NO_SINK).records[0]
    r_aware = append(genesis_chain(), "e", {}, now=BASE,
                     sink=NO_SINK).records[0]
    assert r_naive["ts"] == "2026-10-05T12:00:00"
    assert r_aware["ts"] == "2026-10-05T12:00:00+00:00"


def test_verify_clean_chain_and_head():
    chain = _build(3)
    result = verify(list(chain.records))
    assert result == {"ok": True, "breaks": [], "head": chain.head}
    assert verify(r for r in chain.records) == result  # any iterable


def test_verify_empty_stream_is_ok_at_genesis():
    assert verify([]) == {"ok": True, "breaks": [], "head": GENESIS}


@pytest.mark.parametrize("field,value", [
    ("payload", {"i": "rewritten"}),
    ("ts", "2020-01-01T00:00:00+00:00"),
    ("event", "e.rewritten"),
])
def test_verify_localizes_content_tamper_without_cascade(field, value):
    chain = _build(4)
    tampered = [dict(r) for r in chain.records]
    tampered[1][field] = value
    result = verify(tampered)
    assert result["ok"] is False
    assert result["breaks"] == [{"index": 1, "problem": "hash mismatch"}]


def test_verify_localizes_seq_tamper():
    chain = _build(2)
    tampered = [dict(r) for r in chain.records]
    tampered[0]["seq"] = 5
    result = verify(tampered)
    assert result["ok"] is False
    assert result["breaks"] == [
        {"index": 0, "problem": "seq out of sequence"},
        {"index": 0, "problem": "hash mismatch"},
    ]


def test_verify_flags_deleted_record_at_its_successor():
    chain = _build(3)
    result = verify([chain.records[0], chain.records[2]])
    assert result["ok"] is False
    assert {b["index"] for b in result["breaks"]} == {1}  # deletion flags
    # its successor with every check: the position is exact even though
    # seq, prev-link, and hash all fail there at once
    assert {b["problem"] for b in result["breaks"]} == {
        "seq out of sequence", "prev-link broken", "hash mismatch"}


def test_verify_flags_reordering():
    chain = _build(3)
    result = verify([chain.records[0], chain.records[2], chain.records[1]])
    assert result["ok"] is False
    assert {b["index"] for b in result["breaks"]} == {1, 2}
    assert len(result["breaks"]) == 6  # each swapped position fails all three checks


def test_verify_catches_midchain_rewrite_at_successor_link():
    chain = _build(3)
    # attacker rewrites record 1's payload and re-mines ONLY its hash,
    # reusing the honest module itself; record 1 then verifies clean and
    # the discontinuity surfaces exactly at the successor's link
    side = append(genesis_chain(), "e.0", {"i": 0}, now=BASE, sink=NO_SINK)
    assert side.records[0]["hash"] == chain.records[0]["hash"]
    side = append(side, "e.1", {"i": "rewritten"},
                  now=BASE + timedelta(seconds=1), sink=NO_SINK)
    forged = [chain.records[0], side.records[1], chain.records[2]]
    result = verify(forged)
    assert result["ok"] is False
    assert result["head"] == chain.head  # the honest pinned tail survives
    assert result["breaks"] == [
        {"index": 2, "problem": "prev-link broken"},
        {"index": 2, "problem": "hash mismatch"},
    ]


def test_verify_tampered_prev_hash_field_flags_link_only():
    chain = _build(3)
    tampered = [dict(r) for r in chain.records]
    tampered[1]["prev_hash"] = "f" * 64
    result = verify(tampered)
    assert result["breaks"] == [{"index": 1, "problem": "prev-link broken"}]


def test_verify_survives_missing_hash_row_without_crash():
    chain = _build(3)
    damaged = [dict(r) for r in chain.records]
    del damaged[1]["hash"]
    result = verify(damaged)
    assert result["ok"] is False
    assert {b["index"] for b in result["breaks"]} == {1, 2}
    problems = {(b["index"], b["problem"]) for b in result["breaks"]}
    assert (1, "hash mismatch") in problems
    assert (2, "prev-link broken") in problems


def test_verify_reports_non_object_rows():
    chain = _build(2)
    result = verify([chain.records[0], "corrupt-line"])
    assert result["ok"] is False
    assert result["breaks"] == [{"index": 1,
                                 "problem": "record is not an object"}]
    assert result["head"] == chain.records[0]["hash"]


def test_genesis_override_round_trip():
    anchor = "custom-genesis-anchor"
    chain = genesis_chain(anchor)
    for i in range(2):
        chain = append(chain, f"e.{i}", {"i": i},
                       now=BASE + timedelta(seconds=i), sink=NO_SINK,
                       genesis=anchor)
    assert chain.records[0]["prev_hash"] == anchor
    assert verify(chain.records, genesis=anchor)["ok"] is True
    assert verify(chain.records)["ok"] is False  # wrong anchor = hard fail


def _write_jsonl(tmp_path, count):
    path = tmp_path / "agent_audit.jsonl"
    chain = _build(count)
    with path.open("w", encoding="utf-8") as handle:
        def sink(record):  # caller-side durability wrapper
            handle.write(canonical(record) + "\n")
        for record in chain.records:
            sink(record)
    return path, chain


def test_jsonl_durability_round_trip_via_caller_sink(tmp_path):
    path, chain = _write_jsonl(tmp_path, 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for line, record in zip(lines, chain.records):
        assert line == canonical(record)  # the pinned durable line form
        assert isinstance(json.loads(line), dict)
    stored = [json.loads(line) for line in lines]
    result = verify(stored)
    assert result == {"ok": True, "breaks": [], "head": chain.head}
    assert len(path.read_text(encoding="utf-8").splitlines()) == 3


def test_jsonl_tamper_detected_at_exact_line(tmp_path):
    path, _chain = _write_jsonl(tmp_path, 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[1])
    doctored["payload"]["i"] = "covered-up"
    lines[1] = canonical(doctored)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stored = [json.loads(line)
              for line in path.read_text(encoding="utf-8").splitlines()]
    result = verify(stored)
    assert result["ok"] is False
    assert result["breaks"] == [{"index": 1, "problem": "hash mismatch"}]


def test_rehydrate_and_continue_appending_across_restart():
    chain = _build(3)
    stored = list(chain.records)
    assert verify(stored)["ok"] is True
    revived = from_records(stored)
    assert revived == AuditChain(records=tuple(stored), head=chain.head)
    sink = []
    continued = append(revived, "e.3", {"resumed": True},
                       now=BASE + timedelta(seconds=3), sink=sink.append)
    assert sink == [continued.records[-1]]
    assert continued.records[3]["seq"] == 3
    assert continued.records[3]["prev_hash"] == chain.head
    assert verify(list(continued.records))["ok"] is True


def test_from_records_head_walks_to_last_usable_digest():
    assert from_records([]).head == GENESIS
    chain = _build(2)
    damaged = [dict(r) for r in chain.records]
    del damaged[-1]["hash"]
    assert from_records(damaged).head == chain.records[0]["hash"]


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.audit_chain")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "exec(", "urllib",
                   "requests", "socket", "utcnow", "time.time",
                   "datetime.now", "open("):
        assert banned not in source, banned
    assert "agentic_ai" not in source  # no chassis import either