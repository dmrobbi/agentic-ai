"""KA-094 tests - secrets-store wiring: the ref lifecycle (shape,
determinism, idempotence, hostile-name rejection), resolve via the
injected reader (value-or-None, wrong-prefix rejection, contract
violations that never echo values, fault policy), mask shapes across
length/None/unicode/hostile boundaries, masked entries that never leak
plaintext, describe_flow lifecycle dicts, the tolerant file-store reader
(missing/corrupt/non-dict/subdict missing/non-string entries), put
round-trips with strict 0600 permissions, and the module purity scan (no
execution/network/environment facilities; the JSON file backplane is the
spec-sanctioned exception). All synthetic; no network, no live secrets,
no fixtures - by design."""
from __future__ import annotations

import importlib
import json
import os
import stat
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.secrets_store import (
    MASK,
    NAME_RE,
    REF_PREFIX,
    SECRETS_SCHEMA,
    SecretsStore,
    scrub_secret_name,
)

VALUE_LONG = "sk-live-9999-ABCD-EZ9Q"
VALUE_SHORT = "vG4!x"
VALUE_EIGHT = "abcdefgh"


class DictReader:
    """Injected reader mock: name -> value-or-None, records every lookup."""

    def __init__(self, values):
        self.values = dict(values)
        self.calls = []

    def __call__(self, name):
        self.calls.append(name)
        return self.values.get(name)


class ExplodingReader:
    """Injected reader mock: every lookup raises (use-site sees faults)."""

    def __call__(self, name):
        raise RuntimeError("reader boom")


# ---------------------------------------------------------------- surface --

def test_module_surface_exports_pins():
    module = importlib.import_module("agentic_ai.agents.cyber.secrets_store")
    assert REF_PREFIX == "SECRETREF:"
    assert SECRETS_SCHEMA == "openclaw_secrets_store/v1"
    assert MASK == "****"
    assert callable(module.SecretsStore)
    assert callable(module.scrub_secret_name)
    assert NAME_RE == r"[A-Za-z0-9._\-]{1,64}"
    assert scrub_secret_name("svc-token.v2") == "svc-token.v2"
    with pytest.raises(ValueError):
        scrub_secret_name("a" * 65)


def test_constructor_shapes_validated():
    with pytest.raises(ValueError):
        SecretsStore(reader=42)
    with pytest.raises(ValueError):
        SecretsStore(reader=DictReader({}), file_path=42)
    store = SecretsStore(legacy_extra="x")  # absorbed, never forwarded
    assert store.reader is None and store.file_path is None


# --------------------------------------------------------- ref lifecycle --

def test_get_ref_shape_and_determinism():
    store = SecretsStore()
    assert store.get_ref("kali_api_key") == "SECRETREF:kali_api_key"
    assert store.get_ref("kali_api_key") == store.get_ref("kali_api_key")
    assert store.get_ref("PROD_PASS") == "SECRETREF:PROD_PASS"
    assert store.get_ref("svc-token.v2") == "SECRETREF:svc-token.v2"
    assert store.get_ref("kali_api_key") != store.get_ref("other_cred")


def test_get_ref_idempotent():
    store = SecretsStore()
    ref = store.get_ref("kali_api_key")
    assert store.get_ref(ref) == ref
    with pytest.raises(ValueError):
        store.get_ref("SECRETREF:SECRETREF:kali_api_key")  # nested: rejected


@pytest.mark.parametrize("bad", ["", None, 5, "secret;drop"])
def test_get_ref_rejects_hostile(bad):
    with pytest.raises(ValueError):
        SecretsStore().get_ref(bad)


def test_ref_portable_across_instances():
    ref = SecretsStore().get_ref("kali_api_key")
    store = SecretsStore(
        reader=DictReader({"kali_api_key": VALUE_LONG}))
    assert store.resolve(ref) == VALUE_LONG


# ------------------------------------------------------- resolve (reader) --

def test_resolve_value_or_none_via_injected_reader():
    reader = DictReader({"kali_api_key": VALUE_LONG})
    store = SecretsStore(reader=reader)
    assert store.resolve(store.get_ref("kali_api_key")) == VALUE_LONG
    assert reader.calls == ["kali_api_key"]
    assert store.resolve(store.get_ref("absent_cred")) is None


@pytest.mark.parametrize("bad_ref", ["kali_api_key", "SECRET:foo",
                                     "secretref:foo", None])
def test_resolve_rejects_wrong_prefix(bad_ref):
    with pytest.raises(ValueError):
        SecretsStore().resolve(bad_ref)


def test_reader_faults_propagate_to_use_site():
    store = SecretsStore(reader=ExplodingReader())
    with pytest.raises(RuntimeError):
        store.resolve(store.get_ref("kali_api_key"))


@pytest.mark.parametrize("bad_return", [424242, b"sk-secret-bytes"])
def test_reader_contract_violation_never_echoes_value(bad_return):
    store = SecretsStore(reader=lambda name: bad_return)
    with pytest.raises(ValueError) as err:
        store.resolve(store.get_ref("kali_api_key"))
    assert "424242" not in str(err.value)
    assert "sk-secret-bytes" not in str(err.value)


# ------------------------------------------------------------------ mask --

def test_mask_long_value_keeps_last4_and_unicode():
    assert SecretsStore.mask("sk-live-9999-ABCD-EZ9Q") == "****EZ9Q"
    assert SecretsStore.mask("pässwörd-9") == "****rd-9"
    assert SecretsStore.mask("12345678").startswith(MASK)


@pytest.mark.parametrize("value,expected", [
    ("abc", MASK),
    ("1234567", MASK),
    ("12345678", "****5678"),
])
def test_mask_length_boundary(value, expected):
    assert SecretsStore.mask(value) == expected


def test_mask_none_is_fully_masked():
    assert SecretsStore.mask(None) == MASK


def test_mask_rejects_nonstring_nonnone():
    for bad in (5, 5.5, ["x"], b"sk-plain-bytes"):
        with pytest.raises(ValueError):
            SecretsStore.mask(bad)


# ----------------------------------------------------------- get_masked --

def test_get_masked_present_and_absent():
    store = SecretsStore(reader=DictReader({
        "kali_api_key": VALUE_LONG, "tiny": VALUE_SHORT}))
    assert store.get_masked("kali_api_key") == {
        "name": "kali_api_key", "masked": "****EZ9Q", "present": True}
    entry = store.get_masked("tiny")
    assert entry["masked"] == MASK and entry["present"] is True
    assert store.get_masked("absent_cred") == {
        "name": "absent_cred", "masked": MASK, "present": False}


def test_masked_entry_leaks_nothing_below_mask_floor():
    store = SecretsStore(reader=DictReader(
        {"tiny": VALUE_SHORT, "eight": VALUE_EIGHT}))
    blob = json.dumps([store.get_masked("tiny"), store.get_masked("eight")])
    assert VALUE_SHORT not in blob and VALUE_EIGHT not in blob
    assert MASK in blob


def test_get_masked_and_scrub_reject_hostile_names():
    store = SecretsStore()
    for bad in ("", None, 5, "bad;name", "a" * 65):
        with pytest.raises(ValueError):
            store.get_masked(bad)
        with pytest.raises(ValueError):
            scrub_secret_name(bad)


# -------------------------------------------------------- describe_flow --

def test_describe_flow_shape():
    flow = SecretsStore().describe_flow()
    assert set(flow) == {"flow", "store", "steps", "notes",
                         "ref_prefix", "schema"}
    assert len(flow["steps"]) == 3
    assert all(isinstance(step, dict) for step in flow["steps"])
    assert all(set(step) == {"step", "actor", "detail"}
               for step in flow["steps"])
    assert all(isinstance(note, str) for note in flow["notes"])


def test_describe_flow_step_names_in_order():
    flow = SecretsStore().describe_flow()
    assert [step["step"] for step in flow["steps"]] == [
        "register", "request", "resolve-at-use-site"]


def test_describe_flow_masking_and_env_notes():
    flow = SecretsStore().describe_flow()
    blob = json.dumps(flow)
    assert "MASK" in blob or "mask" in blob
    assert REF_PREFIX in blob
    assert any("environment variables or argv" in note
               for note in flow["notes"])
    assert any("never logged or printed" in note
               for note in flow["notes"])
    assert any("only resolve() returns plaintext" in note
               for note in flow["notes"])


def test_describe_flow_reflects_store_kinds():
    assert SecretsStore().describe_flow()["store"] == "unbound"
    assert SecretsStore(reader=DictReader({})).describe_flow()[
        "store"] == "injected-reader"
    assert SecretsStore(file_path="s.json").describe_flow()[
        "store"] == "file-0600-json"


# ------------------------------------------------------- file store read --

def test_default_file_reader_missing_file_tolerated(tmp_path):
    store = SecretsStore(file_path=tmp_path / "absent.json")
    assert store.resolve(store.get_ref("kali_api_key")) is None
    assert store.get_masked("kali_api_key") == {
        "name": "kali_api_key", "masked": MASK, "present": False}


def test_default_file_reader_corrupt_json_tolerated(tmp_path):
    path = tmp_path / "store.json"
    path.write_text("{ not valid json ]", encoding="utf-8")
    store = SecretsStore(file_path=path)
    assert store.resolve(REF_PREFIX + "kali_api_key") is None
    assert store.get_masked("kali_api_key")["present"] is False


def test_default_file_reader_hostile_json_shapes_tolerated(tmp_path):
    shapes = [
        "[1, 2, 3]",
        "null",
        '"just-a-string"',
        json.dumps({"schema": SECRETS_SCHEMA}),  # values subdict missing
        json.dumps({"schema": SECRETS_SCHEMA,
                    "values": {"k": 5}}),  # non-string entry
    ]
    for i, shape in enumerate(shapes):
        path = tmp_path / ("store-%d.json" % i)
        path.write_text(shape, encoding="utf-8")
        store = SecretsStore(file_path=path)
        assert store.resolve(REF_PREFIX + "k") is None
        assert store.get_masked("k")["present"] is False


# ---------------------------------------------------------- file store put --

def test_roundtrip_put_then_default_reader_resolve(tmp_path):
    path = tmp_path / "store.json"
    ack = SecretsStore(file_path=path).put("kali_api_key", VALUE_LONG)
    assert ack == {"written": True, "name": "kali_api_key",
                   "ref": "SECRETREF:kali_api_key",
                   "masked": "****EZ9Q"}
    assert VALUE_LONG not in json.dumps(ack)  # ack is masked-only
    fresh = SecretsStore(file_path=path)
    assert fresh.resolve(fresh.get_ref("kali_api_key")) == VALUE_LONG
    assert fresh.get_masked("kali_api_key")["masked"] == "****EZ9Q"


def test_put_requires_file_path():
    with pytest.raises(ValueError):
        SecretsStore().put("kali_api_key", VALUE_LONG)
    with pytest.raises(ValueError):
        SecretsStore(reader=DictReader({})).put("kali_api_key", VALUE_LONG)
    unbound = SecretsStore()
    assert unbound.resolve("SECRETREF:x") is None


def test_put_rejects_hostile_name_and_value(tmp_path):
    path = tmp_path / "store.json"
    store = SecretsStore(file_path=path)
    for bad_name in ("", None, 5, "has space", "x" * 65):
        with pytest.raises(ValueError):
            store.put(bad_name, VALUE_LONG)
    for bad_value in ("", "   ", None, 5, ["x"]):
        with pytest.raises(ValueError):
            store.put("ok_name", bad_value)
    assert not path.exists()  # nothing written for hostile inputs


def test_put_overwrites_last_write_wins_with_schema_shape(tmp_path):
    path = tmp_path / "store.json"
    store = SecretsStore(file_path=path)
    store.put("alpha", "v1-99999999")
    store.put("beta_cred", "tiny")
    store.put("alpha", "v2-99999999")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == {"schema", "values"}
    assert data["schema"] == SECRETS_SCHEMA
    assert data["values"] == {"alpha": "v2-99999999", "beta_cred": "tiny"}


def test_written_store_permissions_strict_0600_after_repeated_put(tmp_path):
    path = tmp_path / "store.json"
    store = SecretsStore(file_path=path)
    store.put("kali_api_key", VALUE_LONG)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    store.put("second_cred", "sk-abcdefghijklmnopqrstuvwxyz")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_injected_reader_wins_over_file_store(tmp_path):
    path = tmp_path / "store.json"
    SecretsStore(file_path=path).put("file_name", "file-value-12345")
    store = SecretsStore(reader=DictReader({"kali_api_key": VALUE_LONG}),
                         file_path=path)
    assert store.resolve(store.get_ref("kali_api_key")) == VALUE_LONG
    assert store.resolve(store.get_ref("file_name")) is None
    assert store.get_masked("file_name")["present"] is False
    ack = store.put("written_name", "written-value-9876")  # file path writes
    assert ack["written"] is True
    assert json.loads(path.read_text(encoding="utf-8"))[
        "values"]["written_name"] == "written-value-9876"


# -------------------------------------------------------------- no-leak ---

def test_no_plaintext_in_op_returns(tmp_path):
    values = {
        "kali_api_key": VALUE_LONG,
        "short_cred": VALUE_SHORT,
        "eight_cred": VALUE_EIGHT,
    }
    store = SecretsStore(reader=DictReader(values),
                         file_path=tmp_path / "store.json")
    outputs = {
        "ref": store.get_ref("kali_api_key"),
        "masked": store.get_masked("eight_cred"),
        "masked_short": store.get_masked("short_cred"),
        "ack": store.put("kali_api_key", VALUE_LONG),
        "flow": store.describe_flow(),
        "repr": repr(store),
        "str": str(store),
    }
    blob = json.dumps(outputs, default=str)
    for value in (VALUE_LONG, VALUE_SHORT, VALUE_EIGHT):
        assert value not in blob
    assert outputs["ref"] == REF_PREFIX + "kali_api_key"  # positive control
    with pytest.raises(ValueError) as err:
        store.resolve("kali_api_key")  # wrong prefix: names are no secrets
    for value in (VALUE_LONG, VALUE_SHORT, VALUE_EIGHT):
        assert value not in str(err.value)


def test_reprs_mask_values():
    store = SecretsStore(reader=DictReader({"kali_api_key": VALUE_LONG}),
                         file_path="/tmp/not-real-store.json")
    blob = repr(store) + str(store)
    assert VALUE_LONG not in blob
    assert "injected" in blob
    assert "not-real-store.json" in blob


def test_error_messages_mask_values():
    with pytest.raises(ValueError) as err:
        SecretsStore().resolve("kali_api_key")
    assert "kali_api_key" in str(err.value)  # names/refs are not secrets
    store = SecretsStore(reader=lambda name: 424242)
    with pytest.raises(ValueError) as verr:
        store.get_masked("kali_api_key")
    assert "424242" not in str(verr.value)
    with pytest.raises(ValueError) as merr:
        SecretsStore.mask(9876543)
    assert "9876543" not in str(merr.value)


# ---------------------------------------------------------------- purity --

def test_source_scan_no_exec_no_network_no_env():
    module = importlib.import_module("agentic_ai.agents.cyber.secrets_store")
    source = Path(module.__file__).read_text(encoding="utf-8")
    lowered = source.lower()
    for token in ("subprocess", "os.system", "eval(", "exec(", "popen",
                  "urllib", "requests", "socket", "http.client",
                  "os.environ", "getenv", "sys.argv", "print(", "logging",
                  "datetime.now", "utcnow", "time.time"):
        assert token not in lowered, token
    assert "0600" in source
    assert '"values"' in source


def test_docstring_carries_0600_permission_notes():
    module = importlib.import_module("agentic_ai.agents.cyber.secrets_store")
    doc = module.__doc__
    for token in ("0600", "chmod 0600", "os.open", "values", "schema"):
        assert token in doc, token


def test_legacy_kwargs_absorbed():
    store = SecretsStore(reader=DictReader({"kali_api_key": VALUE_LONG}))
    assert store.get_ref("kali_api_key", junk=1) == REF_PREFIX + "kali_api_key"
    assert store.resolve(store.get_ref("kali_api_key"),
                         junk=1) == VALUE_LONG
    assert SecretsStore.mask(VALUE_LONG, junk=1) == "****EZ9Q"
    assert store.get_masked("kali_api_key", junk=1)["present"] is True
    assert store.describe_flow(junk=1)["ref_prefix"] == REF_PREFIX
    assert SecretsStore(legacy_mode="old").resolve(
        "SECRETREF:x", junk=True) is None
