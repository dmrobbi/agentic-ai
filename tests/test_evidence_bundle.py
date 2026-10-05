"""KA-082 tests - evidence bundler: create shape, manifest self-exclusion,
clean verify, tamper detection (tampered file, extra member, missing
member, missing manifest, non-tar junk, absent bundle file), input
validation, the vacuous empty-source bundle, and the purity scan.
Tempdir-based; no network."""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentic_ai.agents.cyber.evidence_bundle import (
    MANIFEST_MEMBER,
    create_evidence_bundle,
    verify_evidence_bundle,
)


def _seed_source(tmp_path):
    src = tmp_path / "ev"
    nested = src / "sub"
    nested.mkdir(parents=True)
    (src / "a.txt").write_bytes(b"alpha")
    (nested / "b.bin").write_bytes(b"beta-002")
    return src


def _make_bundle(tmp_path, source=None):
    out = tmp_path / "eng.tar.gz"
    return create_evidence_bundle(
        str(source if source is not None else _seed_source(tmp_path)),
        str(out), "ENG-88", {"operator": "ka082-test"},
    )


def _unpack_members(out_path):
    """Read every bundle member as {arcname: bytes} (manifest included)."""
    with tarfile.open(out_path, "r:gz") as bundle:
        return {
            m.name: bundle.extractfile(m).read()
            for m in bundle.getmembers()
            if m.isfile()
        }


def _repack(tmp_path, members):
    """Build a (possibly forged) bundle from {arcname: bytes} - all of it,
    manifest included under its reserved name."""
    out = tmp_path / "forged.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        for arcname, data in sorted(members.items()):
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out


def test_create_bundle_shape(tmp_path):
    out = tmp_path / "eng.tar.gz"
    result = _make_bundle(tmp_path)
    assert result["bundle_path"] == str(out)
    assert out.is_file()
    assert set(result) == {
        "bundle_path", "file_count", "total_bytes", "bundle_sha256",
        "manifest",
    }
    assert result["file_count"] == 2
    assert result["total_bytes"] == 5 + 8
    assert re.fullmatch(r"[0-9a-f]{64}", result["bundle_sha256"])
    manifest = result["manifest"]
    assert manifest["engagement_id"] == "ENG-88"
    assert manifest["metadata"] == {"operator": "ka082-test"}
    assert [e["path"] for e in manifest["files"]] == ["a.txt", "sub/b.bin"]
    assert manifest["files"][0]["size"] == 5
    assert manifest["files"][0]["sha256"] == hashlib.sha256(b"alpha").hexdigest()


def test_verify_clean_bundle(tmp_path):
    _make_bundle(tmp_path)
    result = verify_evidence_bundle(str(tmp_path / "eng.tar.gz"))
    assert result == {"ok": True, "problems": []}


def test_manifest_excludes_self_entry(tmp_path):
    _make_bundle(tmp_path)
    with tarfile.open(tmp_path / "eng.tar.gz", "r:gz") as bundle:
        names = [m.name for m in bundle.getmembers()]
    assert MANIFEST_MEMBER in names
    manifest = json.loads(_unpack_members(tmp_path / "eng.tar.gz")[MANIFEST_MEMBER])
    paths = [e["path"] for e in manifest["files"]]
    assert "manifest.json" not in paths


def test_verify_detects_tampered_file(tmp_path):
    _make_bundle(tmp_path)
    members = _unpack_members(tmp_path / "eng.tar.gz")
    manifest_bytes = members.pop(MANIFEST_MEMBER)
    members_with_manifest = dict(members)
    members_with_manifest[MANIFEST_MEMBER] = manifest_bytes
    members_with_manifest["a.txt"] = b"ALPHA"  # same size, different bytes
    forged = _repack(tmp_path, members_with_manifest)
    result = verify_evidence_bundle(str(forged))
    assert result["ok"] is False
    assert result["problems"] == ["sha256 mismatch: a.txt"]


def test_verify_detects_extra_member(tmp_path):
    _make_bundle(tmp_path)
    members = _unpack_members(tmp_path / "eng.tar.gz")
    members["c.txt"] = b"sneaked in"
    forged = _repack(tmp_path, members)
    result = verify_evidence_bundle(str(forged))
    assert result["ok"] is False
    assert result["problems"] == ["member not in manifest: c.txt"]


def test_verify_detects_missing_member(tmp_path):
    _make_bundle(tmp_path)
    members = _unpack_members(tmp_path / "eng.tar.gz")
    members.pop("sub/b.bin")
    forged = _repack(tmp_path, members)
    result = verify_evidence_bundle(str(forged))
    assert result["ok"] is False
    assert result["problems"] == ["member missing: sub/b.bin"]


def test_verify_detects_missing_manifest(tmp_path):
    _make_bundle(tmp_path)
    members = _unpack_members(tmp_path / "eng.tar.gz")
    members.pop(MANIFEST_MEMBER)
    forged = _repack(tmp_path, members)
    result = verify_evidence_bundle(str(forged))
    assert result == {
        "ok": False,
        "problems": ["manifest member missing: manifest.json"],
    }


def test_verify_rejects_non_tar_file(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"definitely not a tar archive")
    result = verify_evidence_bundle(str(junk))
    assert result["ok"] is False
    assert result["problems"] and result["problems"][0].startswith(
        "unreadable bundle:")


def test_verify_missing_bundle_file(tmp_path):
    ghost = tmp_path / "ghost.tar.gz"
    result = verify_evidence_bundle(str(ghost))
    assert result == {
        "ok": False,
        "problems": ["bundle file missing: " + str(ghost)],
    }


def test_create_rejects_missing_source_and_empty_id(tmp_path):
    with pytest.raises(ValueError):
        create_evidence_bundle(str(tmp_path / "nope"), str(tmp_path / "o.tgz"), "E-1")
    with pytest.raises(ValueError):
        create_evidence_bundle(str(_seed_source(tmp_path)), str(tmp_path / "o.tgz"), "   ")


def test_empty_source_vacuous_bundle(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    result = create_evidence_bundle(str(empty), str(tmp_path / "e.tar.gz"), "ENG-0")
    assert result["file_count"] == 0
    assert result["total_bytes"] == 0
    assert result["manifest"]["files"] == []
    assert verify_evidence_bundle(str(tmp_path / "e.tar.gz")) == {
        "ok": True, "problems": [],
    }


def test_module_purity_source_scan():
    import importlib
    module = importlib.import_module("agentic_ai.agents.cyber.evidence_bundle")
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "agentic_ai.agents" not in source  # no chassis import
    assert "subprocess" not in source
    assert "eval(" not in source
