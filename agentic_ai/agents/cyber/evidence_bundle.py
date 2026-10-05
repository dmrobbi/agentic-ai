"""Per-engagement evidence bundle (KA-082): tar.gz + manifest + sha256.

Contract:
- create_evidence_bundle(source_dir, out_path, engagement_id, metadata=None):
  packs every FILE under source_dir (relative paths, sorted) into a tar.gz -
  members first in sorted order, then "manifest.json" appended last. The
  manifest NEVER lists itself (the bedim backup precedent: a self-entry
  cannot hash itself). Returns a dict: bundle_path, file_count,
  total_bytes (content bytes), bundle_sha256 (the bundle file's hash at
  creation - gzip metadata makes it non-stable across machines, so the
  CONTRACT is the manifest, not bundle byte stability), and the manifest.
- verify_evidence_bundle(bundle_path): re-opens the bundle, hashes every
  manifest-listed member, checks sizes, and flags missing/extra members or
  a missing manifest. ok=True iff problems empty. This verifies corruption,
  NOT adversarial forgery: the manifest is not signed - KA-017's evidence
  hash-chain is the tamper-evident tier above this one.
- Pure local file operations; no network; no chassis import (infrastructure
  utilities only; source-scan pinned).
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentic_ai.infrastructure.utils import utcnow

MANIFEST_MEMBER = "manifest.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_evidence_bundle(
    source_dir: str,
    out_path: str,
    engagement_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Bundle source_dir's files + a sha256 manifest into one tar.gz."""
    source = Path(source_dir)
    if not source.is_dir():
        raise ValueError("source_dir must be an existing directory: %r" % source_dir)
    if not engagement_id or not str(engagement_id).strip():
        raise ValueError("engagement_id must be a non-empty string")

    entries: List[Dict[str, Any]] = []
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        data = path.read_bytes()
        entries.append({
            "path": path.relative_to(source).as_posix(),
            "size": len(data),
            "sha256": _sha256_bytes(data),
        })
    manifest: Dict[str, Any] = {
        "engagement_id": engagement_id,
        "created_at": utcnow().isoformat(),
        "metadata": dict(metadata or {}),
        "file_count": len(entries),
        "files": entries,
    }

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as bundle:
        for entry in entries:
            bundle.add(str(source / entry["path"]), arcname=entry["path"])
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(MANIFEST_MEMBER)
        info.size = len(manifest_bytes)
        bundle.addfile(info, io.BytesIO(manifest_bytes))

    return {
        "bundle_path": str(out),
        "file_count": len(entries),
        "total_bytes": sum(e["size"] for e in entries),
        "bundle_sha256": _sha256_bytes(out.read_bytes()),
        "manifest": manifest,
    }


def verify_evidence_bundle(bundle_path: str) -> Dict[str, Any]:
    """Verify a bundle against its own manifest (see contract above)."""
    bundle_file = Path(bundle_path)
    if not bundle_file.is_file():
        return {"ok": False, "problems": ["bundle file missing: %s" % bundle_path]}
    problems: List[str] = []
    try:
        with tarfile.open(bundle_file, "r:gz") as bundle:
            members = {m.name: m for m in bundle.getmembers() if m.isfile()}
            if MANIFEST_MEMBER not in members:
                return {
                    "ok": False,
                    "problems": ["manifest member missing: %s" % MANIFEST_MEMBER],
                }
            manifest_bytes = bundle.extractfile(members[MANIFEST_MEMBER]).read()
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            listed = {e["path"]: e for e in manifest.get("files", [])}

            for path, entry in listed.items():
                if path == MANIFEST_MEMBER:
                    problems.append("manifest lists itself: %s" % path)
                    continue
                member = members.get(path)
                if member is None:
                    problems.append("member missing: %s" % path)
                    continue
                data = bundle.extractfile(member).read()
                if len(data) != entry["size"]:
                    problems.append("size mismatch: %s" % path)
                if _sha256_bytes(data) != entry["sha256"]:
                    problems.append("sha256 mismatch: %s" % path)

            for extra in sorted(set(members) - set(listed) - {MANIFEST_MEMBER}):
                problems.append("member not in manifest: %s" % extra)

            if manifest.get("file_count") != len(listed):
                problems.append("file_count disagrees with the files list")
    except (tarfile.TarError, json.JSONDecodeError, KeyError, ValueError) as exc:
        return {"ok": False, "problems": ["unreadable bundle: %s" % exc]}

    return {"ok": not problems, "problems": problems}
