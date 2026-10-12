"""LuksOpsMixin tests: the LUKS planner is doc-mirrored and never executes."""
import pathlib

import pytest

from agentic_ai.agents.cyber.luks_ops import (
    LUKS_KNOWN_PROFILES,
    LUKS_SECURE_MEMORY_DEFAULT_KIB,
    LUKS_SECURE_MEMORY_VARIANT_KIB,
    LUKS2_HEADER_FALLBACK_BYTES,
    LuksOpsMixin,
)


class _Host(LuksOpsMixin):
    """Bare planner host; the chassis wiring (LUK-05) is a later phase."""

    def __init__(self, vt=None):
        self.validate_target = vt  # None keeps the guard's silent fallback


@pytest.fixture
def host():
    return _Host()


@pytest.fixture
def scratch(tmp_path):
    return str(tmp_path)


def test_create_secure_plan_shape(host, scratch):
    plan = host.plan_luks_create(scratch, "vault.img", "secure")
    assert plan["profile"] == "secure"
    p = plan["params"]
    assert p["key_size"] == 512 and p["hash"] == "sha512"
    assert p["pbkdf"] == "argon2id"
    assert p["pbkdf_memory_kib"] == LUKS_SECURE_MEMORY_DEFAULT_KIB == 1048576
    assert p["pbkdf_parallel"] == 8 and p["iter_time_ms"] == 5000
    assert p["sector_size"] == 4096 and p["keyslots_size"] == "16m"
    assert p["metadata_size"] == "256k"
    container = str((pathlib.Path(scratch) / "vault.img").resolve())
    assert plan["container"] == container
    assert plan["commands"][0].startswith("dd if=/dev/urandom of=")
    fmt = plan["commands"][1]
    assert "--key-size 512" in fmt and "--pbkdf argon2id" in fmt
    assert "--pbkdf-memory 1048576" in fmt
    assert container in fmt and "--batch-mode" in fmt
    assert plan["consent_rail"] == "scratch-only; no block-device ops"


def test_create_fast_profile_params(host, scratch):
    plan = host.plan_luks_create(scratch, "vault.img", "fast")
    p = plan["params"]
    assert p["key_size"] == 256 and p["hash"] == "sha256"
    assert p["pbkdf"] == "pbkdf2"
    assert p["pbkdf_force_iterations"] == 1000000
    fmt = plan["commands"][1]
    assert "--key-size 256" in fmt
    assert "--pbkdf-force-iterations 1000000" in fmt
    assert "--use-random" in fmt
    assert "argon2id" not in fmt and "--sector-size" not in fmt


def test_secure_memory_variant_flip(host, scratch):
    variant = host.plan_luks_create(scratch, "v.img", "secure",
                                    memory_variant=True)
    assert LUKS_SECURE_MEMORY_VARIANT_KIB == 4194304
    assert "--pbkdf-memory 4194304" in variant["commands"][1]
    default = host.plan_luks_create(scratch, "v.img", "secure")
    assert "--pbkdf-memory 1048576" in default["commands"][1]


def test_unknown_profile_error_lists_known(host, scratch):
    with pytest.raises(ValueError) as exc:
        host.plan_luks_create(scratch, "v.img", "turbo")
    msg = str(exc.value)
    for known in LUKS_KNOWN_PROFILES:
        assert known in msg, (known, msg)


def test_size_mb_bounds(host, scratch):
    for bad in (0, -1, 4097, "64", 1.5):
        with pytest.raises(ValueError):
            host.plan_luks_create(scratch, "v.img", "fast", size_mb=bad)
    tiny = host.plan_luks_create(scratch, "v.img", "fast", size_mb=1)
    assert "count=1" in tiny["commands"][0]
    big = host.plan_luks_create(scratch, "v.img", "fast", size_mb=4096)
    assert "count=4096" in big["commands"][0]


@pytest.mark.parametrize("evil", [
    "x; rm -rf /",
    "x && cat /etc/passwd",
    "$(whoami)",
    "x\ncat",
    "x\x00y",
    "../escape",
    "a/../b",
    "./relative",
    "",
    None,
    5,
])
def test_scrub_rejects_evil(evil):
    with pytest.raises(ValueError):
        LuksOpsMixin._luks_scrub_target(evil)


def test_guard_consults_validate_target(scratch):
    polite = _Host()  # None -> silent fallback, plan proceeds
    assert polite.plan_luks_create(scratch, "v.img")["profile"] == "secure"
    generous = _Host(vt=lambda t: True)
    assert generous.plan_detached_header(scratch, "v.img")["profile"] \
        == "secure"
    picky = _Host(vt=lambda t: False)
    with pytest.raises(ValueError) as exc:
        picky.plan_luks_create(scratch, "v.img")
    assert "validate_target" in str(exc.value)


def test_names_reject_slashes(host, scratch):
    with pytest.raises(ValueError):
        host.plan_luks_create(scratch, "a/b")
    with pytest.raises(ValueError):
        host.plan_luks_create(scratch, "a b")
    with pytest.raises(ValueError):
        host.plan_luks_open_close(scratch, "c.img", key_name="k/l")
    with pytest.raises(ValueError):
        host.plan_luks_open_close(scratch, "c.img", mapper_name="x y")


def test_open_close_rows_flag_root(host, scratch):
    plan = host.plan_luks_open_close(scratch, "c.img")
    rows = plan["rows"]
    assert len(rows) == 4
    assert all(r["requires_root"] for r in rows)
    assert "sudo /usr/sbin/cryptsetup luksOpen" in rows[0]["cmd"]
    key_path = str((pathlib.Path(scratch) / "key").resolve())
    assert rows[0]["cmd"].endswith("--key-file=" + key_path)
    assert "mount" in rows[2]["cmd"]
    assert "process-substitution" in plan["notes"]


def test_slot_add_row(host, scratch):
    row = host.plan_luks_slot_ops(scratch, "c.img", ["add"])["rows"][0]
    assert row["requires_confirmation"] is False
    cmd = row["cmd"]
    assert "--key-slot 5" in cmd and "--new-keyfile=-" in cmd
    assert "--key-file=-" in cmd
    assert "sudo" not in cmd  # add stays unprivileged on file-backed containers


def test_slot_rotate_gate(host, scratch):
    gated = host.plan_luks_slot_ops(scratch, "c.img", ["rotate_slot_0"])
    row = gated["rows"][0]
    assert row["requires_confirmation"] is True and "skipped" in row
    assert "cmd" not in row
    armed = host.plan_luks_slot_ops(scratch, "c.img", ["rotate_slot_0"],
                                    confirm=True, auth_key_file="key_slot3")
    row = armed["rows"][0]
    assert row["requires_confirmation"] is False
    assert "luksKillSlot" in row["cmd"] and "key_slot3" in row["cmd"]
    assert "re-add" in row["note"]
    with pytest.raises(ValueError):
        host.plan_luks_slot_ops(scratch, "c.img", ["rotate_slot_0"],
                                confirm=True)


def test_slot_kill_requires_different_credential(host, scratch):
    with pytest.raises(ValueError) as exc:
        host.plan_luks_slot_ops(scratch, "c.img", ["kill_slot"],
                                confirm=True)
    assert "DIFFERENT" in str(exc.value)
    armed = host.plan_luks_slot_ops(scratch, "c.img", ["kill_slot"],
                                    confirm=True, auth_key_file="key_slot3")
    row = armed["rows"][0]
    assert row["slot"] == 0 and "luksKillSlot" in row["cmd"]


def test_slot_bounds_and_unknown_op(host, scratch):
    with pytest.raises(ValueError):
        host.plan_luks_slot_ops(scratch, "c.img", ["kill_slot"],
                                target_slot=32)
    with pytest.raises(ValueError):
        host.plan_luks_slot_ops(scratch, "c.img", ["kill_slot"],
                                target_slot=-1)
    with pytest.raises(ValueError):
        host.plan_luks_slot_ops(scratch, "c.img", ["add"], staging_slot=32)
    with pytest.raises(ValueError) as exc:
        host.plan_luks_slot_ops(scratch, "c.img", ["frobnicate"])
    msg = str(exc.value)
    for kind in ("add", "rotate_slot_0", "kill_slot"):
        assert kind in msg, (kind, msg)


def test_header_wipe_derives_from_dump(host, scratch):
    dump = ("Version:  2\nMetadata area: \t16384 [bytes]\n"
            "Keyslots area: \t16744448 [bytes]\nPBKDF:      pbkdf2\n")
    plan = host.plan_header_wipe(scratch, "c.img", dump)
    expected = 2 * 16384 + 16744448 + 1048576
    assert plan["parsed"] is True
    assert plan["wipe_bytes"] == expected == 17825792
    assert plan["wipe_bytes"] == LUKS2_HEADER_FALLBACK_BYTES
    assert "count=17" in plan["commands"][0]
    assert plan["wipe_bytes"] != 4 * 1024 * 1024


def test_header_wipe_no_dump_fallback(host, scratch):
    plan = host.plan_header_wipe(scratch, "c.img")
    assert plan["parsed"] is False
    assert plan["wipe_bytes"] == LUKS2_HEADER_FALLBACK_BYTES
    assert "derive the length from luksDump" in plan["warning"]
    assert plan["consent_rail"] == "scratch-only; no block-device ops"


def test_header_wipe_below_floor_rejected(host, scratch):
    dump = "Metadata area: 1000\nKeyslots area: 1000\n"
    with pytest.raises(ValueError) as exc:
        host.plan_header_wipe(scratch, "c.img", dump)
    assert "16 MiB" in str(exc.value)


def test_header_backup_restore_rows(host, scratch):
    plan = host.plan_header_backup_restore(scratch, "c.img")
    rows = plan["rows"]
    assert len(rows) == 2
    assert all(r["requires_root"] is False for r in rows)
    assert "luksHeaderBackup" in rows[0]["cmd"]
    assert "luksHeaderRestore" in rows[1]["cmd"]
    assert "--header-backup-file" in rows[0]["cmd"]
    assert "unlock oracle" in plan["notes"]
    assert str((pathlib.Path(scratch) / "header.bak").resolve()) \
        == plan["backup"]


def test_detached_header_plan_shape(host, scratch):
    plan = host.plan_detached_header(scratch, "c.img")
    header = str((pathlib.Path(scratch) / "header.bin").resolve())
    assert plan["header"] == header
    steps = {a["step"] for a in plan["arcs"]}
    assert steps == {"create", "open-close", "extract", "verify"}
    by_step = {a["step"]: a["cmd"] for a in plan["arcs"]}
    assert "--header " + header in by_step["create"]
    assert "--header " + header in by_step["open-close"]
    assert "luksHeaderBackup" in by_step["extract"]
    assert "luksDump --header" in by_step["verify"]
    assert "RESTORE" in plan["notes"]


def test_checklist_shape(host, scratch):
    cl = host.luks_test_passphrase_checklist(scratch, "c.img")
    assert len(cl) == 4
    assert all(r["requires_root"] is False for r in cl)
    assert all("open --test-passphrase" in r["cmd"] for r in cl)
    assert "--key-file=" in cl[1]["cmd"]
    assert "echo vs echo -n" in cl[1]["check"]
    slotted = host.luks_test_passphrase_checklist(scratch, "c.img", slot=3)
    assert "--key-slot 3" in slotted[2]["cmd"]
    with pytest.raises(ValueError):
        host.luks_test_passphrase_checklist(scratch, "c.img", slot=32)


def test_method_notes_free_of_material(host):
    notes = host.luks_method_notes()
    assert len(notes["findings"]) == 5
    assert notes["bip39_stance"].startswith("do not couple")
    assert "obscurity" in notes["image_key_envelope"]
    assert "owner-signed consent" in notes["consent_rail"]
    assert len(notes["verified_trapdoors"]) == 2
    blob = str(notes)
    assert "abandon ability" not in blob  # no BIP-39 test-vector material


def test_no_exec_tokens():
    p = (pathlib.Path(__file__).resolve().parent.parent / "agentic_ai"
         / "agents" / "cyber" / "luks_ops.py")
    text = p.read_text()
    assert "subprocess" not in text
    assert "os.system" not in text
    assert "eval(" not in text
    assert "popen" not in text.lower()
    assert "import os" not in text
