"""KA-045 tests - WebAuthMixin: the policy rows, the 7-phase plan, the
OAuth grant catalog + assessment arcs (legacy grants row-flagged), the
decoded-claims JWT analysis (no decoding, no key material), the
structural redirect-URI rows, token-storage + SSO checklists, the host
gate consult, and the never-executes / no-secret-material source scan.
Offline; scrubbed inputs only."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentic_ai.agents.cyber.webauth_ops import (
    WEB_AUTH_POLICY,
    WebAuthMixin,
    wa_scrub_claims,
    wa_scrub_uri,
)

MIXIN = WebAuthMixin()

EXPECTED_POLICY = {
    "planner_only": True,
    "no_execution": True,
    "no_secrets_handling": True,
    "decoded_inspection_only": True,
    "no_credential_capture": True,
}

EXPECTED_FLOWS = {"authorization-code-pkce", "client-credentials",
                  "device-code", "implicit", "password-grant"}

EXPECTED_PHASES = ["1-surface-map", "2-grant-inventory", "3-client-config",
                   "4-token-lifecycle", "5-token-structure", "6-sso-surface",
                   "7-reporting"]

DEPRECATED_FLOWS = ("implicit", "password-grant")


def rows_by_key(rows, key="claim"):
    return {r[key]: r for r in rows}


# --- policy -------------------------------------------------------------

def test_policy_rows():
    assert WEB_AUTH_POLICY == EXPECTED_POLICY
    assert MIXIN.webauth_policy() == EXPECTED_POLICY
    assert MIXIN.webauth_index()["policy"] == EXPECTED_POLICY


# --- plan ---------------------------------------------------------------

def test_plan_webauth_phases_and_policy():
    plan = MIXIN.plan_webauth("idp.example.com")
    assert plan["target"] == "idp.example.com"
    assert [p["phase"] for p in plan["phases"]] == EXPECTED_PHASES
    assert plan["policy"] == EXPECTED_POLICY
    for phase in plan["phases"]:
        assert phase["policy"] == EXPECTED_POLICY
        assert phase["goal"] and phase["activities"]
        assert phase["sample_commands"]
        assert "{target}" not in str(phase["sample_commands"])


def test_plan_webauth_target_injected():
    plan = MIXIN.plan_webauth("idp.example.com")
    first_cmds = plan["phases"][0]["sample_commands"]
    assert any("idp.example.com/.well-known/openid-configuration" in c
               for c in first_cmds)


@pytest.mark.parametrize("bad", [
    "idp.example.com; calc", "a b", "", "$(id)", "x&y", "a\nb", 'q"q',
    "a|b", "a..b",
])
def test_plan_webauth_scrub_rejects(bad):
    with pytest.raises(ValueError):
        MIXIN.plan_webauth(bad)


class _RejectingHost(WebAuthMixin):
    def validate_target(self, target):
        return (False, "outside the review scope")


class _AcceptingHost(WebAuthMixin):
    def validate_target(self, target):
        return (True, "ok")


def test_host_gate_consulted_with_silent_fallback():
    with pytest.raises(ValueError) as err:
        _RejectingHost().plan_webauth("idp.example.com")
    assert "host agent gate" in str(err.value)
    assert _AcceptingHost().plan_webauth(
        "idp.example.com")["target"] == "idp.example.com"
    # the bare mixin (no host gate around) works - silent fallback
    assert MIXIN.plan_webauth("idp.example.com")["target"]


# --- OAuth flow catalog -------------------------------------------------

def test_flow_catalog_none_lists_all():
    res = MIXIN.oauth_flow_catalog()
    assert {f["flow"] for f in res["flows"]} == EXPECTED_FLOWS
    status = {f["flow"]: f["status"] for f in res["flows"]}
    assert status["implicit"] == "deprecated"
    assert status["password-grant"] == "deprecated"
    assert status["authorization-code-pkce"] == "current"
    assert res["policy"] == EXPECTED_POLICY


@pytest.mark.parametrize("alias,canonical", [
    ("auth-code", "authorization-code-pkce"),
    ("pkce", "authorization-code-pkce"),
    ("m2m", "client-credentials"),
    ("device", "device-code"),
    ("response-type-token", "implicit"),
    ("ropc", "password-grant"),
])
def test_flow_catalog_resolves_aliases(alias, canonical):
    res = MIXIN.oauth_flow_catalog(alias)
    assert res["flow"] == canonical
    assert res["status"] in ("current", "deprecated")
    assert res["steps"]
    for step in res["steps"]:
        assert step["step"] and step["note"]


def test_flow_catalog_unknown_refused():
    with pytest.raises(ValueError) as err:
        MIXIN.oauth_flow_catalog("banana")
    assert "known:" in str(err.value)


def test_grant_assessment_rows():
    for flow in sorted(EXPECTED_FLOWS):
        res = MIXIN.oauth_grant_assessment(flow)
        assert res["flow"] == flow
        assert res["assessments"]
        has_status = any(a["check"] == "grant-status"
                         for a in res["assessments"])
        assert has_status == (flow in DEPRECATED_FLOWS)
        assert res["policy"] == EXPECTED_POLICY


def test_grant_assessment_unknown_refused():
    with pytest.raises(ValueError):
        MIXIN.oauth_grant_assessment("banana")


# --- JWT decoded-claims analysis ---------------------------------------

def _header_rows(res):
    return rows_by_key(res["header"])


def _payload_rows(res):
    return rows_by_key(res["payload"])


def test_jwt_analysis_ok_path():
    header = {"alg": "RS256", "kid": "2026-09-key", "typ": "at+jwt"}
    payload = {"iss": "https://idp.example.com/", "sub": "u-1001",
               "aud": "client-1001", "exp": 1900000000, "iat": 1800000000,
               "nbf": 1799999500, "jti": "one-time-9f"}
    res = MIXIN.jwt_analysis(header, payload, now=1810000000,
                             client_id="client-1001")
    hdr = _header_rows(res)
    assert hdr["alg"]["class"] == "ok"
    assert "asymmetric" in hdr["alg"]["note"]
    assert hdr["kid"]["class"] == "info"
    pl = _payload_rows(res)
    assert pl["iss"]["class"] == "ok"
    assert pl["aud"]["class"] == "ok" and "covers" in pl["aud"]["note"]
    assert pl["exp"]["class"] == "ok"
    assert pl["exp"]["note"].startswith("expiry still ahead")
    assert pl["iat"]["class"] == "ok"
    assert pl["nbf"]["class"] == "ok"
    assert pl["jti"]["class"] == "ok"
    assert res["timing"]["now_evaluated"] is True
    assert res["timing"]["skew_margin"] == 300
    assert res["policy"] == EXPECTED_POLICY


def test_jwt_analysis_findings():
    header = {"alg": "none"}
    payload = {"iss": "", "sub": "u-1001", "aud": "other-app", "exp": True,
               "iat": 1900000000, "nbf": 1810000100}
    res = MIXIN.jwt_analysis(header, payload, now=1810000000,
                             client_id="client-1001")
    hdr = _header_rows(res)
    assert hdr["alg"]["class"] == "finding"
    assert "refuse" in hdr["alg"]["note"]
    assert hdr["kid"]["present"] is False
    pl = _payload_rows(res)
    assert pl["iss"]["class"] == "finding"  # empty value
    assert pl["aud"]["class"] == "finding"  # does not cover the client
    assert pl["exp"]["class"] == "finding"  # not numeric (bool)
    assert pl["iat"]["class"] == "finding"  # beyond the skew margin
    assert "expired" not in pl["exp"]["note"]


def test_jwt_analysis_symmetric_alg_scope_note():
    res = MIXIN.jwt_analysis({"alg": "HS256"}, {"iss": "https://i.example/"})
    alg = _header_rows(res)["alg"]
    assert alg["class"] == "info"
    assert "outside these ops" in alg["note"]


def test_jwt_analysis_absences_and_no_clock():
    res = MIXIN.jwt_analysis({"alg": "RS256"},
                             {"iss": "https://idp.example.com/"})
    pl = _payload_rows(res)
    assert pl["exp"]["present"] is False and pl["exp"]["class"] == "finding"
    assert pl["aud"]["class"] == "finding"
    assert pl["sub"]["class"] == "info"
    assert pl["nbf"]["class"] == "info"
    assert pl["jti"]["class"] == "info"
    assert res["timing"]["now_evaluated"] is False
    with_now = MIXIN.jwt_analysis(
        {"alg": "RS256"},
        {"iss": "https://idp.example.com/", "exp": 1900000000},
        now=1810000000)
    assert _payload_rows(with_now)["exp"]["class"] == "ok"


def test_jwt_analysis_expired_at_review_time():
    res = MIXIN.jwt_analysis({"alg": "RS256"},
                             {"iss": "https://i.example/",
                              "exp": 1800000000},
                             now=1810000000)
    exp_row = _payload_rows(res)["exp"]
    assert exp_row["class"] == "finding" and "expired" in exp_row["note"]


def test_jwt_analysis_audience_needs_client_id():
    res = MIXIN.jwt_analysis({"alg": "RS256"},
                             {"iss": "https://i.example/",
                              "aud": "client-1001"})
    aud = _payload_rows(res)["aud"]
    assert aud["class"] == "info" and "client_id" in aud["note"]


def test_jwt_analysis_audience_list_membership():
    res = MIXIN.jwt_analysis(
        {"alg": "RS256"},
        {"iss": "https://i.example/", "aud": ["api-a", "client-1001"]},
        client_id="client-1001")
    assert _payload_rows(res)["aud"]["class"] == "ok"


def test_jwt_analysis_custom_claims():
    res = MIXIN.jwt_analysis(
        {"alg": "RS256", "x-custom": "v"},
        {"iss": "https://i.example/", "roles": ["r1", "r2"]})
    custom_header = rows_by_key(res["header"])["x-custom"]
    assert custom_header["class"] == "custom"
    roles = _payload_rows(res)["roles"]
    assert roles["class"] == "custom"
    assert roles["present"] is True


@pytest.mark.parametrize("bad", [
    "not a dict",
    42,
    ("a",),
    {"iss": {"nested": 1}},
    {"iss": "a", "roles": [{"x": 1}]},
    {"iss": "a", "role": ("r1",)},
    {"iss": "a", "bad": "line\nbreak"},
    {"iss": "a", "bad": "tab\tchar"},
    {"iss": "x" * 600},
    {str(i): i for i in range(60)},
])
def test_jwt_scrub_rejects(bad):
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis(bad, {})
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis({}, bad)


def test_jwt_analysis_refuses_encoded_token_strings():
    # the decoded-inspection policy row, proven: an encoded token string
    # enters nothing and gets decoded nowhere - operand rejection only
    with pytest.raises(ValueError) as err:
        MIXIN.jwt_analysis("eyJhbGciOiJIUzI1NiJ9.e30.abc", {})
    assert "decoded" in str(err.value)
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis({}, "eyJhbGciOiJIUzI1NiJ9.e30.abc")


def test_jwt_analysis_bad_anchors_rejected():
    good_header = {"alg": "RS256"}
    good_payload = {"iss": "https://i.example/", "exp": 1900000000}
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis(good_header, good_payload, now=True)
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis(good_header, good_payload, now="1810000000")
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis(good_header, good_payload, client_id="a b")
    with pytest.raises(ValueError):
        MIXIN.jwt_analysis(good_header, good_payload, client_id="x" * 150)


def test_claims_scrub_accepts_primitives_and_flat_lists():
    clean = wa_scrub_claims({"iss": "https://i.example/",
                             "aud": ["a", 1], "mfa": True, "cnt": 3,
                             "noneclaim": None})
    assert clean["mfa"] is True and clean["cnt"] == 3
    assert clean["noneclaim"] is None and clean["aud"] == ["a", 1]


# --- redirect checks ----------------------------------------------------

def test_redirect_checks_rows():
    res = MIXIN.webauth_redirect_checks(
        ["https://app.example.com/callback",
         "http://app.example.com/callback",
         "https://*.example.com/callback",
         "https://app.example.com/callback#tok",
         "https://user@idp.example.com/callback",
         "https://app.example.com"])
    rows = res["uris"]
    assert len(rows) == 6
    assert rows[0]["scheme"] == "https"
    assert any("cleartext" in n for n in rows[1]["notes"])
    assert rows[2]["wildcard"] is True
    assert any("prefix matching" in n for n in rows[2]["notes"])
    assert rows[3]["fragment"] is True
    assert any("fragment" in n for n in rows[3]["notes"])
    assert rows[4]["userinfo"] is True
    assert rows[5]["path"] == ""
    assert any("exact-path" in n for n in rows[5]["notes"])
    assert res["general_checks"]
    assert res["policy"] == EXPECTED_POLICY
    assert res["client_type"] is None


def test_redirect_checks_loopback_by_client_type():
    uri = "https://localhost:8080/callback"
    native = MIXIN.webauth_redirect_checks(uri, client_type="native")
    row = native["uris"][0]
    assert row["loopback"] is True
    assert not any("finding-class" in n for n in row["notes"])
    public = MIXIN.webauth_redirect_checks([uri], client_type="public")
    prow = public["uris"][0]
    assert any("finding-class" in n for n in prow["notes"])


def test_redirect_checks_custom_scheme_by_client_type():
    uri = "com.app.signin://callback"
    native = MIXIN.webauth_redirect_checks(uri, client_type="native")
    assert not any("finding-class" in n
                   for n in native["uris"][0]["notes"])
    conf = MIXIN.webauth_redirect_checks([uri], client_type="confidential")
    assert any("finding-class" in n for n in conf["uris"][0]["notes"])
    assert conf["client_type"] == "confidential"


def test_redirect_checks_single_string_input():
    res = MIXIN.webauth_redirect_checks("https://app.example.com/callback")
    assert len(res["uris"]) == 1
    assert res["uris"][0]["scheme"] == "https"


@pytest.mark.parametrize("bad", [
    "https://app.example.com/cb?next=/home&log=1",
    "https://app;example.com/cb",
    "nota-uri",
    "https://",
    "x" * 2100,
    "",
    None,
])
def test_redirect_uri_scrub_rejects(bad):
    with pytest.raises(ValueError):
        wa_scrub_uri(bad)
    with pytest.raises(ValueError):
        MIXIN.webauth_redirect_checks([bad])


def test_redirect_checks_list_bounds():
    good = "https://app.example.com/callback"
    assert MIXIN.webauth_redirect_checks([good] * 25)
    with pytest.raises(ValueError):
        MIXIN.webauth_redirect_checks([good] * 26)
    with pytest.raises(ValueError):
        MIXIN.webauth_redirect_checks(42)


def test_redirect_client_type_aliases():
    assert MIXIN.webauth_redirect_checks(
        ["https://a.example.com/cb"], client_type="spa")["client_type"] == "public"
    assert MIXIN.webauth_redirect_checks(
        ["https://a.example.com/cb"], client_type="mobile")["client_type"] == "native"
    with pytest.raises(ValueError):
        MIXIN.webauth_redirect_checks(["https://a.example.com/cb"],
                                      client_type="banana")


# --- storage + SSO ------------------------------------------------------

def test_token_storage_rows():
    res = MIXIN.webauth_token_storage()
    positions = rows_by_key(res["positions"], "position")
    for expected in ("access-token", "refresh-token", "authorization-code",
                     "session-cookie", "id-token", "cookie-flags"):
        assert expected in positions
        assert positions[expected]["note"]
    assert len(res["detection"]) >= 5
    for row in res["detection"]:
        assert row["check"] and row["note"]
    assert res["policy"] == EXPECTED_POLICY


def test_sso_surface_list():
    res = MIXIN.webauth_sso_surface()
    assert res["protocols"] == ["oidc", "saml"]
    assert res["policy"] == EXPECTED_POLICY


def test_sso_surface_oidc():
    res = MIXIN.webauth_sso_surface("oidc")
    assert res["protocol"] == "oidc"
    checks = rows_by_key(res["checks"], "check")
    assert {"nonce-binding", "state-binding", "idp-initiated",
            "cookie-flags"} <= set(checks)
    assert res["handshake"]
    for step in res["handshake"]:
        assert step["step"] and step["note"]


def test_sso_surface_saml_alias():
    res = MIXIN.webauth_sso_surface("saml2")
    assert res["protocol"] == "saml"
    checks = rows_by_key(res["checks"], "check")
    assert {"signature-enforced", "response-state-binding"} <= set(checks)


def test_sso_surface_unknown_refused():
    with pytest.raises(ValueError) as err:
        MIXIN.webauth_sso_surface("kerberos")
    assert "known:" in str(err.value)


def test_webauth_index():
    res = MIXIN.webauth_index()
    assert set(res["flows"]) == EXPECTED_FLOWS
    assert res["protocols"] == ["oidc", "saml"]
    assert res["policy"] == EXPECTED_POLICY


# --- purity -------------------------------------------------------------

def test_module_never_executes_and_holds_no_secret_material():
    import agentic_ai.agents.cyber.webauth_ops as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    banned = ("subprocess", "os.system", "eval(", "urllib", "requests",
              "socket", "time.time", "-----BEGIN", "client_secret",
              "client-secret", "password=")
    for token in banned:
        assert token not in source, token


def test_scrub_wrappers_route_through_the_module_helpers():
    assert WebAuthMixin._wa_scrub_target(" a.example.com ") == "a.example.com"
    assert WebAuthMixin._wa_scrub_uri(
        "https://app.example.com/cb") == "https://app.example.com/cb"
    assert WebAuthMixin._wa_scrub_claims({"iss": "i"})["iss"] == "i"
    with pytest.raises(ValueError):
        WebAuthMixin._wa_scrub_target("")
    with pytest.raises(ValueError):
        WebAuthMixin._wa_scrub_uri("https://")
    with pytest.raises(ValueError):
        WebAuthMixin._wa_scrub_claims("nope")