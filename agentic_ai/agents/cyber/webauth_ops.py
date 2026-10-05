"""WebAuthMixin (KA-045): SSO/OAuth/JWT surface method plans.

Planner-only: every op returns review data - no execution, no network, no
I/O. NO SECRETS HANDLING: JWT work is DECODED-INSPECTION planning only;
the operands are decoded claim dicts supplied by the authorized engagement
(these ops never decode encoded token strings and never touch signing or
verification key material). Command templates stay at the header /
discovery-document / structural level; credential values, client secrets,
and token exfiltration steps are out of scope by policy.

Surface knowledge rests on general public specs (OAuth 2.0 RFC 6749 and
RFC 8252, OpenID Connect core, SAML 2.0 concepts): arcs, checklists, and
notes are re-authored in-house; nothing external is copied verbatim.

Ops:
- webauth_policy() - the policy rows
- webauth_index() - flow, protocol, and policy summary
- plan_webauth(target) - the 7-phase methodology arc
- oauth_flow_catalog(flow=None) - per-grant method steps; None = flow list
- oauth_grant_assessment(flow) - assessment arc rows for one grant
- jwt_analysis(header, payload, now=None, client_id=None) - decoded-claims
  structural analysis
- webauth_redirect_checks(uris, client_type=None) - structural redirect-URI
  validation rows plus the general checks
- webauth_token_storage() - storage positions + SOC detection pairings
- webauth_sso_surface(protocol=None) - SSO handshake checks; None = list
"""

from __future__ import annotations

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

# the standing policy carried on every op result; decoded_inspection_only
# states the no-secrets stance: claim dicts in, structure rows out
WEB_AUTH_POLICY = {
    "planner_only": True,
    "no_execution": True,
    "no_secrets_handling": True,
    "decoded_inspection_only": True,
    "no_credential_capture": True,
}

URI_MAX_LENGTH = 2048
URI_MAX_ROWS = 25

# JWT analysis knobs: the skew margin for caller-provided time anchors
SKEW_MARGIN = 300
CLAIM_KEY_MAX = 64
CLAIM_VALUE_MAX = 512
CLAIM_COUNT_MAX = 48
CLAIM_LIST_MAX = 32
CLAIM_TOTAL_MAX = 8192

JWT_HEADER_KEYS = ("alg", "kid", "typ")
JWT_PAYLOAD_CLAIMS = ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")

# registered-client classes (client_type parameter), with aliases
CLIENT_TYPES = {
    "confidential": ("confidential", "conf"),
    "public": ("public", "spa", "web"),
    "native": ("native", "mobile", "rfc8252"),
}

LOOPBACK_PREFIXES = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


# the 7-phase SSO/OAuth/JWT methodology arc; activities and sample commands
# are in-house wording; every command line stays at header/discovery level
WEB_AUTH_PHASES = (
    ("1-surface-map", "Map the SSO/OAuth surface",
     ["Pull the discovery document and inventory endpoints: /authorize, "
      "/token, /revoke, /introspect, /userinfo, /jwks.",
      "Separate the identity provider from the resource servers; note "
      "which domain hosts each endpoint.",
      "Record the JWKS rotation posture (public keys only; key material "
      "stays out of scope)."],
     ["curl -sS -D idp-headers.txt http://{target}/.well-known/openid-configuration",
      "curl -sS http://{target}/.well-known/jwks.json -o jwks.json",
      "# inventory rows: endpoint, domain, TLS, cache headers"]),
    ("2-grant-inventory", "Establish which grants live and which are legacy",
     ["List the enabled grant types per client from the provider registry "
      "or discovery document.",
      "Mark legacy grants (implicit, password-grant) as findings-class on "
      "modern surfaces.",
      "Note PKCE coverage for every client that drives a user session."],
     ["# op: oauth_flow_catalog() lists the grant set with status rows"]),
    ("3-client-config", "Review client configuration",
     ["Check every registered redirect URI against the validation rows "
      "(exact match, scheme, loopback, wildcard).",
      "Confirm state and nonce parameters exist on user-driven flows and "
      "are single-use.",
      "Scope sets per client: narrow to the workload; no wildcard scopes."],
     ["curl -sS -o /dev/null -D - 'http://{target}/.well-known/openid-configuration'",
      "# op: webauth_redirect_checks(<registered redirect URIs>)",
      "# expect: error responses carry a code plus a description only"]),
    ("4-token-lifecycle", "Storage and expiry review",
     ["Pin where each token class lives (memory, cookie, secure store) "
      "against the storage checklist.",
      "Confirm exchange lifetimes: short-lived access material, rotating "
      "refresh material, single-use codes.",
      "Check the revoke and introspection endpoints exist and answer."],
     ["# op: webauth_token_storage()"]),
    ("5-token-structure", "Decoded-claims structural analysis",
     ["During the authorized review, decode one sampled token's header and "
      "payload into dicts.",
      "Feed the decoded forms to the claims-analysis op; never encoded "
      "strings, never key material.",
      "Compare the rows against expectations: audience, issuer, expiry "
      "bounds, algorithm class."],
     ["# op: jwt_analysis(<decoded header>, <decoded payload>) - decoded "
      "inspection only"]),
    ("6-sso-surface", "SSO handshake validation method",
     ["Map the protocol in use (OpenID Connect, SAML) and its handshake "
      "steps on this surface.",
      "Run the protocol's binding checks: nonce/state/in-response-to "
      "handling, signature enforcement, conditions.",
      "Watch the session boundary: new session id at SSO establish-time."],
     ["# op: webauth_sso_surface('<protocol>')"]),
    ("7-reporting", "Findings, remediation, detection pairing",
     ["Per finding: the structure row, the remediation, and the SOC "
      "detection pairing.",
      "Executive summary first; retest criteria attached.",
      "Scrub everything of anything out of scope before it leaves the "
      "machine."],
     ["# op: webauth_token_storage() detection rows pair with every "
      "finding"]),
)

# OAuth grant method catalog: flow -> (aliases, status, clients note,
# steps ((step, note)...), assessments ((check, why)...)); in-house wording
OAUTH_FLOWS = {
    "authorization-code-pkce": {
        "aliases": ("authorization-code", "auth-code", "code", "pkce"),
        "status": "current",
        "clients": "confidential + public (PKCE recommended for both)",
        "steps": (
            ("authorize",
             "the client sends the user agent to the authorization endpoint "
             "with the exact registered redirect URI, response type code, "
             "state, and the PKCE challenge; the provider matches the "
             "redirect value before any consent screen"),
            ("consent",
             "the user approves exactly the scopes shown; the provider "
             "records the scope set the grant actually covered"),
            ("callback",
             "the authorization code returns through the registered "
             "redirect URI; the state value round-trips unchanged and "
             "single-use"),
            ("exchange",
             "code plus PKCE verifier change for tokens at the token "
             "endpoint over TLS; the verifier is single-use and the code "
             "TTL stays short (60 seconds or less)"),
            ("establish-session",
             "session material lands in its planned storage positions; "
             "check each position against the storage checklist"),
        ),
        "assessments": (
            ("pkce-enforced",
             "every public client shows PKCE parameters; absence is a "
             "finding row"),
            ("redirect-exact-match",
             "exact string match after canonicalization; prefix or "
             "wildcard matching is a finding row"),
            ("state-single-use",
             "state is unguessable, single-use, and bound to the browser "
             "session"),
            ("code-single-use",
             "a reused code must fail and, per RFC 6749, revoke tokens "
             "previously issued from it"),
            ("code-ttl",
             "the exchange must fail once the code is older than 60 "
             "seconds"),
            ("no-referrer-leakage",
             "the callback page never forwards the code in a Referer or a "
             "log line"),
        ),
    },
    "client-credentials": {
        "aliases": ("two-legged", "machine-to-machine", "m2m"),
        "status": "current",
        "clients": "confidential machine-to-machine only",
        "steps": (
            ("credential-present",
             "the confidential client presents its credential over the "
             "token endpoint's TLS channel; the credential value itself is "
             "out of scope for planner ops (availability review only)"),
            ("token",
             "an access token returns bound to the requested audience and "
             "scope set"),
            ("boundary",
             "resource servers enforce the audience; scopes carry the "
             "authorization level"),
        ),
        "assessments": (
            ("audience-restriction",
             "the token's audience names the intended resource server, not "
             "every service"),
            ("scope-minimization",
             "each deployment keeps the scope set as narrow as the "
             "workload allows"),
            ("network-pinning",
             "the token endpoint accepts the client only from known egress "
             "points"),
            ("no-log-material",
             "the credential and the issued token stay out of logs and "
             "traces"),
        ),
    },
    "device-code": {
        "aliases": ("device", "device-flow", "device-authorization"),
        "status": "current",
        "clients": "input-limited devices (consoles, TVs, CLI sign-in)",
        "steps": (
            ("device-authorization",
             "the device obtains a user code, a verification URI, and a "
             "polling interval"),
            ("user-consent",
             "the user completes sign-in at the verification URI - ideally "
             "on a separate device - and approves the stated scopes"),
            ("polling",
             "the device polls no faster than the published interval, "
             "honoring slow-down responses, until the code is granted or "
             "expires"),
        ),
        "assessments": (
            ("verification-uri",
             "the URI is complete (no bare code entry where avoidable) and "
             "served over https"),
            ("user-code-entropy",
             "the user code space blocks guessing within the code's TTL"),
            ("polling-caps",
             "failed attempts and the code TTL bound the polling window; "
             "slow-down responses are honored"),
            ("consent-scope-check",
             "the consent screen states the device name and scopes; "
             "unfamiliar device names are an alert hook"),
        ),
    },
    "implicit": {
        "aliases": ("response-type-token", "fragment-flow"),
        "status": "deprecated",
        "clients": "legacy SPAs only",
        "steps": (
            ("authorize-direct",
             "the authorization endpoint returns the access token inside "
             "the redirect fragment instead of a code"),
            ("consume",
             "page scripts read the fragment and hold the token in web "
             "storage"),
        ),
        "assessments": (
            ("grant-status",
             "deprecated grant - plan migration to authorization-code with "
             "PKCE as the finding"),
            ("tokens-in-urls",
             "fragments stay out of logs only by convention; any echo "
             "makes them leak"),
            ("no-refresh",
             "no refresh material exists, so expiry handling gets weak; "
             "migration removes the gap"),
            ("storage-exposure",
             "a token in web storage is script-readable by design; pair "
             "with the storage checklist"),
        ),
    },
    "password-grant": {
        "aliases": ("resource-owner-password-credentials", "ropc"),
        "status": "deprecated",
        "clients": "legacy only",
        "steps": (
            ("direct-post",
             "the client collects the resource owner's secret form and "
             "posts it to the token endpoint"),
            ("token",
             "tokens return for that same credential each run"),
        ),
        "assessments": (
            ("grant-status",
             "deprecated grant - plan migration to authorization-code with "
             "PKCE"),
            ("material-exposure",
             "the raw secret form flows through the client; the planner "
             "flags the class"),
            ("second-factor-breakage",
             "multi-factor and step-up flows cannot run through this "
             "grant"),
            ("migration-path",
             "an authorized migration plan replaces the grant before the "
             "review closes"),
        ),
    },
}

# SSO protocol method notes: protocol -> (aliases, handshake steps,
# validation checks); in-house wording, methodology rows only
SSO_PROTOCOLS = {
    "oidc": {
        "aliases": ("openid", "openid-connect", "oidc"),
        "handshake": (
            ("discovery",
             "the discovery document publishes endpoints, supported "
             "scopes, id-token conventions, and the JWKS location"),
            ("authorize",
             "the request carries nonce, state, and the registered "
             "redirect URI; the nonce binds the later id token to this "
             "session"),
            ("callback",
             "the code returns via the registered redirect with state "
             "unchanged"),
            ("exchange",
             "the exchange returns the id token plus any access/refresh "
             "tokens"),
            ("session",
             "the session cookie establishes at the application domain; "
             "the id token is a receipt, not the session token"),
        ),
        "checks": (
            ("nonce-binding",
             "nonce is unguessable, per-session, single-use, and matched "
             "against the id token's nonce claim"),
            ("state-binding",
             "state survives round-trips unchanged and is single-use"),
            ("idp-initiated",
             "identity-provider-initiated flows carry signed relay state "
             "pinned to the client, or stay disabled"),
            ("logout-consistency",
             "front-channel and back-channel logout expectations match "
             "what the client actually implements"),
            ("cookie-flags",
             "the session cookie carries HttpOnly, Secure, and a "
             "deliberate SameSite choice at provider and application "
             "domains"),
            ("iss-registration",
             "the id token's issuer matches the registered provider "
             "exactly (scheme plus host)"),
        ),
    },
    "saml": {
        "aliases": ("saml", "saml2", "saml-2-0"),
        "handshake": (
            ("sp-metadata",
             "service-provider metadata fixes the audience, the consumer "
             "endpoint, and the binding"),
            ("binding",
             "the provider answers over the agreed binding and the "
             "response carries its signature and conditions"),
            ("consume",
             "the consumer endpoint validates the response before "
             "granting the session"),
        ),
        "checks": (
            ("signature-enforced",
             "responses carry a signature the consumer verifies; unsigned "
             "acceptance is a finding row"),
            ("audience-recipient",
             "audience restriction and recipient conditions name this "
             "exact consumer endpoint"),
            ("response-state-binding",
             "in-response-to matches an issued request; provider-initiated "
             "flows pin the relay state"),
            ("timing-windows",
             "not-on-or-after and not-before windows allow only a small "
             "tolerance"),
            ("xml-hardening",
             "the consumer's parser settings follow the platform's "
             "hardening notes (methodology row; details live with the "
             "platform review)"),
            ("session-fixation",
             "a new session id is established at the SSO boundary; the "
             "class matches any login flow"),
        ),
    },
}

# storage position checklist + SOC detection pairings (in-house wording)
STORAGE_POSITIONS = (
    ("access-token",
     "memory or an HttpOnly Secure SameSite cookie behind a "
     "backend-for-frontend where the architecture allows; web storage only "
     "as a documented last resort"),
    ("refresh-token",
     "secure storage tied to the client identity; rotate on every use and "
     "treat reuse of a rotated value as a family-compromise signal"),
    ("authorization-code",
     "single-use, short TTL, bound to client and PKCE verifier; delivered "
     "exactly once through the registered redirect"),
    ("session-cookie",
     "the application session lives in the cookie, not in tokens; "
     "HttpOnly, Secure, deliberate SameSite, scoped to the application "
     "domain"),
    ("id-token",
     "a receipt the client reads once; no retention beyond "
     "troubleshooting windows"),
    ("cookie-flags",
     "HttpOnly, Secure, SameSite=Lax or Strict per flow needs; consider "
     "partitioned cookies where third-party contexts remain"),
)

STORAGE_DETECTION = (
    ("issuance-pattern",
     "authorize/token volume per client against the baseline; bursts at "
     "odd hours are alert hooks"),
    ("refresh-reuse",
     "an attempt to use a rotated refresh token flags the whole family "
     "for invalidation"),
    ("audience-mismatch",
     "resource servers log token presentation outside their audience"),
    ("jwks-rotation",
     "JWKS key-set changes lacking a scheduled rotation date"),
    ("redirect-probing",
     "spikes in authorize-endpoint error answers signal redirect-mismatch "
     "probing"),
    ("logout-anomalies",
     "back-channel logout failures after provider session changes"),
)


def _flow_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("flow must be a non-empty string")
    form = value.strip().lower()
    for canonical, spec in OAUTH_FLOWS.items():
        if form in spec["aliases"] or form == canonical:
            return canonical
    raise ValueError("unknown OAuth flow %r - known: %s"
                     % (value, ", ".join(sorted(OAUTH_FLOWS))))


def _protocol_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("protocol must be a non-empty string")
    form = value.strip().lower()
    for canonical, spec in SSO_PROTOCOLS.items():
        if form in spec["aliases"] or form == canonical:
            return canonical
    raise ValueError("unknown SSO protocol %r - known: %s"
                     % (value, ", ".join(sorted(SSO_PROTOCOLS))))


def _client_type_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("client_type must be a non-empty string when given")
    form = value.strip().lower()
    for canonical, aliases in CLIENT_TYPES.items():
        if form in aliases or form == canonical:
            return canonical
    raise ValueError("unknown client_type %r - known: %s"
                     % (value, ", ".join(sorted(CLIENT_TYPES))))


def wa_scrub_uri(value):
    """Normalize a redirect-URI string and reject injection attempts.

    Wraps the shared target scrub, then validates the scheme/authority
    shape. Structural findings (fragments, userinfo, wildcards, loopback)
    are ROWS the checks op reports - not rejected inputs.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("uri must be a non-empty string")
    u = wp_scrub_target(value)
    if len(u) > URI_MAX_LENGTH:
        raise ValueError("uri too long (cap %d)" % URI_MAX_LENGTH)
    scheme, sep, rest = u.partition("://")
    chars = set(scheme)
    letters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    digits = set("0123456789")
    extras = set("+.-")
    if (not sep or not scheme or not scheme[0] in letters
            or not chars.issubset(letters | digits | extras)):
        raise ValueError("uri must carry a scheme and authority: %r" % value)
    head = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if not head or head.startswith("@"):
        raise ValueError("uri missing an authority: %r" % value)
    return u


def _numeric(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def wa_scrub_claims(mapping, what="claims"):
    """Structurally validate a DECODED claims dict (headers or payload).

    Contract: flat JSON-like dict - string keys, primitive values (or a
    shallow list of primitives). Rejects nested containers, control
    characters, and oversize shapes with ValueError naming the field.
    """
    if not isinstance(mapping, dict):
        raise ValueError("%s must be a decoded dict, not %s"
                         % (what, type(mapping).__name__))
    total = 0
    clean = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not key or len(key) > CLAIM_KEY_MAX:
            raise ValueError("%s: bad key %r (non-empty string, cap %d)"
                             % (what, key, CLAIM_KEY_MAX))
        if isinstance(value, bool) or value is None:
            clean[key] = value
        elif isinstance(value, (int, float, str)):
            if isinstance(value, str):
                if len(value) > CLAIM_VALUE_MAX:
                    raise ValueError("%s.%s: value over cap %d"
                                     % (what, key, CLAIM_VALUE_MAX))
                if any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise ValueError(
                        "%s.%s: control characters rejected" % (what, key))
            clean[key] = value
        elif isinstance(value, list):
            if len(value) > CLAIM_LIST_MAX:
                raise ValueError("%s.%s: list over cap %d"
                                 % (what, key, CLAIM_LIST_MAX))
            members = []
            for item in value:
                if isinstance(item, bool) or item is None:
                    members.append(item)
                elif isinstance(item, (int, float, str)):
                    if isinstance(item, str) and any(
                            ord(c) < 32 or ord(c) == 127 for c in item):
                        raise ValueError(
                            "%s.%s: control characters in list member"
                            % (what, key))
                    if isinstance(item, str) and len(item) > CLAIM_VALUE_MAX:
                        raise ValueError("%s.%s: member over cap %d"
                                         % (what, key, CLAIM_VALUE_MAX))
                    members.append(item)
                else:
                    raise ValueError("%s.%s: nested container rejected - "
                                     "flatten into separate rows"
                                     % (what, key))
            clean[key] = members
        else:
            raise ValueError("%s.%s: nested container rejected - flatten "
                             "into separate rows" % (what, key))
        total += len(key) + len(str(clean[key]))
    if len(mapping) > CLAIM_COUNT_MAX:
        raise ValueError("%s: over %d keys" % (what, CLAIM_COUNT_MAX))
    if total > CLAIM_TOTAL_MAX:
        raise ValueError("%s: total size over cap %d"
                         % (what, CLAIM_TOTAL_MAX))
    return clean


def _row(claim, present, row_class, note):
    return {"claim": claim, "present": present, "class": row_class,
            "note": note}


def _numeric_rows(name, value, now):
    """Rows for a numeric timestamp claim (exp/nbf/iat semantics)."""
    if not _numeric(value):
        return _row(name, True, "finding",
                    "%s must be a number; this shape is a type finding row"
                    % name)
    if now is None:
        suffix = ("pass now (epoch seconds) with the review's time anchor "
                  "to evaluate the window")
        return _row(name, True, "info", "%s present; %s" % (name, suffix))
    if name == "exp":
        if now >= value:
            return _row(name, True, "finding", "token expired at review time")
        return _row(name, True, "ok",
                    "expiry still ahead; expect a short TTL on access "
                    "material")
    if name == "nbf":
        if now < value:
            return _row(name, True, "info",
                        "not valid yet (may be legitimate scheduling)")
        return _row(name, True, "ok", "valid already")
    # iat
    if now < value - SKEW_MARGIN:
        return _row(name, True, "finding",
                    "issued beyond the %d-second skew margin - finding row"
                    % SKEW_MARGIN)
    return _row(name, True, "ok", "issued inside the skew margin")


def _parse_uri_rows(uri):
    """Structural rows for one scrubbed redirect URI."""
    scheme, _, rest = uri.partition("://")
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    after_authority = rest[len(authority):]
    path = after_authority.split("?", 1)[0].split("#", 1)[0]
    has_query = "?" in rest
    has_fragment = "#" in rest
    wildcard = "*" in authority
    userinfo = "@" in authority
    host = authority.rsplit("@", 1)[-1] if userinfo else authority
    host_lower = host.lower().strip("[]")
    loopback = any(host_lower.startswith(p) for p in LOOPBACK_PREFIXES)
    notes = []
    custom_scheme = scheme.lower() not in ("http", "https")
    if scheme.lower() == "http":
        notes.append("cleartext redirect endpoint - finding-class row")
    elif custom_scheme:
        notes.append("custom scheme %s" % scheme.lower())
    if wildcard:
        notes.append("wildcard authority implies prefix matching - "
                     "finding-class row; exact match is the baseline")
    if userinfo:
        notes.append("userinfo in the authority - suspicious redirect shape, "
                     "finding-class row")
    if has_fragment:
        notes.append("RFC 6749 forbids fragment components in redirect "
                     "URIs - finding-class row")
    if has_query:
        notes.append("query content present; servers echo none of it back - "
                     "check the registration row")
    if not path or path == "/":
        notes.append("apex redirect with no path - exact-path registration "
                     "is recommended")
    if loopback:
        notes.append("loopback endpoint row")
    return {"uri": uri, "scheme": scheme.lower(), "wildcard": wildcard,
            "userinfo": bool(userinfo), "loopback": loopback,
            "path": path, "fragment": has_fragment, "notes": notes}


def _redirect_notes_by_client_type(scheme, loopback, client_type):
    notes = []
    custom = scheme not in ("http", "https")
    if custom and client_type == "native":
        notes.append("custom scheme matches the RFC 8252 native profile - "
                     "prefer the https loopback variant where possible")
    elif custom:
        notes.append("custom scheme on a web client - finding-class row "
                     "unless the registration explicitly allows it")
    if loopback and client_type == "native":
        notes.append("loopback endpoints match the native profile - "
                     "planned, not flagged")
    elif loopback:
        notes.append("loopback on a web or confidential client - "
                     "finding-class row (dev-only pattern)")
    return notes


class WebAuthMixin:
    """SSO/OAuth/JWT surface planning ops (no execution; no secrets)."""

    @staticmethod
    def _wa_scrub_target(target):
        """Normalize a target and reject injection attempts (shared helper)."""
        return wp_scrub_target(target)

    @staticmethod
    def _wa_scrub_uri(value):
        """Normalize a redirect-URI string (shared helper)."""
        return wa_scrub_uri(value)

    @staticmethod
    def _wa_scrub_claims(mapping, what="claims"):
        """Validate a decoded claims dict (shared helper)."""
        return wa_scrub_claims(mapping, what=what)

    def _wa_guard(self, target):
        """Scrub + consult the host agent's target gate when it provides one."""
        t = self._wa_scrub_target(target)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(t)
            if not ok:
                raise ValueError("target rejected by host agent gate: %s"
                                 % msg)
        return t

    def webauth_policy(self) -> dict:
        """The WebAuth policy rows every op result carries."""
        return dict(WEB_AUTH_POLICY)

    def webauth_index(self) -> dict:
        """Flow, protocol, and policy summary for the WebAuth surface."""
        return {"flows": sorted(OAUTH_FLOWS),
                "protocols": sorted(SSO_PROTOCOLS),
                "policy": dict(WEB_AUTH_POLICY)}

    def plan_webauth(self, target):
        """The 7-phase SSO/OAuth/JWT methodology plan for a target."""
        t = self._wa_guard(target)
        phases = []
        for phase, goal, activities, commands in WEB_AUTH_PHASES:
            phases.append({"phase": phase, "goal": goal,
                           "activities": list(activities),
                           "sample_commands": [
                               c.replace("{target}", t) for c in commands],
                           "policy": dict(WEB_AUTH_POLICY)})
        return {"target": t, "phases": phases,
                "policy": dict(WEB_AUTH_POLICY)}

    def oauth_flow_catalog(self, flow=None):
        """OAuth grant method catalog; None returns the flow list."""
        if flow is None:
            return {"flows": [{"flow": name,
                               "status": OAUTH_FLOWS[name]["status"],
                               "clients": OAUTH_FLOWS[name]["clients"]}
                              for name in sorted(OAUTH_FLOWS)],
                    "policy": dict(WEB_AUTH_POLICY)}
        canonical = _flow_for(flow)
        spec = OAUTH_FLOWS[canonical]
        return {"flow": canonical, "status": spec["status"],
                "clients": spec["clients"],
                "steps": [{"step": s, "note": n} for s, n in spec["steps"]],
                "policy": dict(WEB_AUTH_POLICY)}

    def oauth_grant_assessment(self, flow):
        """Assessment arc rows for one OAuth grant flow."""
        canonical = _flow_for(flow)
        spec = OAUTH_FLOWS[canonical]
        return {"flow": canonical, "status": spec["status"],
                "assessments": [{"check": c, "why": w}
                                for c, w in spec["assessments"]],
                "policy": dict(WEB_AUTH_POLICY)}

    def jwt_analysis(self, header, payload, now=None, client_id=None):
        """Decoded-claims structural analysis (no key material; no decoding).

        header/payload are decoded claim dicts from the authorized
        engagement; encoded token strings are never accepted and never
        decoded here. now: optional epoch-seconds anchor from the review;
        client_id: optional presenting-client id to evaluate audience
        coverage. Returns per-claim rows.
        """
        hdr = self._wa_scrub_claims(header, what="header")
        pl = self._wa_scrub_claims(payload, what="payload")
        if now is not None:
            if not _numeric(now):
                raise ValueError(
                    "now must be epoch seconds (number), not %s"
                    % type(now).__name__)
        cid = None
        if client_id is not None:
            cid = wp_scrub_target(client_id)
            if len(cid) > 128:
                raise ValueError("client_id too long (cap 128)")
        header_rows = []
        seen_header = set()
        for name in JWT_HEADER_KEYS:
            seen_header.add(name)
            header_rows.append(self._jwt_header_row(name, hdr.get(name)))
        for name in sorted(set(hdr) - seen_header):
            header_rows.append(_row(name, True, "custom",
                                    "non-standard header parameter - "
                                    "profile review row"))
        payload_rows = []
        seen_claims = set()
        for name in JWT_PAYLOAD_CLAIMS:
            seen_claims.add(name)
            payload_rows.append(
                self._jwt_payload_row(name, pl.get(name), name in pl,
                                      now, cid))
        for name in sorted(set(pl) - seen_claims):
            payload_rows.append(_row(name, True, "custom",
                                     "non-registered claim - profile review "
                                     "row"))
        return {"header": header_rows, "payload": payload_rows,
                "timing": {"now_evaluated": now is not None,
                           "skew_margin": SKEW_MARGIN},
                "policy": dict(WEB_AUTH_POLICY)}

    def _jwt_header_row(self, name, value):
        if name == "alg":
            if value is None:
                return _row("alg", False, "finding",
                            "algorithm absent - the verifier's allowlist "
                            "must pin acceptable algorithms; absence is a "
                            "finding row at review time")
            if not isinstance(value, str):
                return _row("alg", True, "finding",
                            "alg must be a string; this shape is a type "
                            "finding row")
            form = value.strip()
            upper = form.upper()
            if upper == "NONE":
                return _row("alg", True, "finding",
                            "unsigned algorithm class - the verifier must "
                            "refuse it; planning check row")
            if upper.startswith("HS"):
                return _row("alg", True, "info",
                            "symmetric class - shared-secret verification "
                            "material sits outside these ops; allowlist "
                            "note only")
            if upper[0:2] in ("RS", "ES", "PS", "ED"):
                return _row("alg", True, "ok",
                            "asymmetric class - verify against the "
                            "published JWKS; the kid picks the key row")
            return _row("alg", True, "finding",
                        "unknown algorithm class - verifier allowlist "
                        "enforcement is the finding row")
        if name == "kid":
            if value is None:
                return _row("kid", False, "info",
                            "no key id - single-key verification; rotation "
                            "monitoring stays simpler")
            if not isinstance(value, str) or not value:
                return _row("kid", True, "finding",
                            "kid must be a non-empty string; a mismatched "
                            "key id is a verifier-class check row")
            return _row("kid", True, "info",
                        "key id present - JWKS pinning and rotation check "
                        "rows apply")
        if name == "typ":
            if value is None:
                return _row("typ", False, "info",
                            "no typ parameter - surface convention check "
                            "row only")
            if not isinstance(value, str) or not value:
                return _row("typ", True, "finding",
                            "typ must be a non-empty string")
            return _row("typ", True, "info",
                        "typ present - match the surface's declared "
                        "convention (typically at+jwt receipts)")

    def _jwt_payload_row(self, name, value, present, now, cid):
        if not present or value is None:
            return self._jwt_absent_note(name)
        if name in ("exp", "nbf", "iat"):
            return _numeric_rows(name, value, now)
        if name in ("iss", "sub", "jti"):
            if not isinstance(value, str):
                return _row(name, True, "finding",
                            "%s must be a string; this shape is a type "
                            "finding row" % name)
            if not value:
                return _row(name, True, "finding",
                            "empty %s value - finding row" % name)
            note = {
                "iss": "match the expected issuer (scheme plus host) "
                       "registered for this surface",
                "sub": "stable subject identifier; correlation policy "
                       "follows the identity provider's design review",
                "jti": "single-use tracking at the verifier addresses the "
                       "replay class",
            }[name]
            return _row(name, True, "ok", note)
        # audience
        members = value if isinstance(value, list) else [value]
        for member in members:
            if not isinstance(member, str):
                return _row("aud", True, "finding",
                            "aud members must be strings; this shape is a "
                            "type finding row")
        if not members:
            return _row("aud", True, "finding",
                        "empty audience - finding row")
        if cid is None:
            return _row("aud", True, "info",
                        "pass client_id to evaluate audience coverage")
        if any(member == cid for member in members):
            return _row("aud", True, "ok",
                        "audience covers the presenting client")
        return _row("aud", True, "finding",
                    "audience does not cover the presenting client - "
                    "finding row")

    def _jwt_absent_note(self, name):
        notes = {
            "iss": ("finding",
                    "issuer absent - verifier must pin the expected issuer; "
                    "finding row"),
            "sub": ("info",
                    "subject absent - valid for machine flows only; review "
                    "row"),
            "aud": ("finding",
                    "audience absent - verifier must pin the accepted "
                    "audience; finding row"),
            "exp": ("finding",
                    "expiry absent - removes the hard expiry bound; finding "
                    "row"),
            "nbf": ("info", "not-before absent - optional claim"),
            "iat": ("info", "issued-at absent - optional for machine flows"),
            "jti": ("info",
                    "id absent - recommended for single-use semantics"),
        }
        row_class, note = notes[name]
        return _row(name, False, row_class, note)

    def webauth_redirect_checks(self, uris, client_type=None):
        """Structural redirect-URI validation rows plus the general checks.

        uris: up to 25 redirect URIs (one per row, without multi-parameter
        query strings - the shared scrub rejects shell metacharacters).
        client_type: confidential / public / native, or None for neutral
        rows. Findings are structural ROWS; nothing is issued here.
        """
        if isinstance(uris, str):
            uris = [uris]
        if not isinstance(uris, (list, tuple)):
            raise ValueError("uris must be a list of redirect URI strings")
        if not uris:
            raise ValueError("give at least one redirect URI")
        if len(uris) > URI_MAX_ROWS:
            raise ValueError("over %d redirect URIs; split the review"
                             % URI_MAX_ROWS)
        ctype = None
        if client_type is not None:
            ctype = _client_type_for(client_type)
        rows = []
        for raw in uris:
            u = self._wa_scrub_uri(raw)
            parsed = _parse_uri_rows(u)
            parsed["notes"].extend(_redirect_notes_by_client_type(
                parsed["scheme"], parsed["loopback"], ctype))
            rows.append(parsed)
        general = [
            "exact string match against the registered value after "
            "canonicalization - never prefix or substring matching",
            "state parameter unguessable, single-use, and bound to the "
            "browser session",
            "nonce bound per OIDC session and matched against the id token",
            "PKCE binding for every public client",
            "no open-redirect parameter echoes the caller's URI parts",
            "the registration's URI list is reviewed per client, not per "
            "reviewer taste",
            "error responses carry a code plus a description only",
        ]
        return {"uris": rows, "general_checks": general,
                "client_type": ctype, "policy": dict(WEB_AUTH_POLICY)}

    def webauth_token_storage(self):
        """Token storage position checklist plus the SOC pairings."""
        return {"positions": [{"position": p, "note": n}
                              for p, n in STORAGE_POSITIONS],
                "detection": [{"check": c, "note": n}
                              for c, n in STORAGE_DETECTION],
                "policy": dict(WEB_AUTH_POLICY)}

    def webauth_sso_surface(self, protocol=None):
        """SSO handshake checks for a protocol; None returns the list."""
        if protocol is None:
            return {"protocols": sorted(SSO_PROTOCOLS),
                    "policy": dict(WEB_AUTH_POLICY)}
        canonical = _protocol_for(protocol)
        spec = SSO_PROTOCOLS[canonical]
        return {"protocol": canonical,
                "handshake": [{"step": s, "note": n}
                              for s, n in spec["handshake"]],
                "checks": [{"check": c, "note": n}
                           for c, n in spec["checks"]],
                "policy": dict(WEB_AUTH_POLICY)}