"""
Wazuh API client for the agentic-ai SOC layer.

Polls the Wazuh manager REST API, diffs new alerts against a SQLite-backed
seen-set, and feeds them into SecurityOperationsAgent via create_alert().

Design notes
------------
- JWT auth via POST /security/user/authenticate; token cached for ~9 min
  (server-issued tokens are valid 15 min, we refresh early).
- The poll loop runs on a background daemon thread; safe to call from any
  context (main, tests, web).
- The seen-set is stored in the existing StateStore so we don't re-triage
  alerts across process restarts.
- Rule-level mapping (Wazuh levels 0-15) -> AlertSeverity mirrors SANS /
  Wazuh conventions: >=13 critical, >=10 high, >=7 medium, >=4 low, else info.
- All HTTP errors are swallowed at the boundary; the client returns an
  empty list on failure and the caller can decide whether to alert.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

import urllib.error
import urllib.parse
import urllib.request

from agentic_ai.infrastructure.utils import utcnow

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Config & defaults
# --------------------------------------------------------------------------- #

DEFAULT_BASE_URL = "https://192.168.1.106:55000"
DEFAULT_USERNAME = "wazuh-wui"
# Password is intentionally NOT defaulted here. Inject from environment.
ENV_PASSWORD = "WAZUH_API_PASSWORD"
ENV_BASE_URL = "WAZUH_API_URL"
ENV_USERNAME = "WAZUH_API_USERNAME"

POLL_INTERVAL_SEC = int(os.environ.get("WAZUH_POLL_INTERVAL", "15"))
JWT_TTL_SEC = 9 * 60  # refresh 6 minutes before 15-min expiry
DEFAULT_PAGE_LIMIT = 100


# --------------------------------------------------------------------------- #
# OpenSearch indexer client (where alerts actually live in 4.14+)
# --------------------------------------------------------------------------- #

DEFAULT_INDEXER_URL = "https://127.0.0.1:9200"
ENV_INDEXER_URL = "WAZUH_INDEXER_URL"
ENV_INDEXER_USER = "WAZUH_INDEXER_USERNAME"
ENV_INDEXER_PASSWORD = "WAZUH_INDEXER_PASSWORD"


class WazuhIndexerClient:
    """Tiny OpenSearch client for the Wazuh indexer.

    Used to query `wazuh-alerts-*` directly because the /alerts REST endpoint
    is not exposed in Wazuh 4.14. All alerts ingested by the manager land in
    these indices; this is the source of truth for SOC automation.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_INDEXER_URL,
        username: str = "admin",
        password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password or os.environ.get(ENV_INDEXER_PASSWORD)
        if not self.password:
            raise WazuhHTTPError(
                f"WazuhIndexerClient needs a password; set {ENV_INDEXER_PASSWORD}"
            )
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _request(
        self, method: str, path: str, json_body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = self.base_url + path
        data = None
        headers = {"Accept": "application/json"}
        if json_body is not None:
            import json as _json
            data = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        import base64 as _b64
        raw = f"{self.username}:{self.password}".encode("utf-8")
        headers["Authorization"] = f"Basic {_b64.b64encode(raw).decode('ascii')}"

        req = urllib.request.Request(url=url, data=data, method=method, headers=headers)
        ctx = None
        if not self.verify_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return _safe_json(body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise WazuhHTTPError(f"HTTP {e.code} on {method} {path}: {body[:200]}") from e
        except urllib.error.URLError as e:
            raise WazuhHTTPError(f"URL error on {method} {path}: {e}") from e

    def search_alerts(
        self,
        size: int = 100,
        sort_desc: bool = True,
        query: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Search wazuh-alerts-* and return hits as plain dicts."""
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc" if sort_desc else "asc"}}],
            "query": query or {"match_all": {}},
        }
        try:
            resp = self._request("POST", "/wazuh-alerts*/_search", json_body=body)
        except WazuhHTTPError as e:
            if "HTTP 404" in str(e):
                logger.info("no wazuh-alerts-* indices exist yet (no agents reporting)")
                return []
            raise
        hits = (resp.get("hits") or {}).get("hits") or []
        # Each hit is {"_index": ..., "_source": {...}, ...}; return the source.
        return [h.get("_source", {}) for h in hits]

    def count_alerts(self, query: Optional[Dict[str, Any]] = None) -> int:
        try:
            resp = self._request("POST", "/wazuh-alerts*/_count", json_body={"query": query or {"match_all": {}}})
        except WazuhHTTPError as e:
            if "HTTP 404" in str(e):
                return 0
            raise
        return int((resp.get("count") or 0))


# --------------------------------------------------------------------------- #
# Mapping helpers
# --------------------------------------------------------------------------- #

def map_level_to_severity(level: int) -> str:
    """Map Wazuh rule level (0-15) to AlertSeverity string.

    >=13  critical   (auth failure, malware, rootkit)
    >=10  high       (multiple failed logins, policy violation)
    >=7   medium     (generic error, unusual pattern)
    >=4   low        (informational with action)
    <4    informational
    """
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


# --------------------------------------------------------------------------- #
# Token + HTTP plumbing
# --------------------------------------------------------------------------- #

@dataclass
class Token:
    value: str
    expires_at: datetime

    def is_valid(self) -> bool:
        return bool(self.value) and utcnow() < self.expires_at


class WazuhHTTPError(RuntimeError):
    pass


class WazuhClient:
    """Thin client for the Wazuh 4.x REST API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        username: str = DEFAULT_USERNAME,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password or os.environ.get(ENV_PASSWORD)
        if not self.password:
            raise WazuhHTTPError(
                f"WazuhClient needs a password; set {ENV_PASSWORD} or pass it explicitly"
            )
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token: Optional[Token] = None
        self._lock = threading.Lock()

    # ---------- low-level request ---------- #

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        auth: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        data = None
        headers = {"Accept": "application/json"}
        if json_body is not None:
            import json as _json
            data = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth and self._token and self._token.is_valid():
            headers["Authorization"] = f"Bearer {self._token.value}"
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(url=url, data=data, method=method, headers=headers)
        ctx = None
        if not self.verify_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return _safe_json(body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise WazuhHTTPError(f"HTTP {e.code} on {method} {path}: {body[:200]}") from e
        except urllib.error.URLError as e:
            raise WazuhHTTPError(f"URL error on {method} {path}: {e}") from e

    # ---------- token lifecycle ---------- #

    def authenticate(self, force: bool = False) -> Token:
        with self._lock:
            if not force and self._token and self._token.is_valid():
                return self._token
            # Wazuh 4.x authenticate endpoint requires HTTP Basic Auth with the
            # raw username/password, not a JSON body. See:
            # https://documentation.wazuh.com/current/user-manual/api/reference.html
            import base64 as _b64
            raw = f"{self.username}:{self.password}".encode("utf-8")
            basic = _b64.b64encode(raw).decode("ascii")
            try:
                resp = self._request(
                    "POST",
                    "/security/user/authenticate",
                    auth=False,
                    extra_headers={"Authorization": f"Basic {basic}"},
                )
            except WazuhHTTPError as e:
                logger.error("Wazuh authenticate failed: %s", e)
                raise
            token_str = (resp.get("data") or {}).get("token", "")
            if not token_str:
                raise WazuhHTTPError(f"no token in auth response: {resp}")
            self._token = Token(value=token_str, expires_at=utcnow() + timedelta(seconds=JWT_TTL_SEC))
            return self._token

    # ---------- high-level API ---------- #

    def list_agents(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        self.authenticate()
        params: Dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        resp = self._request("GET", "/agents", params=params)
        return (resp.get("data") or {}).get("affected_items", []) or []

    def list_alerts(
        self,
        limit: int = DEFAULT_PAGE_LIMIT,
        sort: str = "-timestamp",
        since_ts: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return recent alerts from the manager REST API.

        NOTE: in Wazuh 4.14 the /alerts REST endpoint is NOT exposed
        (it returns 404). The canonical alert store is the OpenSearch indexer
        at `wazuh-alerts-*`. Use WazuhIndexerClient for that, or call
        list_alerts() and accept an empty list if the endpoint is missing.
        """
        self.authenticate()
        params: Dict[str, Any] = {"limit": limit, "sort": sort}
        if since_ts:
            params["timestamp"] = f">={since_ts}"
        try:
            resp = self._request("GET", "/alerts", params=params)
            return (resp.get("data") or {}).get("affected_items", []) or []
        except WazuhHTTPError as e:
            if "HTTP 404" in str(e):
                logger.debug("Wazuh /alerts not exposed; use WazuhIndexerClient instead")
                return []
            raise

    def manager_info(self) -> Dict[str, Any]:
        self.authenticate()
        resp = self._request("GET", "/manager/info")
        items = (resp.get("data") or {}).get("affected_items", [])
        return items[0] if items else {}

    def ping(self) -> bool:
        """Cheap reachability check; any HTTP response (even 401) is healthy."""
        try:
            self._request("GET", "/", auth=False)
            return True
        except WazuhHTTPError as e:
            # 401 = server alive, just wants auth. Anything else is a real failure.
            if "HTTP 401" in str(e):
                return True
            return False


def _safe_json(body: str) -> Dict[str, Any]:
    import json as _json
    try:
        parsed = _json.loads(body)
        return parsed if isinstance(parsed, dict) else {"data": parsed}
    except ValueError:
        return {"raw": body}


# --------------------------------------------------------------------------- #
# Polling + diff (seen-set lives in StateStore)
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Seen-store (tiny SQLite-backed set, no Redis required)
# --------------------------------------------------------------------------- #

class SeenStore:
    """Persistent seen-alert set; survives process restarts.

    Stored as (alert_id, first_seen_iso) rows in a single SQLite table.
    The default db path lives under ~/.openclaw/state/.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get(
            "WAZUH_SEEN_DB",
            os.path.expanduser("~/.openclaw/state/wazuh_seen.sqlite"),
        )
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS seen_alerts ("
            "  alert_id TEXT PRIMARY KEY,"
            "  first_seen TEXT NOT NULL"
            ")"
        )
        self._conn.commit()

    def has(self, alert_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM seen_alerts WHERE alert_id=? LIMIT 1", (alert_id,)
            )
            return cur.fetchone() is not None

    def add(self, alert_id: str, ts_iso: Optional[str] = None) -> None:
        ts = ts_iso or utcnow().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_alerts (alert_id, first_seen) VALUES (?, ?)",
                (alert_id, ts),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass


SEEN_KEY_PREFIX = "wazuh:seen_alert:"


def _seen_key(alert_id: str) -> str:
    return f"{SEEN_KEY_PREFIX}{alert_id}"


@dataclass
class WazuhPollerConfig:
    base_url: str = DEFAULT_BASE_URL
    username: str = DEFAULT_USERNAME
    password: Optional[str] = None
    poll_interval_sec: int = POLL_INTERVAL_SEC
    page_limit: int = DEFAULT_PAGE_LIMIT
    on_alerts: Optional[Callable[[List[Dict[str, Any]]], None]] = None
    # Optional indexer (OpenSearch) — Wazuh 4.x removed the /alerts REST
    # endpoint, so the poller prefers the indexer when configured.
    indexer: Optional["WazuhIndexerClient"] = None


class WazuhPoller:
    """Background poller: fetch alerts, diff against seen-set, call on_alerts.

    Thread-safe; stop() cleanly joins the worker thread.

    On Wazuh 4.14 the manager REST /alerts endpoint is not exposed (returns
    404). Pass an `indexer` (WazuhIndexerClient) in the config; if absent, the
    poller falls back to the REST API (which will return [] on 4.x) and logs
    a warning so the operator notices.
    """

    def __init__(self, config: WazuhPollerConfig, seen_store: Optional[SeenStore] = None):
        self.config = config
        self.seen = seen_store or SeenStore()
        self.client = WazuhClient(
            base_url=config.base_url,
            username=config.username,
            password=config.password,
        )
        self.indexer = config.indexer
        if not self.indexer:
            logger.warning(
                "WazuhPoller has no indexer; /alerts REST endpoint is missing "
                "on Wazuh 4.x. Pass config.indexer=WazuhIndexerClient(...)."
            )
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_poll: Optional[datetime] = None
        self._last_count: int = 0
        self._lock = threading.Lock()

    # ---------- core diff ---------- #

    def fetch_new_alerts(self, since_ts: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Single-shot poll: return alerts we haven't seen before."""
        ts = since_ts or (self._last_poll or (utcnow() - timedelta(minutes=10)))
        since_iso = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            if self.indexer is not None:
                # Wazuh 4.x canonical path: query the OpenSearch indexer.
                # We use a range query on @timestamp so the indexer filters
                # server-side (cheaper than fetching the page_limit blindly).
                size = self.config.page_limit
                body = {
                    "size": size,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "query": {
                        "range": {"@timestamp": {"gte": since_iso}}
                    },
                }
                resp = self.indexer._request("POST", "/wazuh-alerts-*/_search", json_body=body)
                hits = (resp.get("hits") or {}).get("hits") or []
                alerts = [h.get("_source", {}) for h in hits]
            else:
                # Legacy path: Wazuh REST /alerts. Returns [] on 4.x.
                alerts = self.client.list_alerts(
                    limit=self.config.page_limit, since_ts=since_iso
                )
        except WazuhHTTPError as e:
            logger.warning("Wazuh fetch failed: %s", e)
            return []
        new_alerts = []
        for a in alerts:
            alert_id = _alert_id(a)
            if not alert_id:
                continue
            if not self.seen.has(alert_id):
                new_alerts.append(a)
                self.seen.add(alert_id)
        with self._lock:
            self._last_poll = utcnow()
            self._last_count = len(new_alerts)
        return new_alerts

    # ---------- background loop ---------- #

    def _loop(self) -> None:
        logger.info(
            "WazuhPoller started: base_url=%s interval=%ds",
            self.config.base_url, self.config.poll_interval_sec,
        )
        while not self._stop.is_set():
            try:
                alerts = self.fetch_new_alerts()
                if alerts and self.config.on_alerts:
                    try:
                        self.config.on_alerts(alerts)
                    except Exception:  # callback errors must not kill the loop
                        logger.exception("on_alerts callback raised")
            except Exception:
                logger.exception("WazuhPoller loop iteration failed")
            self._stop.wait(self.config.poll_interval_sec)
        logger.info("WazuhPoller stopped")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="wazuh-poller", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def status(self) -> Dict[str, Any]:
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "last_poll": self._last_poll.isoformat() if self._last_poll else None,
            "last_count": self._last_count,
            "interval_sec": self.config.poll_interval_sec,
            "base_url": self.config.base_url,
        }


# --------------------------------------------------------------------------- #
# Helpers for converting Wazuh alert JSON to SecurityOperationsAgent calls
# --------------------------------------------------------------------------- #

def _alert_id(alert: Dict[str, Any]) -> str:
    """Best-effort stable id for a Wazuh alert.

    Wazuh alerts don't ship a single canonical id; we composite
    timestamp+agent.id+rule.id so duplicates dedupe correctly.
    """
    ts = alert.get("timestamp", "")
    ag = (alert.get("agent") or {}).get("id", "")
    rl = (alert.get("rule") or {}).get("id", "")
    return f"{ts}|{ag}|{rl}"


def alert_to_soc_kwargs(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Wazuh alert dict into kwargs for SecurityOperationsAgent.create_alert()."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    level = int(rule.get("level", 0))
    return {
        "title": rule.get("description", "Wazuh alert"),
        "description": rule.get("description", ""),
        "severity": map_level_to_severity(level),
        "source": "wazuh",
        "rule_name": rule.get("id", "unknown"),
        "affected_asset": agent.get("name") or agent.get("id", "unknown"),
        "source_ip": (agent.get("ip") or None) if not str(agent.get("ip", "")).startswith("127.") else None,
        "timestamp": alert.get("timestamp", utcnow().isoformat()),
        "wazuh_raw": alert,
    }