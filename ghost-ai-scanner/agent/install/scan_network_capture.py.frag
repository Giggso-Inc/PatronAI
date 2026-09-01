# =============================================================
# FRAGMENT: scan_network_capture.py.frag
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: observed_network_target (D2a2) - reads Packetbeat's real NDJSON
#          capture (written by the optional install step in
#          setup_agent.ps1/sh.template, PATRONAI_ENABLE_PACKETBEAT=1) and
#          turns real TLS SNI records into findings. Confirmed this
#          session against a real Packetbeat 9.5.2 capture: TLS events
#          carry a real resolved destination.domain (e.g.
#          api.anthropic.com), not a guess.
#          No-op (returns []) when Packetbeat isn't installed/enabled -
#          this is an optional module, most machines won't have the
#          capture file at all.
#          NOT attempted: attributing a domain to a specific local
#          process/extension. The real capture doesn't carry a local PID
#          for the connection (confirmed this session - the specific
#          ephemeral ports had already closed by the time a follow-up
#          process snapshot could catch them), so this emits the
#          domain-level signal only, honestly, not a fabricated link.
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial.
#   v1.1.0  2026-08-31  Add calls_per_10_min + high_frequency_flag - real
#                       connection-frequency data for a domain, using the
#                       team's own threshold rule ("flag if 50+ connections
#                       in 10 minutes", confirmed working against a real
#                       threshold test earlier this session). Deliberately
#                       NOT named api_call_frequency and NOT attached to
#                       the "process" finding type - this is domain-level
#                       frequency (how often THIS DOMAIN was contacted),
#                       not per-process frequency. Packetbeat's capture
#                       carries no local PID for the connection (confirmed
#                       this session), so a genuine per-process
#                       api_call_frequency still isn't attemptable; naming
#                       these fields distinctly avoids conflating the two.
# =============================================================

_NETCAP_MAX_FINDINGS = 200
_NETCAP_WINDOW_SECONDS = 1800  # one scan cycle (30 min) - avoids re-reporting old events forever
_TLS_RECORD_TYPE = "tls"  # Packetbeat's own record type for a TLS handshake
_HIGH_FREQUENCY_THRESHOLD_PER_10MIN = 50  # team's own rule, confirmed via a real threshold test


def _capture_files() -> list:
    """Packetbeat's rotated NDJSON files under AGENT_DIR, newest content
    first isn't required - we window by event timestamp, not file order."""
    try:
        return sorted(AGENT_DIR.glob("packetbeat_capture*.ndjson"))
    except Exception:
        return []


def _recent_tls_domains() -> dict:
    """domain -> {count, first_seen, last_seen} for real TLS events inside
    the recent window. Encoding may be UTF-16 (PowerShell `*>` redirect on
    Windows) - trying utf-8 first, falling back, matches what was actually
    observed this session."""
    now = datetime.now(timezone.utc)
    domains: dict = {}
    for path in _capture_files():
        for encoding in ("utf-8", "utf-16"):
            try:
                text_ = path.read_text(encoding=encoding)
                break
            except Exception:
                text_ = ""
        for line in text_.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("type") != _TLS_RECORD_TYPE:
                continue
            dest = rec.get("destination") or {}
            domain = dest.get("domain")
            ts = rec.get("@timestamp")
            if not domain or not ts:
                continue
            try:
                seen_at = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if (now - seen_at).total_seconds() > _NETCAP_WINDOW_SECONDS:
                continue
            d = domains.setdefault(domain, {"count": 0, "first_seen": ts, "last_seen": ts})
            d["count"] += 1
            d["last_seen"] = max(d["last_seen"], ts)
            d["first_seen"] = min(d["first_seen"], ts)
    return domains


def _calls_per_10_min(info: dict) -> float:
    """Real connections-per-10-minutes for one domain, from its actual
    first/last-seen span in this window - not the fixed 30-min window
    itself, since most domains won't span the whole thing. A single
    observation has no span to compute a rate from; reporting its raw
    count is the honest, conservative choice (never a fabricated rate)."""
    try:
        first = datetime.fromisoformat(info["first_seen"].replace("Z", "+00:00"))
        last  = datetime.fromisoformat(info["last_seen"].replace("Z", "+00:00"))
        span  = (last - first).total_seconds()
    except Exception:
        span = 0
    if span <= 0:
        return float(info["count"])
    return round(info["count"] * 600.0 / span, 1)


def scan_network_capture() -> list:
    """One finding per real domain observed via TLS SNI in the last scan
    window. Returns [] cleanly when Packetbeat isn't installed/enabled -
    this is an optional, additive signal, not a required one."""
    if not AGENT_DIR.exists():
        return []
    findings: list = []
    for domain, info in _recent_tls_domains().items():
        rate = _calls_per_10_min(info)
        findings.append({
            "type":                "observed_network_target",
            "domain":              domain[:200],
            "observation_count":   info["count"],
            "first_seen":          info["first_seen"],
            "last_seen":           info["last_seen"],
            "calls_per_10_min":    rate,
            "high_frequency_flag": rate >= _HIGH_FREQUENCY_THRESHOLD_PER_10MIN,
        })
        if len(findings) >= _NETCAP_MAX_FINDINGS:
            break
    return findings
