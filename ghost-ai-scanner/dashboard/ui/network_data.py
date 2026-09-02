# =============================================================
# FILE: dashboard/ui/network_data.py
# VERSION: 1.0.0
# UPDATED: 2026-09-02
# OWNER: Giggso Inc
# PURPOSE: Read capture-companion findings and derive the five sections the
#          Network view renders: MCP, AI platforms, accounts, SaaS, timeline.
#          Pure data — no Streamlit, so it is testable on its own.
# DEPENDS: store.findings_store, normalizer.provider_names
# =============================================================
"""Network findings -> the five views the Network tab shows.

Reads what `jobs/tshark_ingest.py` wrote: one finding per
(device, domain, hour), already rolled up. This module classifies those
findings; it never talks to the capture prefix directly.

Self-test:  python network_data.py
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

# The AI catalogue is config, never inlined here — adding a platform means
# editing the JSON, not this file.
_CATALOG_PATHS = [
    Path(os.environ.get("AI_PLATFORMS_JSON", "")),
    Path(__file__).resolve().parents[2] / "config" / "ai_platforms.json",
    Path(__file__).resolve().parents[3] / "proxy" / "ai_platforms.json",
]

# An identity at the org's own email domain is an office account. Anything
# else is UNATTRIBUTED, deliberately - not "personal". The capture cannot
# prove ownership, only that an identity carries no office address.
OFFICE_DOMAIN = os.environ.get("OFFICE_DOMAIN", "") or os.environ.get("COMPANY_SLUG", "")

_catalog_cache: list | None = None


def _load_catalog() -> list:
    """[(domain_base, category, label, platform_key)], longest base first.

    Longest-base-first is required, not cosmetic: `anthropic.com`,
    `api.anthropic.com` and `mcp-proxy.anthropic.com` resolve to three
    DIFFERENT categories, and a plain suffix match would let the parent
    swallow both children.
    """
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache
    bases = []
    for p in _CATALOG_PATHS:
        if not p or not p.exists():
            continue
        try:
            cats = json.loads(p.read_text(encoding="utf-8")).get("categories", {})
        except (ValueError, OSError):
            continue
        for cname, c in cats.items():
            label = c.get("label", cname)
            for pkey, plat in (c.get("platforms") or {}).items():
                for dom in plat.get("domains", []):
                    bases.append((dom.lower(), cname, label, pkey))
        break
    bases.sort(key=lambda b: -len(b[0]))
    _catalog_cache = bases
    return bases


def classify(domain: str):
    """(category, label, platform) for an AI domain, or (None, None, None)."""
    d = (domain or "").lower().rstrip(".")
    for base, cat, label, plat in _load_catalog():
        if d == base or d.endswith("." + base):
            return cat, label, plat
    return None, None, None


def is_internal(domain: str) -> bool:
    """True for the org's own services — they are discovered, not catalogued."""
    if not OFFICE_DOMAIN:
        return False
    d = (domain or "").lower()
    return d == OFFICE_DOMAIN or d.endswith("." + OFFICE_DOMAIN)


def load_findings(store, days: int = 1, owner: str = "") -> list:
    """Capture-sourced findings for the last `days`, newest day first.

    Filtered to source == "tshark": the findings store holds every source,
    and the Network tab must never show endpoint-scan or VPC-flow rows.
    """
    rows: list = []
    # date.today() - LOCAL, deliberately - because findings_store.write()
    # files by date.today() too. Reading in UTC while the writer files in
    # local time silently returns nothing whenever the two differ, which is
    # most of the day in any non-UTC timezone. Match the writer, always.
    today = date.today()
    for n in range(max(1, days)):
        day = (today - timedelta(days=n)).isoformat()
        try:
            df = store.findings.read(target_date=day, limit=10_000)
        except Exception:
            continue
        if df is None or getattr(df, "is_empty", lambda: True)():
            continue
        for r in df.iter_rows(named=True):
            if r.get("source") != "tshark":
                continue
            if owner and (r.get("owner") or "") != owner:
                continue
            rows.append(r)
    return rows


def owners(rows: Iterable[dict]) -> list:
    """Distinct owners present, with unassigned devices last.

    A device whose catalog entry has no recipient_email shows as its token -
    an unassigned device is a real state, not an error to hide.
    """
    seen = {}
    for r in rows:
        key = r.get("owner") or ""
        label = key or f"{r.get('device_token', '?')} (unassigned)"
        seen.setdefault(key, label)
    return sorted(seen.items(), key=lambda kv: (kv[0] == "", kv[1]))


def summarise(rows: list) -> dict:
    """Everything the five sections need, in one pass over the findings."""
    ai: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    saas: dict = defaultdict(int)
    mcp: dict = defaultdict(int)
    timeline: dict = defaultdict(int)
    accounts: dict = defaultdict(int)
    flows = 0

    for r in rows:
        dom = (r.get("dst_domain") or "").lower()
        if not dom:
            continue
        n = int(r.get("occurrences") or 1)
        flows += n

        # The hour comes from the finding's own timestamp, never the S3 key -
        # the key's hour is when the batch was SEALED, not when traffic happened.
        ts = r.get("first_seen") or r.get("timestamp") or ""
        try:
            timeline[datetime.fromisoformat(ts).astimezone(timezone.utc).strftime("%H")] += n
        except (TypeError, ValueError):
            pass

        if "mcp" in dom:
            mcp[dom] += n

        cat, label, plat = classify(dom)
        if cat:
            ai[(cat, label)][plat][dom] += n
        else:
            saas[dom] += n

        acct, ident = r.get("aws_account_id"), r.get("aws_identity")
        if acct:
            accounts[(acct, ident or "")] += n

    return {
        "flows": flows,
        "findings": len(rows),
        "ai": [
            {"cat": cat, "label": label,
             "n": sum(sum(d.values()) for d in plats.values()),
             "platforms": [
                 {"p": p, "n": sum(doms.values()),
                  "domains": sorted(({"d": d, "n": c} for d, c in doms.items()),
                                    key=lambda x: -x["n"])}
                 for p, doms in sorted(plats.items(),
                                       key=lambda kv: -sum(kv[1].values()))]}
            for (cat, label), plats in sorted(
                ai.items(), key=lambda kv: -sum(sum(d.values()) for d in kv[1].values()))],
        "saas": sorted(({"d": d, "n": n, "internal": is_internal(d)}
                        for d, n in saas.items()), key=lambda x: -x["n"]),
        "mcp": sorted(({"d": d, "n": n,
                        "kind": "proxy" if "mcp-proxy" in d
                                else "internal" if is_internal(d) else "direct"}
                       for d, n in mcp.items()), key=lambda x: -x["n"]),
        "timeline": [{"t": f"{h:02d}", "n": timeline.get(f"{h:02d}", 0)} for h in range(24)],
        "accounts": sorted(({"account": a, "identity": i, "n": n,
                             "office": bool(OFFICE_DOMAIN and i.endswith("@" + OFFICE_DOMAIN))}
                            for (a, i), n in accounts.items()), key=lambda x: -x["n"]),
    }


def _selftest():
    def row(dom, n=1, hour="10", owner="a@x.com", **kw):
        r = {"source": "tshark", "dst_domain": dom, "occurrences": n,
             "first_seen": f"2026-09-01T{hour}:00:00+00:00", "owner": owner}
        r.update(kw)
        return r

    rows = [row("api.anthropic.com", 5), row("claude.ai", 3),
            row("mcp-proxy.anthropic.com", 2), row("mcp.deepwiki.com", 1),
            row("ssl.gstatic.com", 40, hour="14"),
            row("console.aws.amazon.com", 2, aws_account_id="123456789012",
                aws_identity="a@x.com")]
    s = summarise(rows)

    assert s["flows"] == 53, s["flows"]
    assert s["findings"] == 6

    # MCP is picked out by domain shape, and the proxy is distinguished from
    # a direct server - they mean different things (see the connector note).
    kinds = {m["d"]: m["kind"] for m in s["mcp"]}
    assert kinds["mcp-proxy.anthropic.com"] == "proxy", kinds
    assert kinds["mcp.deepwiki.com"] == "direct", kinds

    # A domain in no catalogue category falls through to SaaS, never silently
    # disappears.
    assert any(x["d"] == "ssl.gstatic.com" for x in s["saas"]), s["saas"]

    # Timeline always has 24 buckets, so a quiet hour reads as a real zero
    # rather than a missing bar.
    assert len(s["timeline"]) == 24
    assert dict((t["t"], t["n"]) for t in s["timeline"])["14"] == 40

    # Identity survives to the accounts section.
    assert s["accounts"] and s["accounts"][0]["account"] == "123456789012"

    # Owner list puts unassigned devices last.
    o = owners([row("x.com", owner=""), row("y.com", owner="b@x.com")])
    assert o[-1][0] == "", o

    # The reader must file by the same clock as findings_store.write(), which
    # uses date.today() (LOCAL). Reading in UTC returned zero rows for a whole
    # day whenever the two dates differed - the findings were there, invisible.
    import inspect
    src = inspect.getsource(load_findings)
    assert "date.today()" in src, "load_findings must use LOCAL date, matching the writer"
    assert "datetime.now(timezone.utc).date()" not in src,         "UTC read date silently mismatches findings_store's local write date"

    print("network_data self-test: PASS")


if __name__ == "__main__":
    _selftest()
