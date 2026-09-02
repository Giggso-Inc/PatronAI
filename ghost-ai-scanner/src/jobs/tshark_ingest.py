# =============================================================
# FILE: src/jobs/tshark_ingest.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# OWNER: Giggso Inc
# PURPOSE: Ingest capture-companion objects from ocsf/tshark/{token}/...,
#          roll them up to one finding per (device, domain, hour), match
#          against the provider lists, and write to the findings store.
# DEPENDS: store.agent_store, normalizer.tshark, matcher
# =============================================================
"""Capture ingest: raw flows in, aggregated findings out.

TWO deliberate departures from the existing ingest path, both load-bearing.

1. IT DOES NOT USE S3Walker.
   S3Walker.list_new_files() pages EVERY object under `ocsf/` on every cycle
   and filters client-side. That is fine at today's volumes and untenable
   here: ~24 objects/device/day means 100 devices produce ~875k objects a
   year, paged through every five minutes forever. This job instead
   enumerates device tokens from the agent catalog and lists only
   today's and yesterday's partitions per token - bounded work per cycle
   regardless of how much history the bucket holds.

2. IT ROLLS UP BEFORE WRITING.
   findings_store.write() is a full read-modify-write of the day's object per
   finding. A capture segment can hold thousands of flows; writing them
   per-flow would mean thousands of full-object rewrites, each larger than
   the last. Flows are aggregated to one finding per (device, domain, hour)
   first - which is also the only granularity anyone actually queries.

The rollup event carries `occurrences`, `first_seen`, `last_seen` and
`finding_signature` alongside the flat schema. Those are not in FLAT_SCHEMA,
matching existing practice: agent_explode.py attaches finding_signature and
findings_compact.py attaches the other three. Setting finding_signature also
makes these findings visible to findings_compact, which network-sourced
events currently are not.

Self-test:  python -m jobs.tshark_ingest --selftest
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import sys
import time
import threading
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Iterable, Optional

log = logging.getLogger("marauder-scan.jobs.tshark_ingest")

CAPTURE_PREFIX = "ocsf/tshark"
INGEST_INTERVAL_S = int(os.environ.get("TSHARK_INGEST_INTERVAL_S", "900"))
# Cap on objects pulled per token per cycle, so one very busy device cannot
# starve the rest of the fleet.
MAX_OBJECTS_PER_TOKEN = int(os.environ.get("TSHARK_MAX_OBJECTS", "200"))


def _cursor_key(token: str) -> str:
    return f"config/HOOK_AGENTS/{token}/tshark_cursor.json"


def catalog_identity(entry: dict) -> dict:
    """Map one agent-catalog entry to the identity fields of the flat schema.

    The capture companion ships a device TOKEN, never a username - it has no
    idea who is using the machine. The agent catalog is the only place that
    binds the two, because `create_package` records `recipient_email` at
    invite time (agent_store.py:132).

    Without this, every finding reads as an opaque token in the UI and cannot
    be filtered by person, which is the first thing anyone asks of it.

    `owner` is deliberately the EMAIL, not the display name: it is the stable
    key the rest of the pipeline already joins on (identity_resolver, and
    `dashboard/ui/policy_context_loader.sync_scanned_users_from_events`).
    """
    email = (entry.get("recipient_email") or "").strip()
    return {
        "owner": email,
        "src_hostname": entry.get("recipient_name") or "",
        "device_token": entry.get("token") or "",
    }


def _partitions(days: int = 2) -> list:
    """Date partitions to scan, newest first: today, yesterday, ...

    Two days rather than one because a device that was offline, or whose
    spool backed up, uploads late - and because an object sealed at 23:59
    lands in yesterday's partition while the ingest runs today.
    """
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=n)).strftime("%Y/%m/%d") for n in range(days)]


def list_new_objects(store, token: str, processed: set, days: int = 2) -> list:
    """Keys under this token's recent partitions that we have not ingested.

    Scoped per token per day on purpose - see the module docstring.
    """
    found = []
    for part in _partitions(days):
        prefix = f"{CAPTURE_PREFIX}/{token}/{part}/"
        try:
            paginator = store.agent.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=store.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".jsonl.gz") and key not in processed:
                        found.append(key)
        except Exception as exc:
            log.error("listing %s failed: %s", prefix, exc)
    found.sort()
    if len(found) > MAX_OBJECTS_PER_TOKEN:
        log.info("token %s: capping at %d of %d new objects",
                 token, MAX_OBJECTS_PER_TOKEN, len(found))
        found = found[:MAX_OBJECTS_PER_TOKEN]
    return found


def read_records(store, key: str) -> list:
    """Download one gzipped JSONL object and return its records.

    A single unparseable line is skipped, not fatal: one corrupt record must
    not cost the whole segment.
    """
    try:
        body = store.agent.s3.get_object(Bucket=store.bucket, Key=key)["Body"].read()
        text = gzip.decompress(body).decode("utf-8", errors="replace")
    except Exception as exc:
        log.error("read %s failed: %s", key, exc)
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            log.debug("bad JSON line in %s", key)
    return out


def _hour_bucket(iso_ts: str) -> str:
    """YYYY-MM-DDTHH from an ISO timestamp; '' when unparseable.

    Derived from the RECORD's own timestamp, never from the S3 key path. The
    key's {HH} is the hour the batch was SEALED - a segment straddling an hour
    boundary files earlier records under a later partition, so grouping on the
    key would silently skew every hourly figure.
    """
    try:
        return datetime.fromisoformat(iso_ts).astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
    except (TypeError, ValueError):
        return ""


def rollup(events: Iterable[dict], token: str) -> list:
    """Flat events -> one aggregated event per (device, domain, hour)."""
    groups: dict = {}
    for ev in events:
        domain = ev.get("dst_domain") or ""
        hour = _hour_bucket(ev.get("timestamp") or "")
        if not domain or not hour:
            continue
        key = (token, domain, hour)
        slot = groups.get(key)
        if slot is None:
            # Keep the first event as the representative row so every flat
            # field (src_ip, protocol, asset_type, company...) stays populated.
            slot = dict(ev)
            slot["occurrences"] = 0
            slot["bytes_out"] = 0
            slot["first_seen"] = ev.get("timestamp")
            slot["last_seen"] = ev.get("timestamp")
            slot["device_token"] = token
            groups[key] = slot
        slot["occurrences"] += 1
        slot["bytes_out"] += int(ev.get("bytes_out") or 0)
        # Identity can appear on ANY flow in the hour, not just the first one
        # kept as the representative row. Without this, an account seen on the
        # second call of an hour is silently dropped - and the dual-account
        # finding is exactly the thing that must not go missing.
        if ev.get("aws_account_id") and not slot.get("aws_account_id"):
            slot["aws_account_id"] = ev["aws_account_id"]
            slot["aws_identity"] = ev.get("aws_identity") or ""
        ts = ev.get("timestamp")
        if ts:
            if not slot["first_seen"] or ts < slot["first_seen"]:
                slot["first_seen"] = ts
            if not slot["last_seen"] or ts > slot["last_seen"]:
                slot["last_seen"] = ts

    for (tok, domain, hour), slot in groups.items():
        # Stable across cycles: re-ingesting the same hour produces the same
        # signature, so findings_compact collapses rather than duplicating.
        slot["finding_signature"] = hashlib.sha256(
            f"tshark|{tok}|{domain}|{hour}".encode()).hexdigest()[:16]
        # The hour bucket IS the finding's time - not the moment we ingested.
        slot["timestamp"] = slot["first_seen"] or slot["timestamp"]
    return list(groups.values())


def process_token(store, token: str, authorized: list, unauthorized: list,
                  company: str = "", identity: dict = None) -> dict:
    """Ingest one device's new objects. Returns per-token stats.

    `identity` comes from catalog_identity() and is stamped onto every
    finding, so the UI can filter by person rather than by opaque token.
    """
    from normalizer import normalize
    from matcher import match

    raw_cursor = store.agent._get(_cursor_key(token))
    try:
        processed = set(json.loads(raw_cursor).get("processed", [])) if raw_cursor else set()
    except ValueError:
        processed = set()

    keys = list_new_objects(store, token, processed)
    if not keys:
        return {"objects": 0, "flows": 0, "findings": 0, "outcomes": {}}

    events = []
    flows = 0
    for key in keys:
        for rec in read_records(store, key):
            flows += 1
            ev = normalize(rec, source_hint="tshark", company=company)
            if ev:
                events.append(ev)

    outcomes: dict = defaultdict(int)
    written = 0
    for finding in rollup(events, token):
        # Stamp who this device belongs to BEFORE matching, so the verdict
        # and the identity land on the same row.
        if identity:
            finding.update(identity)
        verdict = match(finding, authorized, unauthorized)
        finding.update(verdict)
        outcomes[finding["outcome"]] += 1
        if finding["outcome"] != "SUPPRESS":
            store.findings.write(finding)
            written += 1

    # Advance the cursor ONLY after the findings are written. A crash between
    # the two re-ingests the objects, which is harmless: the rollup signature
    # is deterministic, so the same hour produces the same finding.
    processed.update(keys)
    keep = tuple(f"{CAPTURE_PREFIX}/{token}/{p}/" for p in _partitions(3))
    pruned = sorted(k for k in processed if k.startswith(keep))
    store.agent._put(_cursor_key(token),
                     json.dumps({"processed": pruned,
                                 "updated": datetime.now(timezone.utc).isoformat()}).encode(),
                     "application/json")

    return {"objects": len(keys), "flows": flows,
            "findings": written, "outcomes": dict(outcomes)}


def run_once(store, settings: dict = None) -> dict:
    """One ingest cycle across every enrolled device."""
    settings = settings or {}
    company = settings.get("company", {}).get("slug", "")

    from matcher.loader import load_authorized, load_unauthorized
    authorized = load_authorized(store.bucket)
    unauthorized = load_unauthorized(store.bucket)
    if not unauthorized:
        log.error("Unauthorized list empty - tshark ingest aborted")
        return {"outcome": "aborted", "reason": "empty unauthorized list"}

    catalog = store.agent.list_catalog() if hasattr(store, "agent") else []
    totals = {"devices": 0, "objects": 0, "flows": 0, "findings": 0}
    for entry in catalog:
        token = entry.get("token", "")
        if not token:
            continue
        try:
            stats = process_token(store, token, authorized, unauthorized, company,
                                  identity=catalog_identity(entry))
        except Exception as exc:
            log.error("tshark ingest failed for %s: %s", token, exc, exc_info=True)
            continue
        if stats["objects"]:
            totals["devices"] += 1
            for k in ("objects", "flows", "findings"):
                totals[k] += stats[k]
            log.info("token %s: %s objects, %s flows -> %s findings",
                     token, stats["objects"], stats["flows"], stats["findings"])

    log.info("tshark ingest: %s devices, %s objects, %s flows -> %s findings",
             totals["devices"], totals["objects"], totals["flows"], totals["findings"])
    return totals


def scheduler_loop(store, stop: threading.Event, settings: dict = None) -> None:
    """Daemon thread target. Runs run_once() every INGEST_INTERVAL_S."""
    log.info("tshark_ingest scheduler started - interval=%ss", INGEST_INTERVAL_S)
    while not stop.is_set():
        t0 = time.time()
        try:
            run_once(store, settings)
        except Exception as exc:
            log.error("tshark ingest cycle error: %s", exc, exc_info=True)
        stop.wait(timeout=max(0, INGEST_INTERVAL_S - (time.time() - t0)))
    log.info("tshark_ingest scheduler stopped")


def _selftest():
    """Pure-logic checks - no S3, no network."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from normalizer import normalize

    def rec(domain, ts, **kw):
        base = {"destination_domain": domain, "destination_port": 443,
                "destination_ip": "1.2.3.4", "client_ip": "10.0.0.5",
                "http_version": "HTTP/2", "request_bytes": 100,
                "timestamp": ts, "parser_version": "2026-09-01.1"}
        base.update(kw)
        return base

    # Normalizer: capture schema -> flat schema.
    ev = normalize(rec("chatgpt.com", "1788000000.0"), source_hint="tshark", company="giggso")
    assert ev["dst_domain"] == "chatgpt.com", ev
    assert ev["dst_port"] == 443 and ev["src_ip"] == "10.0.0.5", ev
    assert ev["protocol"] == "TCP" and ev["bytes_out"] == 100, ev
    assert ev["source"] == "tshark" and ev["company"] == "giggso", ev

    # HTTP/3 is QUIC, therefore UDP.
    ev3 = normalize(rec("gemini.google.com", "1788000000.0", http_version="HTTP/3"),
                    source_hint="tshark")
    assert ev3["protocol"] == "UDP", ev3

    # tls_only: SNI is the only destination available, and must be used.
    tls = normalize({"destination_domain": None, "sni": "api.anthropic.com",
                     "destination_port": 443, "tls_only": True,
                     "timestamp": "1788000000.0", "parser_version": "2026-09-01.1"},
                    source_hint="tshark")
    assert tls and tls["dst_domain"] == "api.anthropic.com", tls

    # Records predating the no-bodies policy are refused outright.
    assert normalize(rec("x.com", "1788000000.0", parser_version="2026-08-30.3"),
                     source_hint="tshark") is None
    assert normalize(rec("x.com", "1788000000.0", parser_version=None),
                     source_hint="tshark") is None

    # Auto-detection without a hint must pick tshark, not packetbeat.
    assert normalize(rec("chatgpt.com", "1788000000.0"))["source"] == "tshark"

    # Rollup: 3 flows to one domain in one hour -> ONE finding.
    same_hour = [normalize(rec("chatgpt.com", t), source_hint="tshark")
                 for t in ("1788000000.0", "1788000060.0", "1788000120.0")]
    other_hour = [normalize(rec("chatgpt.com", "1788003700.0"), source_hint="tshark")]
    other_dom = [normalize(rec("claude.ai", "1788000000.0"), source_hint="tshark")]
    rolled = rollup(same_hour + other_hour + other_dom, "devlaptop01")
    assert len(rolled) == 3, [(r["dst_domain"], r["occurrences"]) for r in rolled]
    hot = [r for r in rolled if r["dst_domain"] == "chatgpt.com"
           and r["occurrences"] == 3]
    assert len(hot) == 1, rolled
    assert hot[0]["bytes_out"] == 300, hot[0]
    assert hot[0]["first_seen"] < hot[0]["last_seen"], hot[0]
    assert hot[0]["timestamp"] == hot[0]["first_seen"], "finding time is the hour, not ingest time"

    # Signature is stable across runs - re-ingest must not duplicate.
    again = rollup(same_hour, "devlaptop01")
    assert again[0]["finding_signature"] == hot[0]["finding_signature"], "signature must be stable"
    # ...and distinct per device, per domain, per hour.
    other_device = rollup(same_hour, "otherlaptop")
    assert other_device[0]["finding_signature"] != hot[0]["finding_signature"]

    # A record with no usable timestamp cannot be bucketed, so it is dropped
    # rather than landing in an arbitrary hour.
    assert rollup([dict(hot[0], timestamp="not-a-time")], "d") == []

    # Account identity must survive the rollup even when it appears on a LATER
    # flow than the one kept as representative.
    plain = normalize(rec("console.aws.amazon.com", "1788000000.0"), source_hint="tshark")
    withid = normalize(rec("console.aws.amazon.com", "1788000060.0"), source_hint="tshark")
    withid["aws_account_id"], withid["aws_identity"] = "966293878453", "sanjay-cli"
    merged = rollup([plain, withid], "dev")
    assert len(merged) == 1, merged
    assert merged[0]["aws_account_id"] == "966293878453",         "identity on a non-first flow must still reach the finding"
    assert merged[0]["aws_identity"] == "sanjay-cli"

    # Token -> user mapping. The companion only ever knows a device token;
    # the catalog is what binds it to a person.
    ident = catalog_identity({"token": "abc123", "recipient_name": "Sanjay K",
                              "recipient_email": "k.sanjaykumar@giggso.com"})
    assert ident["owner"] == "k.sanjaykumar@giggso.com", ident
    assert ident["src_hostname"] == "Sanjay K", ident
    assert ident["device_token"] == "abc123", ident
    # A catalog entry with no email must not invent one - an unassigned
    # device is a real state, and a blank owner is how the UI shows it.
    assert catalog_identity({"token": "t"})["owner"] == ""

    # The identity must survive onto the rolled-up finding.
    stamped = rollup(same_hour, "devlaptop01")[0]
    stamped.update(ident)
    assert stamped["owner"] == "k.sanjaykumar@giggso.com"
    assert stamped["occurrences"] == 3, "stamping identity must not disturb the rollup"

    print("tshark_ingest self-test: PASS")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    if ap.parse_args().selftest:
        _selftest()
