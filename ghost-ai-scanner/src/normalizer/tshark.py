# =============================================================
# FILE: src/normalizer/tshark.py
# VERSION: 1.0.0
# UPDATED: 2026-09-01
# PURPOSE: Parse capture-companion JSONL records into the flat universal
#          schema. One record = one observed network flow, captured by
#          agent/capture/pktmon_to_jsonl.py and uploaded to
#          ocsf/tshark/{token}/...
# OWNER: Giggso Inc
# DEPENDS: normalizer.schema
# =============================================================
"""Capture-companion records -> FLAT_SCHEMA.

The capture schema and FLAT_SCHEMA share ZERO field names - it is
`destination_domain` vs `dst_domain`, `bytes_transferred` vs `bytes_out`.
This module is the entire bridge between them.

Two properties of the source worth knowing:

* Records carry NO bodies and NO raw cookies. The companion strips them at
  capture time (parser_version >= 2026-09-01.1), so there is nothing
  sensitive to drop here - but also nothing to recover.
* Many records are `tls_only`: a TLS handshake was seen but never decrypted,
  so only the SNI hostname is known. Those are still valuable - the AI
  platform baseline is built on cleartext SNI precisely so it works without
  key logging - so they are normalised, not discarded.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from .schema import empty_event, infer_asset_type

log = logging.getLogger("marauder-scan.normalizer.tshark")

# Records written before this parser version may contain bodies and raw
# cookies, and predate the HTTP/3 stream-pairing fix. Refuse them: the whole
# point of the version stamp is to keep those populations separable.
MIN_PARSER_VERSION = "2026-09-01.1"


def _timestamp(raw) -> Optional[str]:
    """ISO-8601 UTC from either capture backend's timestamp format.

    pktmon writes Unix epoch seconds as a STRING with nanosecond precision
    ("1787921153.562033000"); the mitmproxy addon writes ISO-8601 directly.
    Both appear in real capture files, so both are handled.
    """
    if raw in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(raw)).isoformat()
    except (TypeError, ValueError):
        return None


def parse(raw: dict, company: str = "") -> Optional[dict]:
    """One capture record -> one flat event. None if it should be skipped.

    Skipped: records with no destination at all (nothing to match on), and
    records from a parser version that predates the no-bodies policy.
    """
    if not isinstance(raw, dict):
        return None

    # Version gate. A record with no stamp is pre-2026-08-30 output and is
    # not trustworthy - see PARSER_VERSION's own note in pktmon_to_jsonl.py.
    version = raw.get("parser_version") or ""
    if version < MIN_PARSER_VERSION:
        log.debug("Skipping record from parser_version %r (< %s)",
                  version, MIN_PARSER_VERSION)
        return None

    # SNI is the fallback, not an afterthought: on a tls_only record it is the
    # ONLY thing identifying the destination, and those are the majority on a
    # machine whose browsers predate the keylog.
    domain = (raw.get("destination_domain") or raw.get("sni") or "").strip().lower()
    port = int(raw.get("destination_port") or 0)
    if not domain and not port:
        return None

    event = empty_event("tshark", company)
    event["dst_domain"] = domain.rstrip(".")
    event["dst_ip"] = raw.get("destination_ip") or ""
    event["dst_port"] = port
    event["src_ip"] = raw.get("client_ip") or ""

    # HTTP/3 rides on QUIC, which is UDP. Everything else here is TCP.
    http_version = (raw.get("http_version") or "").upper()
    event["protocol"] = "UDP" if "3" in http_version.replace("HTTP/", "") else "TCP"

    # bytes_out is defined as "bytes sent TO destination" - request_bytes,
    # not bytes_transferred (which includes the response).
    event["bytes_out"] = int(raw.get("request_bytes") or 0)

    ts = _timestamp(raw.get("timestamp"))
    if ts:
        event["timestamp"] = ts

    event["asset_type"] = infer_asset_type(event["src_ip"])
    # Deliberately blank: this is endpoint capture, not cloud telemetry.
    # infer_asset_type's "not RFC1918 therefore EC2" guess does not apply.
    event["cloud_provider"] = ""

    # No process attribution is possible from a packet capture. Packetbeat's
    # one real advantage over this source; leaving it empty rather than
    # guessing keeps that honest.
    event["process_name"] = ""

    # Platform account identity, extracted AT CAPTURE TIME and carried through
    # as extra keys (not FLAT_SCHEMA fields, matching how agent_explode.py and
    # findings_compact.py attach their own).
    #
    # These are the ONLY identity that survives a no-body capture: the AWS
    # console puts the IAM ARN in a cookie, so the companion parses it before
    # redacting that cookie. Dropping them here would silently discard the
    # dual-account signal the whole capture exists to find - which is exactly
    # what happened until this was added.
    if raw.get("aws_account_id"):
        event["aws_account_id"] = raw["aws_account_id"]
        event["aws_identity"] = raw.get("aws_identity") or ""

    return event
