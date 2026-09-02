"""Converts a pktmon-captured .pcapng (decrypted via SSLKEYLOGFILE) into the
same flat JSONL record shape poc_capture_addon.py writes, so
check_mcp_servers.py / check_dual_use_accounts.py can read a pktmon capture
exactly like a mitmproxy one, for direct comparison.

Shells out to tshark (not bundled - see run_pktmon_capture.ps1's own check)
to do the actual TLS decryption and HTTP dissection - reusing tshark's own
mature dissectors rather than reimplementing TLS/HTTP parsing, same
"call a purpose-built tool" reasoning discussed throughout mitmalternate.md.

Handles BOTH classic HTTP/1.1-2 over TCP+TLS and HTTP/3 over QUIC+UDP - the
latter added 2026-08-28 after confirming live that Google properties (e.g.
gemini.google.com) predominantly use QUIC, which an HTTP-only version
silently missed entirely. These are two separate tshark invocations, not one
combined query - the display filter differs (HTTP vs HTTP/3 traffic) and the
field lists are entirely different dissectors' fields, so there's no benefit
to combining them. Both invocations use the SAME -E settings uniformly
(occurrence=a, aggregator=|, quote=d - see _run_tshark) - every field is
treated as potentially multi-valued (see _first()), since a field this
script expects to be single-valued has still turned out not to be at least
once already (quic.stream.stream_id, confirmed live).

Header capture added 2026-08-28 (second pass) so this matches
poc_capture_addon.py's schema instead of always writing {} - the SAME
redaction policy is applied here (SECRET_HEADERS below, copied verbatim from
that file): Authorization/Set-Cookie/Proxy-Authorization are redacted,
Cookie is deliberately left raw (see poc_condition.md for why). Extending
capture to "everything possible" does not mean loosening that policy - it
stays exactly as strict as the mitmproxy path. This same pass switched
row-parsing from naive line.split("\n")/"\t" to tshark's -E quote=d output
parsed with Python's csv module - REQUIRED, not a style choice: a
self-test run (2026-08-28) proved that http.request.line/response.line
values contain a literal \r\n (the real captured header-line bytes), which
silently corrupted row boundaries under naive newline-splitting.

Field-name honesty: HTTP/3 field names (http3.header.header.name,
http3.headers.header.value, http3.data, quic.connection.number) were
confirmed live against this machine's real tshark and a real decrypted
Gemini capture in an earlier pass - notably the singular/plural
inconsistency in Wireshark's own naming. The classic HTTP/1-2 header/version
fields added in THIS pass (http.request.line, http.response.line,
http.request.version, http.response.version, tls.handshake.version) are
long-established, well-documented tshark fields, but were NOT re-verified
live in this session (tool access to run tshark was blocked mid-session by
an unrelated safety classifier - see the conversation this was built in).
Confirm against a real capture before trusting these specific fields.

ponytail / known limitations, stated honestly - this is a comparison spike,
not a full mitmproxy-grade flow reassembly:
- Classic HTTP/1-2 pairing is still a naive per-tcp.stream FIFO queue -
  correct for simple sequential exchanges, wrong for pipelined/out-of-order
  responses on the same connection. HTTP/3 pairing (2026-08-28, third pass)
  is no longer this naive - it now keys on the EXACT
  (quic.connection.number, quic.stream.stream_id) pair rather than FIFO
  over the whole connection, which was the direct cause of an
  already-observed ~48% empty-domain-field rate on one real capture (a
  connection with multiple concurrent streams was mismatching responses to
  the wrong request). Caveat: this depends on quic.stream.stream_id (via
  _first()) reliably naming the right stream per row - confirmed live only
  that the field CAN return multiple aggregated values per packet, not that
  the first one is always correct. Re-check this specific assumption if
  pairing still looks wrong after this change on a real capture.
- Multi-packet response bodies ARE now reassembled for HTTP/3 (2026-08-28,
  third pass) - every http3.data fragment on a stream, from its :status
  packet through quic.stream.fin, is concatenated before decoding. Found
  and fixed after a real capture showed Gemini's L5adhe call ("[gzip-
  compressed, failed to decompress - likely truncated across multiple
  packets]") - a response big enough to need more than one packet was
  silently truncated before this fix. Classic HTTP/1-2 does NOT get the
  same treatment yet - only a single packet's http.file_data is used there,
  and request bodies (either protocol) are also still single-packet only,
  on the assumption that request bodies are usually small enough to fit in
  one packet, unlike large tool-call/account-listing results.
- Gzip-compressed bodies are auto-decompressed (detected via the 1f 8b magic
  bytes). Brotli ("br", confirmed live as Chrome's preferred encoding) is
  NOT handled - decodes as garbage rather than failing loudly.
- request_bytes/response_bytes measure the (pre-decompression) body length
  only, matching poc_capture_addon.py's len(raw_content) semantic - not the
  full wire frame size.
- tls_version reads tls.handshake.version, which TLS 1.3 connections often
  still report as "TLS 1.2" for middlebox-compatibility reasons (the real
  negotiated version lives in a supported_versions extension this script
  does not separately parse) - treat it as approximate, not authoritative.
  HTTP/3 records report "TLS 1.3" unconditionally instead, since QUIC always
  uses it - no separate field needed there.
- The tab-parsing + pairing + header-redaction logic for both paths has a
  canned-fixture self-test that does not need tshark - run
  `python pktmon_to_jsonl.py` with no arguments.
"""
import argparse
import csv
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from collections import defaultdict, deque
from pathlib import Path

# ── tshark location ──────────────────────────────────────────────────────
# Resolved to an ABSOLUTE path, never invoked as a bare name.
#
# Wireshark's silent installer (/S) does NOT add itself to the machine PATH,
# and the capture companion runs as SYSTEM - so a bare "tshark" is
# unresolvable there and every extraction fails. It looks fine interactively
# because a developer's shell usually has it, which is exactly how this hid.
_TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
]


def resolve_tshark() -> str:
    """Absolute path to tshark, or the bare name if nothing else is found.

    Order: explicit override, then PATH, then the standard install locations.
    Returning the bare name as a last resort keeps the failure message in one
    place (the callers raise a clear "tshark not found" SystemExit).
    """
    override = os.environ.get("PATRONAI_TSHARK", "").strip()
    if override:
        return override
    found = shutil.which("tshark")
    if found:
        return found
    for candidate in _TSHARK_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return "tshark"


TSHARK = resolve_tshark()

# Python's csv module caps a single field at 131072 bytes by default and
# raises _csv.Error ("field larger than field limit") past that - which
# aborts the ENTIRE conversion, not just the offending row. Confirmed live
# 2026-08-29: 4 of 48 capture segments failed outright this way during a
# bulk re-processing run. Bodies here are hex-encoded, so a field is ~2x the
# real byte size, and any response over ~64 KB trips it - routine for a JS
# bundle or a large JSON payload.
#
# sys.maxsize overflows the C long this setting maps to on some platforms
# (Windows in particular), so step down until one is accepted rather than
# assuming a single value works everywhere.
_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_limit)
        break
    except OverflowError:
        _limit = int(_limit // 10)

# Copied verbatim from poc_capture_addon.py - same policy, same reasoning.
# Cookie is deliberately NOT in this set: it is handled by sanitize() below
# instead, because the AWS identity has to be read out of it BEFORE it is
# redacted. Adding "cookie" here would destroy that value at build time.
SECRET_HEADERS = {"authorization", "set-cookie", "proxy-authorization"}

REDACTED = "[REDACTED]"

# ── Phase 0 data policy ───────────────────────────────────────────────────
# Applied by sanitize() at the SINGLE point where records are written, so a
# new builder cannot bypass the policy by forgetting to call it. There are
# four record builders (HTTP/1.x, HTTP/2, HTTP/3, TLS-handshake-only) and
# adding the policy to each would mean four places to forget.
#
# Only the account id and the user/role NAME are ever extracted from the
# cookie. `keybase` and `aws-userInfo-signed` are signature material and are
# read into memory only long enough to be discarded - never stored.
AWS_USERINFO_COOKIE_RE = re.compile(r"aws-userInfo=([^;]+)")
AWS_ARN_IN_COOKIE_RE = re.compile(
    r"arn:aws:iam::(\d{12}):(?:user|role|assumed-role)/([^\"/]+)")


def _aws_identity_from_cookie(cookie_value: str):
    """(account_id, identity) from an aws-userInfo cookie crumb, or (None, None).

    The crumb is URL-encoded on the wire, so it must be unquoted before the
    ARN regex will match anything.
    """
    if not cookie_value:
        return None, None
    crumb = AWS_USERINFO_COOKIE_RE.search(cookie_value)
    if not crumb:
        return None, None
    try:
        decoded = urllib.parse.unquote(crumb.group(1))
    except Exception:
        return None, None
    arn = AWS_ARN_IN_COOKIE_RE.search(decoded)
    if not arn:
        return None, None
    return arn.group(1), arn.group(2)


def _redact_query(path: str) -> str:
    """Redact query-string VALUES, keep parameter NAMES.

    Some sites put session tokens in the URL (?SID=...), which lands in `path`
    and is not covered by header redaction. Names are kept because they are
    derivable signal with no secret in them; values are where the credential
    lives. Same principle as the Cookie handling: redact the value, keep the
    key.

    Deliberately hand-rolled rather than urllib.parse.parse_qs + urlencode -
    that round-trip re-encodes and reorders, which would silently rewrite the
    path even when there is nothing to redact.
    """
    if not path:
        return path
    head, sep, query = path.partition("?")
    if not sep:
        return path
    out = []
    for pair in query.split("&"):
        name, eq, _value = pair.partition("=")
        if eq:
            out.append(f"{name}={REDACTED}")
        else:
            # A VALUELESS token - "?a1b2c3d4" with no '=' at all. Earlier this
            # was emitted verbatim on the reasoning that a bare name carries no
            # secret. That is wrong: with no '=', the token IS the value. Found
            # in the lake as Windows Update cache-busters (harmless), but the
            # same shape is exactly how a bare session id or nonce would look.
            # Redact it, and keep the marker so "there was a query" survives.
            out.append(REDACTED if name else "")
    return f"{head}?{'&'.join(out)}"


def sanitize(record: dict, save_bodies: bool = False,
             redact_params: bool = True) -> dict:
    """Apply the Phase 0 data policy to one record, in place.

    ORDER MATTERS: the AWS identity is read out of the Cookie before the
    cookie is redacted. Redaction destroys the only source of AWS account
    identity that survives a no-body policy, so capture time is the only
    moment it can be read at all.

    aws_account_id / aws_identity are always present (None when absent) so
    every record written by this parser version has an identical key set.
    """
    record.setdefault("aws_account_id", None)
    record.setdefault("aws_identity", None)

    headers = record.get("request_headers") or {}
    for name in [k for k in headers if k.lower() == "cookie"]:
        account_id, identity = _aws_identity_from_cookie(headers[name] or "")
        if account_id:
            record["aws_account_id"] = account_id
            record["aws_identity"] = identity
        headers[name] = REDACTED

    if not save_bodies:
        # Keys are KEPT and nulled rather than deleted, so the record shape is
        # identical whether or not bodies were collected. parser_version is
        # what tells a consumer which policy produced the record.
        record["request_body"] = None
        record["response_body"] = None

    if redact_params:
        record["path"] = _redact_query(record.get("path"))

    record["parser_version"] = PARSER_VERSION
    return record

# Stamped onto every record. The capture JSONL is APPEND-ONLY and long-lived,
# so it accumulates records written by every parser version that ever ran -
# including buggy ones. Measured on the reference capture: 6,662 HTTP/3
# records written before the 2026-08-30 stream-pairing fix carry NO
# destination_domain and are invisible to every analysis section, while only
# 94 of the 3,768 records written after it do (2.5%). Aggregated blindly that
# reads as a 47% failure rate for a bug that is already fixed.
#
# Without a version stamp there is no way to tell those apart, exclude them,
# or target them for reprocessing. Bump this on any change to how records are
# extracted or paired - it is metadata about the PARSER, not the traffic.
# 2026-08-30.4: the stamp itself was initially applied to the HTTP/3 builder
# ONLY, so a live run emitted 8,480 stamped records that were all HTTP/3 while
# every HTTP/1.x, HTTP/2 and handshake record went out unstamped and therefore
# indistinguishable from genuinely pre-fix data. Bumped so those two
# populations stay separable; the self-test now asserts all four builders.
# 2026-08-31.1: `timestamp` now means FLOW START on every protocol. HTTP/1.x
# previously stamped flow END - see build_records. Records written before this
# version carry the old HTTP/1.x semantic and are ~250 ms late.
# 2026-09-01.1: PRODUCT PORT. Phase 0 data policy applied - bodies are not
# written by default, the Cookie header VALUE is redacted (after the AWS
# identity is read out of it), and query-string parameter VALUES are redacted.
# Two new always-present fields: aws_account_id / aws_identity.
# This is the version boundary a lake consumer filters on: records at
# 2026-09-01.1 or later are safe to ship off the device. EARLIER RECORDS ARE
# NOT - they carry live cookies and full request/response bodies.
PARSER_VERSION = "2026-09-01.1"

# Per-run extraction counters, consumed by report_completeness(). Populated by
# the builders; reset per run so the self-test can assert on them.
STATS = {}


def _stat(bucket: str, key: str, n: int = 1):
    STATS.setdefault(bucket, defaultdict(int))[key] += n

HTTP_FIELDS = [
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
    "http.request.method",
    "http.request.uri",
    "http.request.version",
    "http.request.line",
    "http.host",
    "http.response.code",
    "http.response.version",
    "http.response.line",
    "http.file_data",
]

HTTP3_FIELDS = [
    "frame.time_epoch",
    "quic.connection.number",
    # http3.frame_streamid, NOT quic.stream.stream_id - see _last() and
    # build_http3_records for the full root-cause writeup. Short version:
    # quic.stream.stream_id lists every QUIC stream in the packet, which for
    # a response is typically "11|0" (11 = QPACK encoder control stream), so
    # keying on it pairs a response against a control stream and never
    # matches its request. http3.frame_streamid is documented by tshark as
    # "QUIC Stream id that this frame came in on" - the HTTP/3 frame's own
    # stream, which is what request/response correlation actually needs.
    "http3.frame_streamid",
    "quic.stream.fin",
    "ip.dst",
    "udp.dstport",
    "http3.header.header.name",
    "http3.headers.header.value",
    "http3.data",
]

# HTTP/2 over TCP+TLS - added 2026-08-30, and it was a COMPLETE blind spot
# until then. tshark dissects HTTP/2 with an entirely separate `http2.*`
# field family; the `http.*` fields used by HTTP_FIELDS only ever match
# HTTP/1.x. So every HTTP/2 site returned zero rows and zero errors, exactly
# like the HTTP/3 gap found on 2026-08-28 - the domain then fell through to
# the TLS-handshake-only fallback and looked like "captured but never
# decrypted". Confirmed live: us-east-1.console.aws.amazon.com
# POST /api/prod/browserCreds was decrypting perfectly the whole time and
# being silently discarded, which is why AWS never produced an account
# identity (its IAM ARNs live in HTTP/2 response bodies).
#
# Stream semantics differ from HTTP/3 in a way that matters: http2.streamid
# CAN come back multi-valued ("1|0", "3|0") when a control frame on stream 0
# is coalesced into the same TCP segment, but the HEADERS frame's stream is
# FIRST and the control stream is appended after - the OPPOSITE order from
# HTTP/3's frame_streamid. So this path uses _first(), while the HTTP/3 path
# uses _last(). Confirmed live against real rows; do not "unify" these two
# without re-checking, they are genuinely different.
HTTP2_FIELDS = [
    "frame.time_epoch",
    "tcp.stream",
    "http2.streamid",
    "ip.src",
    "ip.dst",
    "tcp.dstport",
    "http2.headers.method",
    "http2.headers.authority",
    "http2.headers.path",
    "http2.headers.status",
    "http2.header.name",
    "http2.header.value",
    "http2.flags.end_stream",
    "http2.data.data",
]

# Third pass, added 2026-08-29: TLS handshakes carry the SNI hostname in
# CLEARTEXT, so a connection that never decrypts (no keylog entry for it)
# still reveals WHO was contacted, even though not WHAT was said. Before
# this, such connections produced no record at all and were invisible to
# the analysis layer - confirmed live: a real MCP call from Claude Code
# showed up in the pcapng only as an SNI for mcp-proxy.anthropic.com, and
# was completely absent from the JSONL, so check_mcp_servers.py could not
# possibly see it.
HANDSHAKE_FIELDS = [
    "frame.time_epoch",
    "ip.dst",
    "tcp.dstport",
    "udp.dstport",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
]


def _run_tshark(pcap_path: Path, keylog_path: Path, display_filter: str, fields: list) -> str:
    # -E quote=d wraps every field value in double quotes (internal quotes
    # escaped as "") - REQUIRED because http.request.line/http.response.line
    # capture the literal wire bytes of a header line, which genuinely
    # contain a raw \r\n. Without quoting, that \r\n corrupts the
    # one-record-per-line structure this script depends on to find row
    # boundaries at all - confirmed live 2026-08-28 (a real self-test run
    # against a hand-built fixture failed exactly this way before quoting
    # was added). occurrence=a + aggregator=| is used uniformly (not
    # occurrence=f for "simple" fields) because a field with only one real
    # occurrence is unaffected by occurrence=a, but http.request.line/
    # http.response.line - which can have MANY occurrences per packet, one
    # per header line - would silently lose every header past the first
    # under occurrence=f. Scalar fields are still defensively split on "|"
    # and the first value taken, in build_records/build_http3_records,
    # in case a field this script assumes is single-valued ever isn't.
    cmd = [
        TSHARK, "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-Y", display_filter,
        "-T", "fields", "-E", "header=y", "-E", "separator=\t",
        "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=d",
    ]
    for field in fields:
        cmd += ["-e", field]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        raise SystemExit(f"tshark not found (tried: {TSHARK}) - install Wireshark, or set PATRONAI_TSHARK to its full path.")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"tshark failed (exit {e.returncode}): {e.stderr}")
    return result.stdout


def run_tshark_http(pcap_path: Path, keylog_path: Path) -> str:
    return _run_tshark(
        pcap_path, keylog_path,
        "tls.handshake.extensions_server_name or http.request or http.response",
        HTTP_FIELDS,
    )


def run_tshark_http3(pcap_path: Path, keylog_path: Path) -> str:
    return _run_tshark(
        pcap_path, keylog_path,
        "http3.header.header.name",
        HTTP3_FIELDS,
    )


def run_tshark_http2(pcap_path: Path, keylog_path: Path) -> str:
    return _run_tshark(
        pcap_path, keylog_path,
        "http2.headers.method or http2.headers.status or http2.data.data",
        HTTP2_FIELDS,
    )


QUIC_SNI_FIELDS = ["quic.connection.number", "tls.handshake.extensions_server_name"]

# Every field this parser asks tshark for, across all five passes.
ALL_TSHARK_FIELDS = sorted(set(
    HTTP_FIELDS + HTTP2_FIELDS + HTTP3_FIELDS + HANDSHAKE_FIELDS + QUIC_SNI_FIELDS))


def verify_tshark_fields(required=None) -> list:
    """Return the required tshark fields this tshark build does NOT know.

    Empty list means every field resolves. This exists because of the single
    nastiest failure mode in this pipeline: asking tshark for a field family
    it does not have returns ZERO ROWS AND EXIT CODE 0 - a silent, error-free
    total loss. It is how AWS traffic (HTTP/2) and Gemini traffic (HTTP/3)
    each went undetected for days.

    Pinning tshark 4.6.8 is not sufficient on its own: Linux endpoints take
    whatever their distro ships, so this runs at startup on every platform
    rather than trusting the pin (PLAN section 0, P4b).

    `tshark -G fields` prints the whole dissector registry, tab-separated,
    with the field abbreviation in column 3.
    """
    required = required if required is not None else ALL_TSHARK_FIELDS
    try:
        result = subprocess.run([TSHARK, "-G", "fields"],
                                capture_output=True, text=True, check=True)
    except FileNotFoundError:
        raise SystemExit(f"tshark not found (tried: {TSHARK}) - install Wireshark, or set PATRONAI_TSHARK to its full path.")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"tshark -G fields failed: {exc}")

    known = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) > 2:
            known.add(parts[2])
    return [f for f in required if f not in known]


def run_tshark_quic_sni(pcap_path: Path, keylog_path: Path) -> str:
    """QUIC handshakes only, as (connection number -> SNI) pairs.

    A separate pass because the HTTP/3 pass filters on
    `http3.header.header.name`, which by definition excludes the handshake
    packets carrying the SNI. Confirmed live that tshark exposes both fields
    together on QUIC CRYPTO frames."""
    return _run_tshark(
        pcap_path, keylog_path,
        "tls.handshake.extensions_server_name and quic",
        QUIC_SNI_FIELDS,
    )


def build_quic_sni_map(raw: str) -> dict:
    """conn number -> SNI. First value wins: a QUIC connection negotiates one
    server name, and a repeat means a retransmitted or coalesced handshake,
    not a second host."""
    out = {}
    for row in _parse_tshark_fields(raw, QUIC_SNI_FIELDS):
        conn = _first(row.get("quic.connection.number"))
        sni = _first(row.get("tls.handshake.extensions_server_name"))
        if conn and sni and conn not in out:
            out[conn] = sni
    return out


def run_tshark_handshakes(pcap_path: Path, keylog_path: Path) -> str:
    return _run_tshark(
        pcap_path, keylog_path,
        "tls.handshake.extensions_server_name",
        HANDSHAKE_FIELDS,
    )


def _decode_body(hexstr: str):
    """Returns (raw_byte_length, decoded_text) - byte length is measured
    BEFORE decompression, matching poc_capture_addon.py's len(raw_content)."""
    if not hexstr:
        return 0, ""
    try:
        raw = bytes.fromhex(hexstr.replace(":", "").replace("|", ""))
    except ValueError:
        return 0, ""
    raw_len = len(raw)
    if raw[:2] == b"\x1f\x8b":
        try:
            text = gzip.decompress(raw).decode("utf-8", errors="replace")
        except (OSError, EOFError):
            # EOFError specifically for a truncated stream - confirmed live,
            # happens when a body spans multiple packets and only one was
            # captured in this record (multi-packet reassembly is a known,
            # not-yet-handled limitation - see module docstring).
            text = "[gzip-compressed, failed to decompress - likely truncated across multiple packets]"
    else:
        text = raw.decode("utf-8", errors="replace")
    return raw_len, text


def _parse_header_lines(joined_lines: str) -> dict:
    """Parses tshark's http.request.line/http.response.line occurrences
    (aggregated with '|', each one a raw "Name: Value\\r\\n" line) into a
    redacted dict - same redaction policy as poc_capture_addon.py."""
    headers = {}
    if not joined_lines:
        return headers
    for line in joined_lines.split("|"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        headers[name] = "[REDACTED]" if name.lower() in SECRET_HEADERS else value
    return headers


def _headers_from_pairs(names: list, values: list) -> dict:
    """Build a header dict from parallel name/value lists, JOINING repeated
    names instead of letting later ones overwrite earlier ones.

    This is not a nicety - dict(zip(...)) silently destroyed data. HTTP/2 and
    HTTP/3 split the Cookie header into one field PER COOKIE for compression
    efficiency (RFC 7540 8.1.2.5), and a real AWS console request was
    confirmed live 2026-08-30 to carry **34 separate `cookie` fields**.
    Collapsing them kept only the last crumb, which is why the aws-userInfo
    cookie - the one carrying the full IAM identity - was absent from every
    record while sitting plainly in the raw capture.

    Cookie crumbs rejoin with "; " to reconstitute a valid Cookie header;
    any other repeated header rejoins with ", " per RFC 9110 field-order
    semantics.

    PSEUDO-HEADERS ARE THE EXCEPTION - first value wins, never joined.
    A pseudo-header (":status", ":method", ":path", ":authority", ":scheme")
    is defined to appear exactly once per HTTP message, so a repeat does NOT
    mean "multi-value field", it means tshark coalesced TWO SEPARATE
    MESSAGES into one row. Joining them produced ":status" = "200, 401",
    which then crashed int() - confirmed live 2026-08-30, a regression
    introduced by the cookie fix itself. Taking the first value keeps the
    row aligned with the first message rather than inventing a hybrid.

    ponytail: the coalesced-second-message is still dropped rather than
    emitted as its own record - the known "multiple messages per row"
    limitation already documented in build_http3_records. First-wins keeps
    that behaviour unchanged instead of silently corrupting the first
    record too."""
    out = {}
    for name, value in zip(names, values):
        if not name:
            continue
        if name in out:
            if name.startswith(":"):
                continue  # pseudo-header: first wins, never joined
            sep = "; " if name.lower() == "cookie" else ", "
            out[name] = f"{out[name]}{sep}{value}"
        else:
            out[name] = value
    return out


def _as_int(value):
    """Parse a status code defensively. Returns None rather than raising on
    anything unexpected - a single malformed row must never abort a whole
    segment's conversion (that failure mode cost 4 entire segments once
    already, via the csv field-limit crash)."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _redact_http3_headers(headers: dict) -> dict:
    return {k: ("[REDACTED]" if k.lower() in SECRET_HEADERS else v) for k, v in headers.items()}


def _parse_tshark_fields(raw: str, fields: list):
    """Parse tshark -T fields -E header=y -E quote=d tab-separated output
    into dicts keyed by the given field list - the field order THIS script
    requested, not re-parsed from tshark's own header row (that row is just
    skipped; no need to handle its quoting separately). Uses Python's csv
    module, not line.split("\\n")/"\\t" - required because a quoted field
    (see _run_tshark's -E quote=d comment) can legitimately span what looks
    like multiple physical lines when it contains an embedded \\r\\n, which
    naive newline-splitting cannot handle without corrupting row
    boundaries."""
    reader = csv.reader(io.StringIO(raw), delimiter="\t", quotechar='"')
    rows = list(reader)
    if not rows:
        return
    for cols in rows[1:]:  # rows[0] is tshark's own header row - skipped
        if not cols:
            continue
        cols = cols + [""] * (len(fields) - len(cols))
        yield dict(zip(fields, cols))


def _first(value) -> str:
    """First value of a possibly '|'-joined multi-occurrence tshark field.
    Every field is requested with occurrence=a (see _run_tshark) so ANY
    field could in principle come back multi-valued, not just the ones
    this script expects to repeat (confirmed live earlier: quic.stream.
    stream_id returned multiple values per packet unexpectedly) - scalar
    fields always go through this, never read raw. Body/header-line fields
    are the deliberate exception - they pass their full '|'-joined value
    straight to _decode_body/_parse_header_lines instead, since those
    specifically need every occurrence, not just the first."""
    return (value or "").split("|")[0]


def _last(value) -> str:
    """LAST value of a '|'-joined multi-occurrence tshark field.

    Used only for http3.frame_streamid. A single QUIC packet coalesces
    several HTTP/3 frames, and tshark lists their stream ids in wire order:
    control/QPACK frames come first, the HEADERS frame that actually carries
    :method or :status comes LAST. Confirmed live 2026-08-29 against a real
    capture:

        request   frame_streamid = "2|0"  -> HEADERS is on stream 0
        response  frame_streamid = "0"    -> HEADERS is on stream 0   (pairs)

    Taking _first() here instead picks stream 2 for that request - a control
    stream - so the request keys to (conn,"2") while its response keys to
    (conn,"0") and they can never match. That single wrong index was
    responsible for a measured 89% orphan rate on HTTP/3 records."""
    return (value or "").split("|")[-1]


def build_records(raw: str):
    """Classic HTTP/1.1-2 over TCP+TLS - request/response paired per tcp.stream."""
    sni_by_stream = {}
    tls_version_by_stream = {}
    pending_requests = defaultdict(deque)  # tcp.stream -> deque of request row dicts
    records = []

    for row in _parse_tshark_fields(raw, HTTP_FIELDS):
        stream = _first(row.get("tcp.stream"))
        sni = _first(row.get("tls.handshake.extensions_server_name"))
        if sni:
            sni_by_stream[stream] = sni
            # tls.handshake.version only appears on this same handshake
            # packet, never on the later request/response packets - must be
            # cached per-stream here, same as SNI, not read from the
            # response row later (that field would always be empty there).
            tls_version = _first(row.get("tls.handshake.version"))
            if tls_version:
                tls_version_by_stream[stream] = tls_version
            continue

        if _first(row.get("http.request.method")):
            pending_requests[stream].append(row)
            continue

        if _first(row.get("http.response.code")):
            req = pending_requests[stream].popleft() if pending_requests[stream] else {}
            # Same direction caveat as dst_ip below - the last-resort fallback
            # must be the REQUEST's destination, not the response row's.
            domain = (sni_by_stream.get(stream) or _first(req.get("http.host"))
                      or _first(req.get("ip.dst")) or _first(row.get("ip.src")))
            req_bytes, req_body = _decode_body(req.get("http.file_data", ""))
            resp_bytes, resp_body = _decode_body(row.get("http.file_data", ""))
            dstport = _first(row.get("tcp.dstport"))
            status = _first(row.get("http.response.code"))
            # DIRECTION FIX 2026-08-30. `row` here is the RESPONSE packet, so
            # its ip.dst is this machine and its ip.src is the server - the
            # exact opposite of what these two fields mean. Reading them off
            # the response row swapped destination_ip and client_ip on EVERY
            # HTTP/1.x record. Found while surveying signals for the SaaS
            # discovery pass: download.windowsupdate.com, ws.chatgpt.com and
            # c.pki.goog all reported RFC1918 "destination" addresses, which
            # would have made any private-IP-means-internal-service heuristic
            # completely wrong. Prefer the REQUEST row's addresses (correct by
            # construction); fall back to the response row with src/dst
            # deliberately swapped when no request was paired.
            dst_ip = _first(req.get("ip.dst")) or _first(row.get("ip.src"))
            src_ip = _first(req.get("ip.src")) or _first(row.get("ip.dst"))
            # TIMESTAMP SEMANTICS - flow START, matching HTTP/2 and HTTP/3.
            # This read `row` (the RESPONSE packet) until 2026-08-31, so an
            # HTTP/1.x record was stamped at flow END while every HTTP/2 and
            # HTTP/3 record was stamped at flow START. Measured across the
            # reference capture: 3,218 HTTP/1.1 records stamped ==response_end
            # vs 17,718 HTTP/2/3 records stamped ==request_start, with a
            # median flow duration of 231-338 ms. That is a one-directional
            # ~1/4-second BIAS, not noise - it survives averaging, and it
            # silently corrupts any cross-protocol correlation ("what did the
            # user open just before this call?"). Falls back to the response
            # frame so an unpaired response still carries a time.
            records.append({
                "parser_version": PARSER_VERSION,
                "timestamp": (_first(req.get("frame.time_epoch"))
                              or _first(row.get("frame.time_epoch")) or None),
                "destination_domain": domain or None,
                "destination_ip": dst_ip or None,
                "destination_port": _as_int(dstport),
                "client_ip": src_ip or None,
                "protocol": "https",
                "http_version": _first(req.get("http.request.version")) or _first(row.get("http.response.version")) or None,
                "method": _first(req.get("http.request.method")) or None,
                "path": _first(req.get("http.request.uri")) or None,
                "status_code": _as_int(status),
                "request_bytes": req_bytes,
                "response_bytes": resp_bytes,
                "bytes_transferred": req_bytes + resp_bytes,
                "request_headers": _parse_header_lines(req.get("http.request.line", "")),
                "response_headers": _parse_header_lines(row.get("http.response.line", "")),
                "request_body": req_body,
                "response_body": resp_body,
                "tls_version": tls_version_by_stream.get(stream),
                "sni": sni_by_stream.get(stream),
                "request_start": _first(req.get("frame.time_epoch")) or None,
                "request_end": _first(req.get("frame.time_epoch")) or None,
                "response_end": _first(row.get("frame.time_epoch")) or None,
            })

    return records


def _finalize_http3_record(resp: dict) -> dict:
    """Builds the final flat record from an accumulated response - joins
    ALL of that response's http3.data fragments (across however many
    packets it took) into one hex string BEFORE decoding, not decoded
    fragment-by-fragment - decoding piecemeal would corrupt a multi-byte
    UTF-8 character or a gzip stream that happens to split across a
    fragment boundary."""
    req = resp["req"]
    req_headers = req["headers"]
    combined_hex = "".join(resp["data_parts"])
    req_bytes, req_body = _decode_body(req.get("body_hex", ""))
    resp_bytes, resp_body = _decode_body(combined_hex)
    udp_dstport = req.get("udp_dstport", "")
    # :authority is a REQUEST pseudo-header, so an orphaned response has none.
    # sni_fallback carries the QUIC connection's cleartext SNI for exactly
    # that case - see the orphan branch in build_http3_records.
    domain = req_headers.get(":authority") or req.get("sni_fallback")
    return {
        "parser_version": PARSER_VERSION,
        "timestamp": req.get("frame_time") or resp.get("frame_time") or None,
        "destination_domain": domain,
        "destination_ip": req.get("ip_dst") or None,
        "destination_port": _as_int(udp_dstport),
        "client_ip": None,
        "protocol": "https",
        "http_version": "3",
        "method": req_headers.get(":method"),
        "path": req_headers.get(":path"),
        "status_code": _as_int(resp["headers"].get(":status")),
        "request_bytes": req_bytes,
        "response_bytes": resp_bytes,
        "bytes_transferred": req_bytes + resp_bytes,
        "request_headers": _redact_http3_headers(req_headers),
        "response_headers": _redact_http3_headers(resp["headers"]),
        "request_body": req_body,
        "response_body": resp_body,
        "tls_version": "TLS 1.3",
        "sni": domain,
        "request_start": req.get("frame_time") or None,
        "request_end": req.get("frame_time") or None,
        "response_end": resp.get("frame_time") or None,
    }


def build_http3_records(raw: str, sni_by_conn: dict = None):
    """HTTP/3 over QUIC+UDP - request/response paired per EXACT
    (quic.connection.number, quic.stream.stream_id), added 2026-08-28
    (replacing per-connection-only FIFO pairing) for two reasons at once:

    1. Multi-packet response reassembly - a large response (confirmed live:
       Gemini's account-switcher-adjacent L5adhe call, gzip-compressed,
       response.bin attachment) spans multiple packets. Every http3.data
       fragment on the SAME stream, from the :status-bearing packet through
       to quic.stream.fin, is now concatenated before decoding - previously
       only the single :status packet's data was used, so any response
       needing more than one packet showed up truncated.
    2. Pairing accuracy - per-connection FIFO (the previous design) could
       mismatch request N's response with an unrelated response M when a
       connection had multiple concurrent streams in flight - the
       already-documented ~48% empty-domain-field issue from an earlier
       real capture. Exact-stream pairing cannot make that specific mistake.

    ROOT CAUSE FIX 2026-08-30 - two independent defects were compounding
    here, which is why fixing either one alone barely moved the numbers.
    Measured on a real capture, orphaned-response rate:

        current code (both defects)           89%
        correct stream field only             75%
        dedupe only                           57%
        BOTH fixes                             0%

    Defect 1 - WRONG STREAM FIELD AND WRONG ELEMENT. The old code keyed on
    _first(quic.stream.stream_id). That field lists every QUIC stream in the
    packet, and for a response it is typically "11|0" (11 = QPACK encoder
    control stream), so the response keyed to a control stream and could
    never match its request. Fixed by keying on _last(http3.frame_streamid)
    instead - tshark documents that field as "QUIC Stream id that this frame
    came in on", and the HEADERS frame is last in wire order. See _last().

    Defect 2 - pktmon CAPTURES EVERY PACKET ~4 TIMES. Its default
    --comp all logs the same packet once per NDIS layer, so each logical
    HTTP/3 message appears as ~4 identical rows (confirmed live: every
    (conn, stream) key had exactly 4 occurrences). Pairing pops the pending
    request on the first matching response, so 1 response paired and the
    other 3 orphaned - exactly the 3-of-4 = 75% floor observed. Fixed by
    dropping duplicate rows before pairing.

    Deduping in the PARSER rather than relying on `pktmon start --comp nics`
    is deliberate: it makes correctness independent of how the capture was
    taken, so an existing .etl captured with default settings still parses
    correctly. Note an earlier attempt to measure this duplication keyed on
    (frame.time_epoch, frame.len, ip.id) and reported only 3% duplicates -
    that was wrong, because each layer's copy carries a slightly different
    timestamp. Dedupe on semantic content, never on frame timing."""
    sni_by_conn = sni_by_conn or {}
    pending_requests = {}   # (conn, stream) -> request dict
    open_responses = {}     # (conn, stream) -> accumulating response dict
    seen_rows = set()       # dedupe key -> pktmon's ~4x per-layer copies
    records = []

    for row in _parse_tshark_fields(raw, HTTP3_FIELDS):
        _stat("http3", "tshark_rows")
        conn = _first(row.get("quic.connection.number"))
        stream = _last(row.get("http3.frame_streamid"))
        key = (conn, stream)
        fin = _first(row.get("quic.stream.fin")) in ("1", "True", "true")
        names = (row.get("http3.header.header.name") or "").split("|")
        values = (row.get("http3.headers.header.value") or "").split("|")
        headers = _headers_from_pairs(names, values) if names != [""] else {}
        data_hex = row.get("http3.data", "")

        # Drop pktmon's duplicate per-layer copies of the same packet
        # (defect 2 in this function's docstring). Keyed on semantic content
        # - stream, header set, and body - deliberately NOT on frame timing,
        # since each layer's copy carries a slightly different timestamp and
        # would therefore look unique.
        row_sig = (key, tuple(sorted(headers.items())), data_hex)
        if row_sig in seen_rows:
            _stat("http3", "pktmon_duplicate_rows")
            continue
        seen_rows.add(row_sig)
        _stat("http3", "unique_rows")
        if ":method" in headers:
            _stat("http3", "requests")
        elif ":status" in headers:
            _stat("http3", "responses")

        if ":method" in headers:
            pending_requests[key] = {
                "headers": headers,
                "body_hex": data_hex,
                "ip_dst": _first(row.get("ip.dst")),
                "udp_dstport": _first(row.get("udp.dstport")),
                "frame_time": _first(row.get("frame.time_epoch")),
            }
            continue

        if ":status" in headers:
            if key not in pending_requests:
                # ORPHANED RESPONSE - no request was paired. Previously this
                # produced a record with destination_domain=None (":authority"
                # lives on the REQUEST only), making it invisible to every
                # analysis section: no domain, no path, unusable. Falling back
                # to the QUIC connection's cleartext SNI recovers the domain,
                # so the record still counts toward "which host, when, how
                # often" even though the URL is unrecoverable. Same principle
                # as the HTTP/1.x path, which has always used sni_by_stream.
                _stat("http3", "orphan_responses")
            req = pending_requests.pop(key, {"headers": {}, "body_hex": "", "udp_dstport": "",
                                             "frame_time": "", "sni_fallback": sni_by_conn.get(conn)})
            open_responses[key] = {
                "req": req,
                "headers": headers,
                "data_parts": [data_hex] if data_hex else [],
                "frame_time": _first(row.get("frame.time_epoch")),
            }
            if fin:
                records.append(_finalize_http3_record(open_responses.pop(key)))
            continue

        # Continuation: a DATA-only packet (no header pseudo-fields) on a
        # stream whose response is already open - append its fragment.
        if key in open_responses:
            if data_hex:
                open_responses[key]["data_parts"].append(data_hex)
            if fin:
                records.append(_finalize_http3_record(open_responses.pop(key)))

    # Anything still open when the capture ends (no fin ever seen, e.g. the
    # capture was stopped mid-stream) - emit anyway with whatever fragments
    # were captured, rather than silently dropping it.
    for resp in open_responses.values():
        records.append(_finalize_http3_record(resp))

    # Unanswered requests - same reasoning as the HTTP/2 path: a request
    # observed on the wire is evidence even with no response, and dropping
    # it silently loses the URL (which is where several identity signals
    # live). See build_http2_records for the claude.ai case that exposed it.
    for req in pending_requests.values():
        records.append(_finalize_http3_record(
            {"req": req, "headers": {}, "data_parts": [], "frame_time": None}))

    return records


def _finalize_http2_record(resp: dict) -> dict:
    """Build the flat record from an accumulated HTTP/2 exchange. Same
    fragment-joining rule as _finalize_http3_record: concatenate ALL data
    fragments before decoding, never decode fragment-by-fragment."""
    req = resp["req"]
    combined_hex = "".join(resp["data_parts"])
    req_bytes, req_body = _decode_body(req.get("body_hex", ""))
    resp_bytes, resp_body = _decode_body(combined_hex)
    port = req.get("tcp_dstport", "")
    domain = req.get("authority") or None
    status = resp.get("status", "")
    return {
        "parser_version": PARSER_VERSION,
        "timestamp": req.get("frame_time") or resp.get("frame_time") or None,
        "destination_domain": domain,
        "destination_ip": req.get("ip_dst") or None,
        "destination_port": _as_int(port),
        "client_ip": req.get("ip_src") or None,
        "protocol": "https",
        "http_version": "2",
        "method": req.get("method") or None,
        "path": req.get("path") or None,
        "status_code": _as_int(status),
        "request_bytes": req_bytes,
        "response_bytes": resp_bytes,
        "bytes_transferred": req_bytes + resp_bytes,
        "request_headers": req.get("headers") or {},
        "response_headers": resp.get("headers") or {},
        "request_body": req_body,
        "response_body": resp_body,
        "tls_version": None,
        "sni": domain,
        "request_start": req.get("frame_time") or None,
        "request_end": req.get("frame_time") or None,
        "response_end": resp.get("frame_time") or None,
    }


def build_http2_records(raw: str):
    """HTTP/2 over TCP+TLS - paired per (tcp.stream, http2.streamid).

    Mirrors build_http3_records, with two deliberate differences:

    1. _first(http2.streamid), NOT _last(). A coalesced control frame on
       stream 0 is appended AFTER the HEADERS frame's stream here, the
       reverse of HTTP/3's frame ordering. Confirmed live on real rows
       ("1|0", "3|0" -> HEADERS stream is 1 and 3).
    2. No SNI lookup is needed - HTTP/2 carries :authority in the request
       headers, which is the destination domain directly.

    Shares the same pktmon ~4x per-layer duplicate filtering, for the same
    reason documented in build_http3_records."""
    pending_requests = {}
    open_responses = {}
    seen_rows = set()
    records = []

    for row in _parse_tshark_fields(raw, HTTP2_FIELDS):
        tcp_stream = _first(row.get("tcp.stream"))
        h2_stream = _first(row.get("http2.streamid"))
        key = (tcp_stream, h2_stream)
        method = _first(row.get("http2.headers.method"))
        status = _first(row.get("http2.headers.status"))
        data_hex = row.get("http2.data.data", "")
        end_stream = "True" in (row.get("http2.flags.end_stream") or "")

        names = (row.get("http2.header.name") or "").split("|")
        values = (row.get("http2.header.value") or "").split("|")
        headers = _redact_http3_headers(_headers_from_pairs(names, values)) if names != [""] else {}

        row_sig = (key, method, status, tuple(sorted(headers.items())), data_hex)
        if row_sig in seen_rows:
            continue
        seen_rows.add(row_sig)

        if method:
            pending_requests[key] = {
                "method": method,
                "authority": _first(row.get("http2.headers.authority")),
                "path": _first(row.get("http2.headers.path")),
                "headers": headers,
                "body_hex": data_hex,
                "ip_src": _first(row.get("ip.src")),
                "ip_dst": _first(row.get("ip.dst")),
                "tcp_dstport": _first(row.get("tcp.dstport")),
                "frame_time": _first(row.get("frame.time_epoch")),
            }
            continue

        if status:
            req = pending_requests.pop(key, {"headers": {}, "body_hex": "",
                                              "tcp_dstport": "", "frame_time": ""})
            open_responses[key] = {
                "req": req,
                "status": status,
                "headers": headers,
                "data_parts": [data_hex] if data_hex else [],
                "frame_time": _first(row.get("frame.time_epoch")),
            }
            if end_stream:
                records.append(_finalize_http2_record(open_responses.pop(key)))
            continue

        # DATA-only frame continuing an already-open response.
        if key in open_responses:
            if data_hex:
                open_responses[key]["data_parts"].append(data_hex)
            if end_stream:
                records.append(_finalize_http2_record(open_responses.pop(key)))

    # Anything still open when the capture ends - emit rather than drop.
    for resp in open_responses.values():
        records.append(_finalize_http2_record(resp))

    # UNANSWERED REQUESTS - emit these too. They were silently DROPPED
    # before 2026-08-30, and that dropped real data: a segment containing
    # 28 claude.ai /api/organizations/<uuid>/chat_conversations requests
    # produced ZERO records for them, because claude.ai's SSE completion
    # responses stream past the segment boundary and no :status ever
    # arrives inside this file. A request that was observed on the wire is
    # evidence in its own right - the URL alone carries the org id this
    # POC needs - so it must not require a matching response to survive.
    for req in pending_requests.values():
        records.append(_finalize_http2_record(
            {"req": req, "status": "", "headers": {}, "data_parts": [], "frame_time": None}))

    return records


def build_handshake_records(raw: str, decrypted_domains: set):
    """One record per TLS handshake whose SNI hostname produced NO decrypted
    HTTP record anywhere in this capture - i.e. connections we can see the
    destination of but not the content of.

    Deliberately skips any hostname that DID decrypt, to avoid duplicating
    what the HTTP/HTTP3 passes already reported in full. The result is a
    clean "seen but unreadable" layer rather than a second copy of
    everything.

    These records carry no method/path/body by construction (that data is
    encrypted and we have no key for it) and are marked tls_only=True so a
    consumer can tell "this connection existed" apart from "this request
    was empty". Confirmed live 2026-08-29: this is the ONLY way an MCP call
    made through Anthropic's connector infrastructure is visible at all on
    the endpoint - it shows up as an SNI for mcp-proxy.anthropic.com and
    nothing else."""
    records = []
    for row in _parse_tshark_fields(raw, HANDSHAKE_FIELDS):
        sni = _first(row.get("tls.handshake.extensions_server_name"))
        if not sni or sni in decrypted_domains:
            continue
        tcp_port = _first(row.get("tcp.dstport"))
        udp_port = _first(row.get("udp.dstport"))
        port = tcp_port or udp_port
        records.append({
            "parser_version": PARSER_VERSION,
            "timestamp": _first(row.get("frame.time_epoch")) or None,
            "destination_domain": sni,
            "destination_ip": _first(row.get("ip.dst")) or None,
            "destination_port": _as_int(port),
            "client_ip": None,
            "protocol": "https",
            "http_version": "3" if (udp_port and not tcp_port) else None,
            "method": None,
            "path": None,
            "status_code": None,
            "request_bytes": None,
            "response_bytes": None,
            "bytes_transferred": None,
            "request_headers": {},
            "response_headers": {},
            "request_body": None,
            "response_body": None,
            "tls_version": _first(row.get("tls.handshake.version")) or None,
            "sni": sni,
            "request_start": None,
            "request_end": None,
            "response_end": None,
            "tls_only": True,
        })
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--keylog", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--no-handshakes", action="store_true",
                        help="skip SNI-only records for connections that never decrypted")
    # Both policy flags default to the SAFE state, so forgetting to pass one
    # can never widen what is collected. They only ever loosen the policy.
    parser.add_argument("--save-bodies", action="store_true",
                        help="store request/response bodies. Default: OFF - bodies "
                             "are never written, and must not be shipped off-device")
    parser.add_argument("--keep-raw-params", action="store_true",
                        help="keep query-string values unredacted. Default: OFF - "
                             "param names are kept, values redacted")
    args = parser.parse_args()

    STATS.clear()
    http_records = build_records(run_tshark_http(args.pcap, args.keylog))
    http2_records = build_http2_records(run_tshark_http2(args.pcap, args.keylog))
    sni_by_conn = build_quic_sni_map(run_tshark_quic_sni(args.pcap, args.keylog))
    http3_records = build_http3_records(run_tshark_http3(args.pcap, args.keylog), sni_by_conn)
    records = http_records + http2_records + http3_records

    handshake_records = []
    if not args.no_handshakes:
        decrypted_domains = {r.get("destination_domain") for r in records if r.get("destination_domain")}
        handshake_records = build_handshake_records(
            run_tshark_handshakes(args.pcap, args.keylog), decrypted_domains)
        records += handshake_records

    # THE policy choke point. Every record from every builder passes through
    # sanitize() here, on its way to disk. Do not write records anywhere else.
    with args.out.open("w", encoding="utf-8") as f:
        for r in records:
            sanitize(r,
                     save_bodies=args.save_bodies,
                     redact_params=not args.keep_raw_params)
            f.write(json.dumps(r) + "\n")

    print(f"Wrote {len(records)} records to {args.out} "
          f"({len(http_records)} HTTP/1.x, {len(http2_records)} HTTP/2, "
          f"{len(http3_records)} HTTP/3, {len(handshake_records)} TLS-handshake-only)")

    report_completeness(records, len(http3_records))


def report_completeness(records: list, http3_emitted: int, warn_pct: float = 5.0) -> list:
    """THE COMPLETENESS ASSERTION.

    Every silent-loss bug in this pipeline's history shared one shape: tshark
    returned rows, the parser dropped them, and NOTHING said so. Exit code 0,
    a plausible-looking JSONL, and a wrong answer downstream. The HTTP/2 blind
    spot (an entire protocol yielding zero records), the csv field-limit crash
    (4 whole segments lost), the restart filename collision (every segment
    skipped, JSONL frozen) and the HTTP/3 stream-pairing defect (47% of
    records with no domain) would each have been caught in one run by this
    check instead of costing hours of forensics apiece.

    It compares what tshark HANDED us against what we EMITTED, and says so out
    loud. Returns the list of warning strings (empty = clean) so a caller can
    fail a build on it; prints regardless.

    Note the pktmon duplicate count is reported, not treated as loss: pktmon's
    default --comp all logs each packet once per NDIS layer (~4x), so dropping
    those rows is correct behaviour and must not look like a defect."""
    warnings = []
    print("\n--- completeness ---")

    h3 = STATS.get("http3", {})
    rows = h3.get("tshark_rows", 0)
    if rows:
        uniq = h3.get("unique_rows", 0)
        dupes = h3.get("pktmon_duplicate_rows", 0)
        reqs = h3.get("requests", 0)
        resps = h3.get("responses", 0)
        orphans = h3.get("orphan_responses", 0)
        print(f"  HTTP/3  tshark rows {rows}  ->  unique {uniq} "
              f"(pktmon dupes dropped: {dupes})")
        print(f"          requests {reqs}   responses {resps}   "
              f"records emitted {http3_emitted}")
        if resps:
            pct = 100.0 * orphans / resps
            note = "" if pct <= warn_pct else "   <-- OVER THRESHOLD"
            print(f"          orphaned responses (no paired request): "
                  f"{orphans} = {pct:.1f}%{note}")
            if pct > warn_pct:
                warnings.append(
                    f"HTTP/3 orphaned-response rate {pct:.1f}% exceeds {warn_pct}% "
                    f"- pairing may be broken; these records have no URL")

    # Records that carry no destination_domain are unusable by EVERY analysis
    # section - no host, no path, nothing to group on. This is the single
    # number that best predicts "the report will silently under-count".
    blind = sum(1 for r in records if not r.get("destination_domain"))
    total = len(records) or 1
    pct = 100.0 * blind / total
    note = "" if pct <= warn_pct else "   <-- OVER THRESHOLD"
    print(f"  records with NO destination_domain: {blind}/{total} = {pct:.1f}%{note}")
    if pct > warn_pct:
        warnings.append(
            f"{pct:.1f}% of records have no destination_domain - they are "
            f"invisible to every analysis section")

    if warnings:
        print("  RESULT: SUSPECT - " + str(len(warnings)) + " warning(s)")
        for w in warnings:
            print(f"     ! {w}")
    else:
        print("  RESULT: clean")
    return warnings


def _build_tsv(fields: list, rows: list) -> str:
    """Builds a tab-separated string matching tshark's real -E quote=d
    output shape (every field double-quoted, CSV-escaped) via csv.writer -
    NOT hand-typed tab strings. Confirmed live: an earlier hand-typed
    fixture broke the very bug this rewrite fixes (a field containing a
    literal \\r\\n corrupted naive line-splitting) - building fixtures
    through the real csv module, the same way the parser reads them back,
    is what makes the self-test actually exercise that fix instead of
    accidentally sidestepping it."""
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter="\t", quotechar='"', quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(fields)
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def _selftest():
    """Canned-fixture check - does NOT require tshark. Validates the
    csv-based parsing + pairing + header-redaction logic for BOTH protocol
    paths. The HTTP/3 field shape was confirmed live against a real
    decrypted capture in an earlier pass; the http.request.line/
    response.line fields added in this pass were NOT re-verified live
    (tool access was blocked mid-session - see module docstring), and a
    real run against this exact self-test DID catch a bug (tls_version read
    from the wrong packet, and naive line-splitting breaking on an embedded
    \\r\\n) - both fixed here, but treat this pass as still needing a real
    tshark run to fully confirm."""
    # --- classic HTTP/1-2, including header capture + redaction ---
    body_hex = b'[{"name":"Test"}]'.hex(":")
    req_line = "GET /api/mcp/remote_servers HTTP/1.1\r\n|Authorization: Bearer secret-token\r\n|Cookie: sid=abc123\r\n"
    resp_line = "HTTP/1.1 200 OK\r\n|Content-Type: application/json\r\n"

    def http_row(**kwargs):
        return [kwargs.get(f, "") for f in HTTP_FIELDS]

    common = {"tcp.stream": "0", "ip.src": "10.0.0.5", "ip.dst": "1.2.3.4",
              "tcp.srcport": "55000", "tcp.dstport": "443"}
    rows = [
        http_row(**common, **{"frame.time_epoch": "1000.0",
                               "tls.handshake.extensions_server_name": "example.com",
                               "tls.handshake.version": "TLS 1.2"}),
        http_row(**common, **{"frame.time_epoch": "1000.1",
                               "http.request.method": "GET",
                               "http.request.uri": "/api/mcp/remote_servers",
                               "http.request.version": "HTTP/1.1",
                               "http.request.line": req_line,
                               "http.host": "example.com"}),
        http_row(**common, **{"frame.time_epoch": "1000.2",
                               "http.response.code": "200",
                               "http.response.version": "HTTP/1.1",
                               "http.response.line": resp_line,
                               "http.file_data": body_hex}),
    ]
    raw = _build_tsv(HTTP_FIELDS, rows)
    records = build_records(raw)
    assert len(records) == 1, f"expected 1 HTTP record, got {len(records)}"
    r = records[0]
    assert r["destination_domain"] == "example.com", r
    assert r["method"] == "GET", r
    assert r["path"] == "/api/mcp/remote_servers", r
    assert r["status_code"] == 200, r
    assert r["http_version"] == "HTTP/1.1", r
    assert r["tls_version"] == "TLS 1.2", r
    assert json.loads(r["response_body"]) == [{"name": "Test"}], r
    assert r["request_headers"]["Authorization"] == "[REDACTED]", r["request_headers"]
    assert r["request_headers"]["Cookie"] == "sid=abc123", r["request_headers"]  # deliberately NOT redacted
    assert r["response_headers"]["Content-Type"] == "application/json", r["response_headers"]
    assert r["request_bytes"] == 0 and r["response_bytes"] == len(b'[{"name":"Test"}]'), r

    # --- HTTP/3 over QUIC, single-packet response, including header
    # capture + redaction + exact-stream pairing ---
    def http3_row(**kwargs):
        return [kwargs.get(f, "") for f in HTTP3_FIELDS]

    # Stream ids here reproduce the REAL shape confirmed live 2026-08-29:
    # the request's frame_streamid is "2|0" (a control frame on stream 2
    # coalesced ahead of the HEADERS frame on stream 0) while the response's
    # is plain "0". Only _last() pairs these; _first() would key the request
    # to stream "2" and orphan the response. Keeping the asymmetric fixture
    # means this test actually exercises the root-cause fix rather than
    # passing trivially on matching values.
    resp_body_hex = b'{"serverInfo":{"name":"Test MCP","version":"1.0"}}'.hex(":")
    rows3 = [
        http3_row(**{"frame.time_epoch": "2000.0", "quic.connection.number": "0",
                     "http3.frame_streamid": "2|0", "ip.dst": "1.2.3.4", "udp.dstport": "443",
                     "http3.header.header.name": ":method|:authority|:scheme|:path|cookie",
                     "http3.headers.header.value": "POST|mcp.example.com|https|/mcp|sid=xyz"}),
        http3_row(**{"frame.time_epoch": "2000.1", "quic.connection.number": "0",
                     "http3.frame_streamid": "0", "quic.stream.fin": "1",
                     "ip.dst": "1.2.3.4", "udp.dstport": "0",
                     "http3.header.header.name": ":status|content-type",
                     "http3.headers.header.value": "200|application/json",
                     "http3.data": resp_body_hex}),
    ]
    raw3 = _build_tsv(HTTP3_FIELDS, rows3)
    records3 = build_http3_records(raw3)
    assert len(records3) == 1, f"expected 1 HTTP/3 record, got {len(records3)}"
    r3 = records3[0]
    assert r3["destination_domain"] == "mcp.example.com", r3
    assert r3["method"] == "POST", r3
    assert r3["path"] == "/mcp", r3
    assert r3["status_code"] == 200, r3
    assert r3["http_version"] == "3", r3
    assert r3["tls_version"] == "TLS 1.3", r3
    assert r3["request_headers"]["cookie"] == "sid=xyz", r3["request_headers"]  # deliberately NOT redacted
    assert json.loads(r3["response_body"]) == {"serverInfo": {"name": "Test MCP", "version": "1.0"}}, r3

    # --- HTTP/3 multi-packet response reassembly - the actual bug found
    # live 2026-08-28 (Gemini's L5adhe call: "response_body":
    # "[gzip-compressed, failed to decompress - likely truncated across
    # multiple packets]") - a response whose data arrives split across two
    # packets on the SAME stream, second packet carrying no header fields
    # at all (a pure DATA-frame continuation) and setting fin. ---
    big_payload = json.dumps({"serverInfo": {"name": "Reassembled MCP", "version": "2.0"},
                               "padding": "x" * 40}).encode()
    big_hex = big_payload.hex(":")
    split_at = len(big_hex) // 2
    part1, part2 = big_hex[:split_at], big_hex[split_at:]
    rows3b = [
        http3_row(**{"frame.time_epoch": "3000.0", "quic.connection.number": "1",
                     "http3.frame_streamid": "4", "ip.dst": "1.2.3.4", "udp.dstport": "443",
                     "http3.header.header.name": ":method|:authority|:path",
                     "http3.headers.header.value": "POST|mcp.example.com|/mcp"}),
        http3_row(**{"frame.time_epoch": "3000.1", "quic.connection.number": "1",
                     "http3.frame_streamid": "4", "ip.dst": "1.2.3.4", "udp.dstport": "0",
                     "http3.header.header.name": ":status", "http3.headers.header.value": "200",
                     "http3.data": part1}),
        # continuation packet - no header fields at all, just more data + fin
        http3_row(**{"frame.time_epoch": "3000.2", "quic.connection.number": "1",
                     "http3.frame_streamid": "4", "quic.stream.fin": "1",
                     "http3.data": part2}),
    ]
    raw3b = _build_tsv(HTTP3_FIELDS, rows3b)
    records3b = build_http3_records(raw3b)
    assert len(records3b) == 1, f"expected 1 reassembled HTTP/3 record, got {len(records3b)}"
    r3b = records3b[0]
    assert json.loads(r3b["response_body"]) == json.loads(big_payload), \
        f"multi-packet reassembly failed: {r3b['response_body']!r}"
    assert r3b["response_bytes"] == len(big_payload), r3b

    # --- pktmon's ~4x per-layer duplication (defect 2). The SAME logical
    # exchange repeated 4 times, as a real default-settings capture emits
    # it, must still yield exactly ONE record - not 1 paired + 3 orphans,
    # which was the measured 75% orphan floor before the dedupe. ---
    dup_body = b'{"ok":true}'.hex(":")
    one_exchange = [
        http3_row(**{"frame.time_epoch": "4000.0", "quic.connection.number": "7",
                     "http3.frame_streamid": "2|8", "ip.dst": "9.9.9.9", "udp.dstport": "443",
                     "http3.header.header.name": ":method|:authority|:path",
                     "http3.headers.header.value": "GET|dup.example.com|/x"}),
        http3_row(**{"frame.time_epoch": "4000.1", "quic.connection.number": "7",
                     "http3.frame_streamid": "8", "quic.stream.fin": "1",
                     "ip.dst": "9.9.9.9", "udp.dstport": "0",
                     "http3.header.header.name": ":status",
                     "http3.headers.header.value": "200", "http3.data": dup_body}),
    ]
    rows3c = one_exchange * 4          # pktmon logs each packet once per layer
    raw3c = _build_tsv(HTTP3_FIELDS, rows3c)
    records3c = build_http3_records(raw3c)
    assert len(records3c) == 1, \
        f"dedupe failed: 4x-duplicated exchange produced {len(records3c)} records, expected 1"
    assert records3c[0]["destination_domain"] == "dup.example.com", records3c[0]
    assert records3c[0]["method"] == "GET", records3c[0]
    assert json.loads(records3c[0]["response_body"]) == {"ok": True}, records3c[0]

    # --- HTTP/2 over TCP+TLS. The whole protocol was invisible until
    # 2026-08-30 (http.* fields only match HTTP/1.x), which is why AWS
    # console traffic never produced an account identity. Fixture uses the
    # real shape confirmed live: request streamid "1", response streamid
    # "1|0" (control stream 0 coalesced AFTER the HEADERS stream) - so this
    # exercises _first(), the OPPOSITE of the HTTP/3 path's _last(). ---
    def http2_row(**kwargs):
        return [kwargs.get(f, "") for f in HTTP2_FIELDS]

    h2_body = b'{"account":"arn:aws:iam::123:user/x"}'.hex(":")
    rows_h2 = [
        http2_row(**{"frame.time_epoch": "5000.0", "tcp.stream": "58",
                     "http2.streamid": "1", "ip.src": "10.0.0.5", "ip.dst": "1.2.3.4",
                     "tcp.dstport": "443", "http2.headers.method": "POST",
                     "http2.headers.authority": "us-east-1.console.aws.amazon.com",
                     "http2.headers.path": "/api/prod/browserCreds",
                     "http2.header.name": "cookie|authorization",
                     "http2.header.value": "sid=abc|Bearer secret"}),
        http2_row(**{"frame.time_epoch": "5000.1", "tcp.stream": "58",
                     "http2.streamid": "1|0", "http2.headers.status": "200",
                     "http2.flags.end_stream": "True",
                     "http2.header.name": "content-type",
                     "http2.header.value": "application/json",
                     "http2.data.data": h2_body}),
    ]
    records_h2 = build_http2_records(_build_tsv(HTTP2_FIELDS, rows_h2))
    assert len(records_h2) == 1, f"expected 1 HTTP/2 record, got {len(records_h2)}"
    h2 = records_h2[0]
    assert h2["destination_domain"] == "us-east-1.console.aws.amazon.com", h2
    assert h2["method"] == "POST" and h2["path"] == "/api/prod/browserCreds", h2
    assert h2["status_code"] == 200 and h2["http_version"] == "2", h2
    assert "arn:aws:iam::123:user/x" in h2["response_body"], h2
    assert h2["request_headers"]["authorization"] == "[REDACTED]", h2["request_headers"]
    assert h2["request_headers"]["cookie"] == "sid=abc", h2["request_headers"]  # NOT redacted, per policy

    # HTTP/2 splits Cookie into one field PER COOKIE (RFC 7540 8.1.2.5) -
    # a real AWS console request carried 34 separate `cookie` fields.
    # dict(zip(...)) kept only the last crumb, which silently dropped the
    # aws-userInfo cookie carrying the full IAM identity. Repeated headers
    # must REJOIN, not overwrite.
    rows_h2_cookie = [
        http2_row(**{"frame.time_epoch": "6000.0", "tcp.stream": "9",
                     "http2.streamid": "1", "ip.dst": "1.2.3.4", "tcp.dstport": "443",
                     "http2.headers.method": "GET",
                     "http2.headers.authority": "console.aws.amazon.com",
                     "http2.headers.path": "/home",
                     "http2.header.name": "cookie|cookie|cookie",
                     "http2.header.value": "a=1|aws-userInfo=%7B%22arn%22%3A%22x%22%7D|z=9"}),
        http2_row(**{"frame.time_epoch": "6000.1", "tcp.stream": "9",
                     "http2.streamid": "1", "http2.headers.status": "200",
                     "http2.flags.end_stream": "True"}),
    ]
    rec_ck = build_http2_records(_build_tsv(HTTP2_FIELDS, rows_h2_cookie))[0]
    ck = rec_ck["request_headers"]["cookie"]
    assert ck == "a=1; aws-userInfo=%7B%22arn%22%3A%22x%22%7D; z=9", ck
    assert "aws-userInfo" in ck, "split-cookie rejoin lost the identity crumb"

    # REGRESSION GUARD: an UNANSWERED request must still produce a record.
    # Dropping these silently lost 28 real claude.ai
    # /api/organizations/<uuid>/chat_conversations calls from one segment,
    # because SSE completion responses stream past the segment boundary and
    # no :status arrives in the same file. The URL alone carries the org id.
    rows_h2_noresp = [
        http2_row(**{"frame.time_epoch": "8000.0", "tcp.stream": "5",
                     "http2.streamid": "1", "ip.dst": "1.2.3.4", "tcp.dstport": "443",
                     "http2.headers.method": "POST",
                     "http2.headers.authority": "claude.ai",
                     "http2.headers.path": "/api/organizations/abc-123/chat_conversations/x/completion"}),
    ]
    recs_nr = build_http2_records(_build_tsv(HTTP2_FIELDS, rows_h2_noresp))
    assert len(recs_nr) == 1, f"unanswered request was dropped: got {len(recs_nr)} records"
    assert recs_nr[0]["path"].startswith("/api/organizations/abc-123/"), recs_nr[0]
    assert recs_nr[0]["status_code"] is None, recs_nr[0]
    assert recs_nr[0]["destination_domain"] == "claude.ai", recs_nr[0]

    # REGRESSION GUARD: two responses coalesced into one row means ":status"
    # appears twice. The cookie-rejoin fix originally joined them into
    # "200, 401", which crashed int() and aborted an entire segment mid-run
    # (confirmed live 2026-08-30). Pseudo-headers must take first-wins, and
    # status parsing must never raise.
    rows_h2_dblstatus = [
        http2_row(**{"frame.time_epoch": "7000.0", "tcp.stream": "3",
                     "http2.streamid": "1", "ip.dst": "1.2.3.4", "tcp.dstport": "443",
                     "http2.headers.method": "GET",
                     "http2.headers.authority": "example.com",
                     "http2.headers.path": "/x"}),
        http2_row(**{"frame.time_epoch": "7000.1", "tcp.stream": "3",
                     "http2.streamid": "1", "http2.headers.status": "200",
                     "http2.flags.end_stream": "True",
                     "http2.header.name": ":status|:status",
                     "http2.header.value": "200|401"}),
    ]
    rec_ds = build_http2_records(_build_tsv(HTTP2_FIELDS, rows_h2_dblstatus))[0]
    assert rec_ds["response_headers"][":status"] == "200", rec_ds["response_headers"]
    assert rec_ds["status_code"] == 200, rec_ds
    # _as_int must swallow anything malformed rather than raising.
    assert _as_int("200, 401") is None and _as_int(None) is None and _as_int("200") == 200

    # HTTP/2 must dedupe pktmon's ~4x per-layer copies too.
    records_h2_dup = build_http2_records(_build_tsv(HTTP2_FIELDS, rows_h2 * 4))
    assert len(records_h2_dup) == 1, \
        f"HTTP/2 dedupe failed: got {len(records_h2_dup)} records from a 4x-duplicated exchange"

    # --- gzip auto-decompression + truncated gzip (EOFError, not OSError) ---
    import gzip as _gzip
    compressed = _gzip.compress(b'{"ok":true}')
    _, text = _decode_body(compressed.hex(":"))
    assert json.loads(text) == {"ok": True}
    truncated = compressed[:6].hex(":")
    _, trunc_text = _decode_body(truncated)
    assert "failed to decompress" in trunc_text, trunc_text

    # --- TLS-handshake-only records: SNI visible, content not. The
    # mcp-proxy.anthropic.com case confirmed live 2026-08-29. A hostname
    # that DID decrypt elsewhere must be skipped rather than duplicated. ---
    def hs_row(**kwargs):
        return [kwargs.get(f, "") for f in HANDSHAKE_FIELDS]

    rows_hs = [
        hs_row(**{"frame.time_epoch": "4000.0", "ip.dst": "5.6.7.8", "tcp.dstport": "443",
                  "tls.handshake.extensions_server_name": "mcp-proxy.anthropic.com",
                  "tls.handshake.version": "TLS 1.2"}),
        hs_row(**{"frame.time_epoch": "4000.1", "ip.dst": "1.2.3.4", "tcp.dstport": "443",
                  "tls.handshake.extensions_server_name": "example.com",
                  "tls.handshake.version": "TLS 1.2"}),
    ]
    raw_hs = _build_tsv(HANDSHAKE_FIELDS, rows_hs)
    # "example.com" decrypted fine in the HTTP fixture above, so it must NOT
    # be re-emitted here; only the undecryptable mcp-proxy one should be.
    hs_records = build_handshake_records(raw_hs, {"example.com"})
    assert len(hs_records) == 1, f"expected 1 handshake-only record, got {len(hs_records)}"
    h = hs_records[0]
    assert h["destination_domain"] == "mcp-proxy.anthropic.com", h
    assert h["tls_only"] is True, h
    assert h["method"] is None and h["response_body"] is None, h

    # --- completeness assertion -------------------------------------------
    # It must STAY QUIET when the run is clean and SHOUT when it is not.
    # A checker that cannot fail is worse than none: it manufactures
    # confidence. Both directions are asserted.
    STATS.clear()
    clean = [{"destination_domain": "example.com"} for _ in range(10)]
    assert report_completeness(clean, http3_emitted=10) == []

    STATS.clear()
    _stat("http3", "tshark_rows", 400)
    _stat("http3", "unique_rows", 100)
    _stat("http3", "pktmon_duplicate_rows", 300)
    _stat("http3", "requests", 50)
    _stat("http3", "responses", 50)
    _stat("http3", "orphan_responses", 24)      # 48% - the real historical rate
    broken = [{"destination_domain": None} for _ in range(47)] + \
             [{"destination_domain": "example.com"} for _ in range(53)]
    warns = report_completeness(broken, http3_emitted=100)
    assert len(warns) == 2, warns
    assert "orphaned-response rate" in warns[0]
    assert "no destination_domain" in warns[1]

    # EVERY builder must stamp parser_version - all four, not just the one
    # being worked on. Caught for real: the stamp was first added to
    # _finalize_http3_record alone, so a live run produced 8,480 stamped
    # records that were ALL HTTP/3, with zero HTTP/1.x, HTTP/2 or
    # handshake records carrying it. That silently makes the stamp useless
    # for exactly the records it cannot distinguish. Asserting per-builder
    # (rather than on one sample record) is what makes the omission
    # impossible to repeat when a fifth builder is added.
    STATS.clear()
    r3 = build_http3_records(_build_tsv(HTTP3_FIELDS, [[
        "1.0", "1", "0", "1", "10.0.0.1", "443",
        ":method|:authority|:path", "GET|ex.com|/a", ""]]))
    assert r3 and r3[0]["parser_version"] == PARSER_VERSION, ("http3", r3)

    r1 = build_records(_build_tsv(HTTP_FIELDS, [
        ["1.0", "5", "10.0.0.1", "1.2.3.4", "5555", "443", "ex.com", "0x0303",
         "", "", "", "", "", "", "", ""],
        ["1.1", "5", "10.0.0.1", "1.2.3.4", "5555", "443", "", "",
         "GET", "/a", "HTTP/1.1", "Host: ex.com\r\n", "ex.com", "", "", ""],
        ["1.2", "5", "1.2.3.4", "10.0.0.1", "443", "5555", "", "",
         "", "", "", "", "", "200", "HTTP/1.1 200 OK\r\n", ""]]))
    assert r1 and r1[0]["parser_version"] == PARSER_VERSION, ("http1", r1)

    r2 = build_http2_records(_build_tsv(HTTP2_FIELDS, [
        ["2.0", "9", "1", "10.0.0.1", "1.2.3.4", "443",
         "GET", "ex.com", "/a", "", "", "", "False", ""],
        ["2.1", "9", "1", "1.2.3.4", "10.0.0.1", "443",
         "", "", "", "200", "", "", "True", ""]]))
    assert r2 and r2[0]["parser_version"] == PARSER_VERSION, ("http2", r2)

    rh = build_handshake_records(_build_tsv(HANDSHAKE_FIELDS, [
        ["3.0", "1.2.3.4", "443", "", "never-decrypted.example", "0x0303"]]),
        decrypted_domains=set())
    assert rh and rh[0]["parser_version"] == PARSER_VERSION, ("handshake", rh)

    # TIMESTAMP SEMANTICS must be IDENTICAL across protocols: flow START.
    # The fixtures above each use a request frame time distinct from the
    # response frame time, so a builder that stamps the response instead
    # fails here. HTTP/1.x did exactly that until 2026-08-31, which put a
    # one-directional ~250 ms bias between HTTP/1.x and HTTP/2-3 records.
    for label, rec in (("http1", r1[0]), ("http2", r2[0]), ("http3", r3[0])):
        assert rec["timestamp"] == rec["request_start"], (
            label, rec["timestamp"], rec["request_start"], rec["response_end"])
        if rec["response_end"]:
            assert rec["timestamp"] != rec["response_end"], (
                label, "timestamp is stamping flow END, not START", rec)
    # r1's fixture: request at 1.1, response at 1.2 - so the two really are
    # distinguishable and the assertion above is not vacuously true.
    assert r1[0]["timestamp"] == "1.1" and r1[0]["response_end"] == "1.2", r1[0]

    # An ORPHANED HTTP/3 response (no paired request) must still get a domain
    # from the QUIC connection's SNI, instead of the None that made 6,662
    # historical records invisible to every analysis section.
    STATS.clear()
    orphan = build_http3_records(_build_tsv(HTTP3_FIELDS, [[
        "2.0", "7", "0", "1", "10.0.0.1", "443",
        ":status", "200", ""]]), sni_by_conn={"7": "recovered.example.com"})
    assert orphan and orphan[0]["destination_domain"] == "recovered.example.com", orphan
    assert orphan[0]["sni"] == "recovered.example.com"
    assert STATS["http3"]["orphan_responses"] == 1

    # ── Phase 0 data policy ──────────────────────────────────────────
    # These assertions are the thing standing between a metadata capture
    # and shipping live credentials to a data lake. Do not weaken them.

    # Bodies off by default; keys RETAINED so the record shape is stable
    # whether or not bodies were collected.
    rec = {"path": "/a", "request_headers": {},
           "request_body": "prompt text", "response_body": "reply text"}
    sanitize(rec)
    assert rec["request_body"] is None and rec["response_body"] is None, rec
    assert "request_body" in rec and "response_body" in rec, "keys kept, not deleted"
    assert rec["parser_version"] == PARSER_VERSION, rec
    assert rec["aws_account_id"] is None and rec["aws_identity"] is None, rec

    # --save-bodies opts back in.
    rec = {"path": "/a", "request_headers": {},
           "request_body": "kept", "response_body": None}
    sanitize(rec, save_bodies=True)
    assert rec["request_body"] == "kept", rec

    # Cookie: value redacted, KEY kept - check_metadata_only.py uses cookie
    # PRESENCE as evidence a host is an authenticated app rather than a CDN,
    # so deleting the key would silently degrade SaaS discovery.
    cookie = ("aws-userInfo=" + urllib.parse.quote(
        '{"arn":"arn:aws:iam::966293878453:user/sanjay-cli",'
        '"username":"sanjay-cli","keybase":"SIGNATURE-MATERIAL"}')
        + "; session=live-session-value")
    rec = {"path": "/x", "request_headers": {"Cookie": cookie},
           "request_body": None, "response_body": None}
    sanitize(rec)
    assert rec["request_headers"]["Cookie"] == REDACTED, rec["request_headers"]
    # ...and the identity was read out BEFORE the redaction destroyed it.
    assert rec["aws_account_id"] == "966293878453", rec
    assert rec["aws_identity"] == "sanjay-cli", rec
    # Signature material and the session cookie must not survive ANYWHERE.
    serialized = json.dumps(rec)
    assert "SIGNATURE-MATERIAL" not in serialized, rec
    assert "live-session-value" not in serialized, rec

    # Query-string values redacted, names kept.
    rec = {"path": "/api?SID=live-token&model=opus", "request_headers": {},
           "request_body": None, "response_body": None}
    sanitize(rec)
    assert rec["path"] == f"/api?SID={REDACTED}&model={REDACTED}", rec["path"]
    assert "live-token" not in rec["path"], rec["path"]

    # A VALUELESS token is the value - it must be redacted, not passed through.
    # Real leak found in the lake: 8 Windows Update cache-busters like
    # "?0df207e801c8dc54". Harmless content, but a bare session id looks
    # identical, so the rule was wrong even though the data was not sensitive.
    rec = {"path": "/x.cab?0df207e801c8dc54", "request_headers": {},
           "request_body": None, "response_body": None}
    sanitize(rec)
    assert rec["path"] == f"/x.cab?{REDACTED}", rec["path"]
    assert "0df207e8" not in rec["path"], "valueless token leaked"

    # Mixed: named pairs AND a bare token in one query.
    rec = {"path": "/a?tok=secret&bare123&k=v", "request_headers": {},
           "request_body": None, "response_body": None}
    sanitize(rec)
    assert "secret" not in rec["path"] and "bare123" not in rec["path"], rec["path"]

    # A path with no query is returned untouched - not re-encoded or reordered.
    rec = {"path": "/plain/path", "request_headers": {},
           "request_body": None, "response_body": None}
    sanitize(rec)
    assert rec["path"] == "/plain/path", rec["path"]

    # --keep-raw-params opts back out.
    rec = {"path": "/api?SID=live-token", "request_headers": {},
           "request_body": None, "response_body": None}
    sanitize(rec, redact_params=False)
    assert rec["path"] == "/api?SID=live-token", rec["path"]

    # A tls_only record has no headers and no path - must not crash.
    rec = {"path": None, "request_headers": None, "tls_only": True}
    sanitize(rec)
    assert rec["parser_version"] == PARSER_VERSION, rec
    assert rec["aws_account_id"] is None, rec

    # ── tshark resolution ────────────────────────────────────────────
    # Never a bare name: the companion runs as SYSTEM, and Wireshark's silent
    # installer does not put itself on the machine PATH.
    old = os.environ.get("PATRONAI_TSHARK")
    try:
        os.environ["PATRONAI_TSHARK"] = "/custom/path/to/tshark"
        assert resolve_tshark() == "/custom/path/to/tshark", "override must win"
        os.environ.pop("PATRONAI_TSHARK")
        resolved = resolve_tshark()
        assert resolved, "resolver returned nothing"
        # On this machine it must find a real binary, not fall through to the
        # bare name - falling through means the candidate list has gone stale.
        if Path(r"C:\Program Files\Wireshark\tshark.exe").exists():
            assert resolved != "tshark", "fell through to bare name despite an install being present"
    finally:
        if old is None:
            os.environ.pop("PATRONAI_TSHARK", None)
        else:
            os.environ["PATRONAI_TSHARK"] = old

    print("pktmon_to_jsonl self-test: PASS")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _selftest()
    else:
        main()
