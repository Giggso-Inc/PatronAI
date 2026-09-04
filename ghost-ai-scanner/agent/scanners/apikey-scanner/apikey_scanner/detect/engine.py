"""Single-pass per-line scan: regex catalog + gated entropy fallback.

HARD INVARIANT (PLAN.md section 1.1): every `Detection` this module
produces carries only line_number/column_start/match_length -- never the
matched text. A candidate string exists only as a local inside this
module's functions and is never returned, logged, or attached to any
object that outlives the call that inspected it.
"""

from __future__ import annotations

from apikey_scanner.catalog.loader import GENERIC_ENTROPY_PATTERN_ID, Catalog
from apikey_scanner.catalog.validators import VALIDATORS
from apikey_scanner.config import ScannerConfig
from apikey_scanner.detect import context, filters
from apikey_scanner.detect.entropy import meets_entropy_threshold
from apikey_scanner.models import Confidence, Detection, Detector
from apikey_scanner.secret_salt import fingerprint as _fingerprint


def _overlaps(detections: list[Detection], start: int, end: int) -> bool:
    for d in detections:
        d_end = d.column_start + d.match_length
        if start < d_end and d.column_start < end:
            return True
    return False


def scan_line(
    line: str,
    line_number: int,
    catalog: Catalog,
    config: ScannerConfig,
    *,
    is_lockfile: bool,
    rotation_salt: bytes | None = None,
) -> list[Detection]:
    detections: list[Detection] = []

    if len(line) > config.max_line_length:
        return detections

    for compiled in catalog.compiled:
        spec = compiled.spec
        if spec.id in config.disabled_pattern_ids:
            continue
        if is_lockfile and spec.confidence != Confidence.HIGH:
            continue

        for m in compiled.regex.finditer(line):
            try:
                candidate = m.group(spec.capture_group)
            except IndexError:
                continue
            if not candidate:
                continue
            if filters.should_suppress_structural_match(candidate):
                continue
            if spec.validate is not None and not VALIDATORS[spec.validate](candidate):
                continue

            start, end = m.span(spec.capture_group)
            fp = _fingerprint(rotation_salt, candidate) if rotation_salt is not None else None
            detections.append(
                Detection(
                    pattern_id=spec.id,
                    provider=spec.provider,
                    confidence=spec.confidence,
                    detector=Detector.REGEX,
                    line_number=line_number,
                    column_start=start,
                    match_length=end - start,
                    secret_fingerprint=fp,
                )
            )

    if config.enable_entropy and not is_lockfile:
        entropy_spec = catalog.specs.get(GENERIC_ENTROPY_PATTERN_ID)
        if entropy_spec is not None and entropy_spec.id not in config.disabled_pattern_ids:
            for candidate, start, end in context.find_context_candidates(line):
                if len(candidate) < config.min_candidate_length:
                    continue
                if filters.should_suppress_generic_match(candidate):
                    continue
                if _overlaps(detections, start, end):
                    continue  # a higher-confidence regex pattern already covers this span
                passes, entropy_bits = meets_entropy_threshold(
                    candidate,
                    min_entropy_hex=config.min_entropy_hex,
                    min_entropy_base64=config.min_entropy_base64,
                )
                if not passes:
                    continue
                fp = (
                    _fingerprint(rotation_salt, candidate)
                    if rotation_salt is not None
                    else None
                )
                detections.append(
                    Detection(
                        pattern_id=entropy_spec.id,
                        provider=entropy_spec.provider,
                        confidence=entropy_spec.confidence,
                        detector=Detector.ENTROPY,
                        line_number=line_number,
                        column_start=start,
                        match_length=end - start,
                        entropy_bits=entropy_bits,
                        secret_fingerprint=fp,
                    )
                )

    return detections


def scan_text(
    text: str,
    catalog: Catalog,
    config: ScannerConfig,
    *,
    is_lockfile: bool,
    rotation_salt: bytes | None = None,
) -> list[Detection]:
    detections: list[Detection] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        detections.extend(
            scan_line(
                line,
                line_number,
                catalog,
                config,
                is_lockfile=is_lockfile,
                rotation_salt=rotation_salt,
            )
        )
    return detections
