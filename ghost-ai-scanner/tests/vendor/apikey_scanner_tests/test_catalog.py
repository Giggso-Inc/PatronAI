from __future__ import annotations

import json

import pytest

from apikey_scanner.catalog.loader import GENERIC_ENTROPY_PATTERN_ID, load_catalog
from apikey_scanner.errors import CatalogError


def test_catalog_loads_and_has_entries(catalog):
    assert len(catalog.specs) >= 40
    assert GENERIC_ENTROPY_PATTERN_ID in catalog.specs


def test_all_pattern_ids_unique(catalog):
    ids = list(catalog.specs.keys())
    assert len(ids) == len(set(ids))


def test_every_non_entropy_pattern_has_compiled_regex(catalog):
    compiled_ids = {c.spec.id for c in catalog.compiled}
    for pattern_id in catalog.specs:
        if pattern_id == GENERIC_ENTROPY_PATTERN_ID:
            assert pattern_id not in compiled_ids
        else:
            assert pattern_id in compiled_ids


def test_capture_group_within_bounds(catalog):
    for compiled in catalog.compiled:
        assert compiled.spec.capture_group <= compiled.regex.groups


def test_rejects_duplicate_ids(tmp_path):
    bad = {
        "catalog_version": "1.0.0",
        "patterns": [
            {"id": "dup", "confidence": "high", "regex": "a", "capture_group": 0},
            {"id": "dup", "confidence": "high", "regex": "b", "capture_group": 0},
        ],
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(CatalogError, match="duplicate"):
        load_catalog(str(path))


def test_rejects_unknown_validator(tmp_path):
    bad = {
        "catalog_version": "1.0.0",
        "patterns": [
            {
                "id": "x",
                "confidence": "high",
                "regex": "a",
                "capture_group": 0,
                "validate": "not_a_real_validator",
            },
        ],
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(CatalogError, match="unknown validator"):
        load_catalog(str(path))


def test_rejects_capture_group_out_of_range(tmp_path):
    bad = {
        "catalog_version": "1.0.0",
        "patterns": [
            {"id": "x", "confidence": "high", "regex": "(a)", "capture_group": 5},
        ],
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(CatalogError, match="capture_group"):
        load_catalog(str(path))


def test_rejects_missing_regex_for_non_entropy_pattern(tmp_path):
    bad = {
        "catalog_version": "1.0.0",
        "patterns": [{"id": "x", "confidence": "high", "capture_group": 1}],
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(CatalogError, match="no regex"):
        load_catalog(str(path))
