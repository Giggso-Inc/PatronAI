from __future__ import annotations

from apikey_scanner.identity import build_anchor, compute_finding_id


def test_anchor_excises_only_the_match_span():
    line = 'aws_key = "AKIAQ7ZP4XKM9LWD2FTR"  # prod'
    start = line.index("AKIAQ7ZP4XKM9LWD2FTR")
    anchor = build_anchor(line, start, len("AKIAQ7ZP4XKM9LWD2FTR"))
    assert "AKIAQ7ZP4XKM9LWD2FTR" not in anchor
    assert "\x00" in anchor
    assert "aws_key" in anchor


def test_anchor_stable_under_reindentation():
    line_a = 'aws_key = "AKIAQ7ZP4XKM9LWD2FTR"'
    line_b = '    aws_key   =    "AKIAQ7ZP4XKM9LWD2FTR"   '
    anchor_a = build_anchor(line_a, line_a.index("AKIA"), 20)
    anchor_b = build_anchor(line_b, line_b.index("AKIA"), 20)
    assert anchor_a == anchor_b


def test_finding_id_stable_when_line_number_changes():
    # Same repo/file/pattern/anchor, only the surrounding file changed
    # (simulated by simply not passing line_number into the id at all).
    anchor = build_anchor('aws_key = "AKIAQ7ZP4XKM9LWD2FTR"', 11, 20)
    id_before = compute_finding_id("github.com/org/repo", "app.py", "aws_access_key_id", anchor, 0)
    id_after = compute_finding_id("github.com/org/repo", "app.py", "aws_access_key_id", anchor, 0)
    assert id_before == id_after


def test_finding_id_differs_across_repo_file_or_pattern():
    anchor = build_anchor('aws_key = "AKIAQ7ZP4XKM9LWD2FTR"', 11, 20)
    pid = "aws_access_key_id"
    base = compute_finding_id("github.com/org/repo", "app.py", pid, anchor, 0)
    other_repo = compute_finding_id("github.com/org/other", "app.py", pid, anchor, 0)
    other_file = compute_finding_id("github.com/org/repo", "other.py", pid, anchor, 0)
    other_pattern = compute_finding_id("github.com/org/repo", "app.py", "gcp_api_key", anchor, 0)
    assert base != other_repo
    assert base != other_file
    assert base != other_pattern


def test_ordinal_disambiguates_identical_anchors_on_same_line_shape():
    anchor = build_anchor('aws_key = "AKIAQ7ZP4XKM9LWD2FTR"', 11, 20)
    first = compute_finding_id("github.com/org/repo", "app.py", "aws_access_key_id", anchor, 0)
    second = compute_finding_id("github.com/org/repo", "app.py", "aws_access_key_id", anchor, 1)
    assert first != second


def test_finding_id_never_contains_the_secret_bytes():
    secret = "AKIAQ7ZP4XKM9LWD2FTR"
    anchor = build_anchor(f'aws_key = "{secret}"', 11, 20)
    finding_id = compute_finding_id("github.com/org/repo", "app.py", "aws_access_key_id", anchor, 0)
    assert secret not in finding_id
    assert secret not in anchor
