"""End-to-end orchestration. PLAN.md section 3.1 pipeline, exercised through
`run_scan` itself rather than any one module in isolation — this is the
piece the manual fixture-repo testing covered by hand but no unit test did."""

from __future__ import annotations

import json
import subprocess

from ai_sdk_scanner.catalog.loader import load_catalog
from ai_sdk_scanner.pipeline import run_scan


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _make_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "openai>=1.0,<2\nboto3==1.34.0\nrequests\nlangchain-community==0.2.1\n",
        encoding="utf-8",
    )
    (repo / "package.json").write_text(
        json.dumps({
            "dependencies": {"@anthropic-ai/sdk": "^0.20.0", "express": "^4.18.0"},
        }),
        encoding="utf-8",
    )
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def test_end_to_end_collects_every_dependency(tmp_path):
    repo = _make_repo(tmp_path)
    catalog = load_catalog()

    report = run_scan(repo, catalog)

    names = {r.dependency_name for r in report.records}
    # AI libraries...
    assert "openai" in names
    assert "langchain-community" in names
    assert "@anthropic-ai/sdk" in names
    # ...and everything else, which is the point of the default mode.
    assert "boto3" in names
    assert "requests" in names
    assert "express" in names

    assert report.commit_sha is not None
    assert report.is_dirty is False
    assert all(r.commit_sha == report.commit_sha for r in report.records)
    assert all(r.repo_id == report.repo_id for r in report.records)
    assert report.coverage.manifests_found == 2
    assert report.coverage.manifests_parsed == 2
    assert set(report.coverage.ecosystems_seen) == {"pypi", "npm"}


def test_generics_are_collected_but_never_flagged_as_ai(tmp_path):
    # The catalog's exclusion list (PLAN.md 5.4) still governs
    # CLASSIFICATION. boto3 and requests are now collected like any other
    # dependency, but must not be marked AI-related -- that was the whole
    # reason for excluding them.
    repo = _make_repo(tmp_path)
    report = run_scan(repo, load_catalog())
    by_name = {r.dependency_name: r for r in report.records}

    for generic in ("boto3", "requests", "express"):
        assert by_name[generic].is_ai_related is False
        assert by_name[generic].category.value == "unclassified"
        assert by_name[generic].match_rule == ""

    for ai_lib in ("openai", "@anthropic-ai/sdk"):
        assert by_name[ai_lib].is_ai_related is True
        assert by_name[ai_lib].category.value != "unclassified"
        assert by_name[ai_lib].match_rule


def test_ai_only_restores_filtered_behaviour(tmp_path):
    repo = _make_repo(tmp_path)
    report = run_scan(repo, load_catalog(), ai_only=True)
    names = {r.dependency_name for r in report.records}
    assert "openai" in names
    assert "boto3" not in names
    assert "express" not in names
    assert all(r.is_ai_related for r in report.records)
    assert report.is_dirty is False
    assert all(r.commit_sha == report.commit_sha for r in report.records)
    assert all(r.repo_id == report.repo_id for r in report.records)
    assert report.coverage.manifests_found == 2
    assert report.coverage.manifests_parsed == 2
    assert set(report.coverage.ecosystems_seen) == {"pypi", "npm"}


def test_every_record_has_a_unique_scan_timestamp_shared_across_the_scan(tmp_path):
    repo = _make_repo(tmp_path)
    catalog = load_catalog()
    report = run_scan(repo, catalog)
    timestamps = {r.scan_timestamp for r in report.records}
    assert len(timestamps) == 1
    assert timestamps == {report.scan_timestamp}


def test_dirty_file_marks_content_matches_commit_false(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "requirements.txt").write_text("openai\nanthropic\n", encoding="utf-8")

    catalog = load_catalog()
    report = run_scan(repo, catalog)

    assert report.is_dirty is True
    reqs_records = [r for r in report.records if r.file_path == "requirements.txt"]
    assert reqs_records
    assert all(r.content_matches_commit is False for r in reqs_records)


def test_setup_py_reported_as_unparsed_not_silently_skipped(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "setup.py").write_text("from setuptools import setup\n", encoding="utf-8")

    catalog = load_catalog()
    report = run_scan(repo, catalog)

    reasons = {u.reason for u in report.coverage.manifests_unparsed}
    assert "python_setup_py_unparsed" in reasons


def test_with_file_commits_populates_file_last_commit_sha(tmp_path):
    repo = _make_repo(tmp_path)
    catalog = load_catalog()
    report = run_scan(repo, catalog, with_file_commits=True)
    assert report.records
    assert all(r.file_last_commit_sha is not None for r in report.records)


def test_without_file_commits_leaves_field_none(tmp_path):
    repo = _make_repo(tmp_path)
    catalog = load_catalog()
    report = run_scan(repo, catalog, with_file_commits=False)
    assert all(r.file_last_commit_sha is None for r in report.records)


def test_non_git_directory_still_scans_successfully(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "requirements.txt").write_text("openai\n", encoding="utf-8")

    catalog = load_catalog()
    report = run_scan(plain, catalog)

    assert report.commit_sha is None
    assert report.repo_id == f"local:{plain.name}"
    assert len(report.records) == 1
    assert report.records[0].commit_sha is None


def test_explicit_repo_id_flows_through_to_every_record(tmp_path):
    repo = _make_repo(tmp_path)
    catalog = load_catalog()
    report = run_scan(repo, catalog, explicit_repo_id="my-org/my-repo")
    assert report.repo_id == "my-org/my-repo"
    assert all(r.repo_id == "my-org/my-repo" for r in report.records)
