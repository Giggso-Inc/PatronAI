"""Whole-system project discovery. Every test builds a synthetic tree
under tmp_path and points discovery at it — no test walks a real drive."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ai_sdk_scanner.catalog.loader import load_catalog
from ai_sdk_scanner.system_scan import discover_projects, run_system_scan


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "t@example.com")
    _git(path, "config", "user.name", "t")


def test_finds_git_project(tmp_path):
    proj = tmp_path / "myproj"
    _init_repo(proj)
    (proj / "requirements.txt").write_text("openai\n")

    projects, _stats = discover_projects([tmp_path])
    assert [Path(p.path).name for p in projects] == ["myproj"]
    assert projects[0].discovered_by == "git_repo"


def test_finds_manifest_only_project(tmp_path):
    proj = tmp_path / "plainproj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("openai\n")

    projects, _stats = discover_projects([tmp_path])
    assert [Path(p.path).name for p in projects] == ["plainproj"]
    assert projects[0].discovered_by == "manifest_only"


def test_does_not_descend_into_a_git_project(tmp_path):
    # A nested repo (submodule / vendored clone) is not reported separately.
    outer = tmp_path / "outer"
    _init_repo(outer)
    (outer / "requirements.txt").write_text("openai\n")
    inner = outer / "vendored" / "inner"
    _init_repo(inner)
    (inner / "requirements.txt").write_text("anthropic\n")

    projects, _stats = discover_projects([tmp_path])
    assert [Path(p.path).name for p in projects] == ["outer"]


def test_prunes_node_modules_and_site_packages(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "package.json").write_text("{}")
    site = tmp_path / "venv" / "Lib" / "site-packages" / "somelib"
    site.mkdir(parents=True)
    (site / "requirements.txt").write_text("openai\n")
    real = tmp_path / "realproj"
    real.mkdir()
    (real / "requirements.txt").write_text("openai\n")

    projects, _stats = discover_projects([tmp_path])
    assert [Path(p.path).name for p in projects] == ["realproj"]


def test_container_directory_is_never_a_project_root(tmp_path):
    # Regression test for the real bug found in live system scanning: a
    # stray package.json directly in a container directory (Documents,
    # Desktop, $HOME, ...) made discovery treat the whole container as one
    # project and stop descending, hiding every real project below it.
    documents = tmp_path / "Documents"
    documents.mkdir()
    (documents / "package.json").write_text("{}")  # the stray manifest
    real_a = documents / "project_a"
    real_a.mkdir()
    (real_a / "requirements.txt").write_text("openai\n")
    real_b = documents / "project_b"
    real_b.mkdir()
    (real_b / "requirements.txt").write_text("anthropic\n")

    projects, _stats = discover_projects([tmp_path])
    found = sorted(Path(p.path).name for p in projects)
    assert found == ["project_a", "project_b"]


def test_hidden_directories_are_pruned(tmp_path):
    hidden = tmp_path / ".cache" / "something"
    hidden.mkdir(parents=True)
    (hidden / "requirements.txt").write_text("openai\n")

    projects, _stats = discover_projects([tmp_path])
    assert projects == []


def test_max_projects_limit_stops_discovery(tmp_path):
    for i in range(5):
        p = tmp_path / f"proj_{i}"
        p.mkdir()
        (p / "requirements.txt").write_text("openai\n")

    projects, _stats = discover_projects([tmp_path], max_projects=2)
    assert len(projects) == 2


def test_max_depth_bounds_discovery(tmp_path):
    deep = tmp_path / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "requirements.txt").write_text("openai\n")

    projects, _stats = discover_projects([tmp_path], max_depth=1)
    assert projects == []


def test_run_system_scan_collects_every_dependency_in_every_project(tmp_path):
    proj_ai = tmp_path / "has_ai"
    proj_ai.mkdir()
    (proj_ai / "requirements.txt").write_text("openai>=1.0\nboto3\n")
    proj_plain = tmp_path / "no_ai"
    proj_plain.mkdir()
    (proj_plain / "requirements.txt").write_text("flask\nrequests\n")

    report = run_system_scan(load_catalog(), roots=[tmp_path])

    assert report.summary.projects_found == 2
    # BOTH projects are reported now: every dependency counts, not only AI.
    assert sorted(Path(p.project_root).name for p in report.projects) == ["has_ai", "no_ai"]
    names = {r.dependency_name for p in report.projects for r in p.records}
    assert names == {"openai", "boto3", "flask", "requests"}
    assert report.roots_scanned == (str(tmp_path),)


def test_system_summary_separates_ai_subtotals_from_totals(tmp_path):
    proj = tmp_path / "mixed"
    proj.mkdir()
    (proj / "requirements.txt").write_text("openai>=1.0\nboto3\nflask\n")

    report = run_system_scan(load_catalog(), roots=[tmp_path])
    s = report.summary

    assert s.total_references == 3
    assert s.ai_references == 1
    assert s.unique_dependencies == 3
    assert s.unique_ai_dependencies == 1
    assert s.projects_with_any_refs == 1
    assert s.projects_with_ai_refs == 1


def test_system_ai_only_filters_back_to_ai_matches(tmp_path):
    proj = tmp_path / "mixed"
    proj.mkdir()
    (proj / "requirements.txt").write_text("openai>=1.0\nboto3\nflask\n")

    report = run_system_scan(load_catalog(), roots=[tmp_path], ai_only=True)
    names = {r.dependency_name for p in report.projects for r in p.records}
    assert names == {"openai"}
    assert report.summary.total_references == 1
    assert report.summary.ai_references == 1


def test_project_with_no_parseable_dependencies_is_omitted_by_default(tmp_path):
    proj_empty = tmp_path / "empty_manifest"
    proj_empty.mkdir()
    (proj_empty / "requirements.txt").write_text("# only a comment\n")

    report = run_system_scan(load_catalog(), roots=[tmp_path])
    assert report.projects == ()
    assert report.summary.projects_found == 1

    with_all = run_system_scan(
        load_catalog(), roots=[tmp_path], only_with_matches=False
    )
    assert [Path(p.project_root).name for p in with_all.projects] == ["empty_manifest"]
    assert with_all.summary.total_references == 0


def test_every_record_carries_its_own_project_repo_id(tmp_path):
    for name in ("alpha", "beta"):
        p = tmp_path / name
        p.mkdir()
        (p / "requirements.txt").write_text("openai\n")

    report = run_system_scan(load_catalog(), roots=[tmp_path])
    by_project = {
        Path(p.project_root).name: {r.repo_id for r in p.records} for p in report.projects
    }
    assert by_project["alpha"] == {"local:alpha"}
    assert by_project["beta"] == {"local:beta"}


def test_project_root_is_recorded_on_each_report(tmp_path):
    proj = tmp_path / "myproj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("openai\n")

    report = run_system_scan(load_catalog(), roots=[tmp_path])
    assert report.projects[0].project_root == str(proj.resolve())
