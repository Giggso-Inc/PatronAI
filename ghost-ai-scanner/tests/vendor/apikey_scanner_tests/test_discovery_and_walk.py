from __future__ import annotations

from pathlib import Path

from apikey_scanner.config import ScannerConfig
from apikey_scanner.discovery import discover_all_repos, discover_repos
from apikey_scanner.walk import walk_repo_files
from .conftest import init_git_repo


def test_discover_repos_stops_at_git_boundary(tmp_path: Path):
    outer = tmp_path / "outer"
    init_git_repo(outer)
    nested = outer / "vendor" / "nested_repo"
    init_git_repo(nested)

    config = ScannerConfig()
    found = list(discover_repos(outer, config))
    assert found == [outer]  # never descends into the nested repo


def test_discover_repos_prunes_configured_dirs(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    skipped = root / "node_modules" / "some_pkg_repo"
    init_git_repo(skipped)

    config = ScannerConfig()
    found = list(discover_repos(root, config))
    assert found == []


def test_discover_all_repos_dedupes_across_roots(tmp_path: Path):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    config = ScannerConfig()
    config.roots = (str(tmp_path), str(repo))
    found = list(discover_all_repos(config))
    assert len(found) == 1


def test_walk_skips_binary_files(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02binarydata")
    config = ScannerConfig()
    found = {f.repo_relative_posix for f in walk_repo_files(tmp_path, config)}
    assert "app.py" in found
    assert "image.bin" not in found


def test_walk_skips_oversized_files(tmp_path: Path):
    (tmp_path / "huge.txt").write_bytes(b"a" * 10)
    config = ScannerConfig()
    config.max_file_size_bytes = 5
    found = {f.repo_relative_posix for f in walk_repo_files(tmp_path, config)}
    assert "huge.txt" not in found


def test_walk_marks_lockfiles(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    config = ScannerConfig()
    found = list(walk_repo_files(tmp_path, config))
    assert found[0].is_lockfile is True


def test_walk_skips_minified_by_suffix(tmp_path: Path):
    (tmp_path / "bundle.min.js").write_text("var x=1;", encoding="utf-8")
    config = ScannerConfig()
    found = {f.repo_relative_posix for f in walk_repo_files(tmp_path, config)}
    assert "bundle.min.js" not in found
