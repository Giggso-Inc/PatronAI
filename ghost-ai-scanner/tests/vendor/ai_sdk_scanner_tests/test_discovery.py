"""Manifest discovery. PLAN.md section 9: pruned directories must never be
descended into, not merely filtered out after the fact."""

from __future__ import annotations

import subprocess

import pytest

from ai_sdk_scanner.discovery import discover_manifests


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_finds_recognized_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai\n")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "README.md").write_text("not a manifest")

    manifests, _truncated = discover_manifests(tmp_path)
    kinds = {m.file_path: m.kind for m in manifests}
    assert kinds["requirements.txt"] == "python_requirements"
    assert kinds["package.json"] == "node_package_json"
    assert "README.md" not in kinds


def test_prunes_node_modules_directory(tmp_path):
    nm = tmp_path / "node_modules" / "some-package"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")

    manifests, _truncated = discover_manifests(tmp_path)
    assert len(manifests) == 1
    assert manifests[0].file_path == "package.json"


def test_prunes_venv_directory(tmp_path):
    venv_site = tmp_path / ".venv" / "lib" / "site-packages"
    venv_site.mkdir(parents=True)
    (venv_site / "requirements.txt").write_text("openai\n")
    (tmp_path / "requirements.txt").write_text("openai\n")

    manifests, _truncated = discover_manifests(tmp_path)
    assert [m.file_path for m in manifests] == ["requirements.txt"]


def test_requirements_dir_txt_files_are_recognized(tmp_path):
    req_dir = tmp_path / "requirements"
    req_dir.mkdir()
    (req_dir / "base.txt").write_text("openai\n")

    manifests, _truncated = discover_manifests(tmp_path)
    assert manifests[0].kind == "python_requirements"
    assert manifests[0].file_path == "requirements/base.txt"


def test_setup_py_is_classified_but_recognized(tmp_path):
    (tmp_path / "setup.py").write_text("from setuptools import setup\n")
    manifests, _truncated = discover_manifests(tmp_path)
    assert manifests[0].kind == "python_setup_py_unparsed"


@pytest.mark.parametrize("filename,expected_kind", [
    ("pom.xml", "java_maven"),
    ("build.gradle", "java_gradle"),
    ("build.gradle.kts", "java_gradle"),
    ("go.mod", "go_mod"),
    ("Cargo.toml", "rust_cargo"),
    ("packages.config", "dotnet_packages_config"),
    ("Directory.Packages.props", "dotnet_central_packages"),
    ("Gemfile", "ruby_gemfile"),
    ("composer.json", "php_composer"),
])
def test_new_ecosystem_manifests_are_classified(tmp_path, filename, expected_kind):
    (tmp_path / filename).write_text("placeholder\n", encoding="utf-8")
    manifests, _truncated = discover_manifests(tmp_path)
    assert manifests[0].kind == expected_kind


@pytest.mark.parametrize("filename", ["App.csproj", "App.fsproj", "App.vbproj"])
def test_dotnet_project_files_are_classified_by_extension(tmp_path, filename):
    (tmp_path / filename).write_text("placeholder\n", encoding="utf-8")
    manifests, _truncated = discover_manifests(tmp_path)
    assert manifests[0].kind == "dotnet_project"


def test_respects_gitignore(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("requirements-extra.txt\n")
    (tmp_path / "requirements.txt").write_text("openai\n")
    (tmp_path / "requirements-extra.txt").write_text("anthropic\n")

    manifests, _truncated = discover_manifests(tmp_path, is_git_repo=True, respect_gitignore=True)
    assert [m.file_path for m in manifests] == ["requirements.txt"]


def test_gitignore_check_is_order_independent(tmp_path):
    # Regression test: a Windows-only bug meant `git check-ignore --stdin`
    # only correctly matched the LAST path in a multi-path batch (see
    # discovery._gitignored_paths' docstring). Three candidates, ignored
    # file placed first, to catch a return to the old text=True behavior.
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("requirements-extra.txt\n")
    (tmp_path / "requirements-extra.txt").write_text("anthropic\n")
    (tmp_path / "requirements.txt").write_text("openai\n")
    (tmp_path / "package.json").write_text("{}")

    manifests, _truncated = discover_manifests(tmp_path, is_git_repo=True, respect_gitignore=True)
    assert {m.file_path for m in manifests} == {"requirements.txt", "package.json"}


def test_gitignore_ignored_without_respecting_it(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("requirements-extra.txt\n")
    (tmp_path / "requirements.txt").write_text("openai\n")
    (tmp_path / "requirements-extra.txt").write_text("anthropic\n")

    manifests, _truncated = discover_manifests(tmp_path, is_git_repo=True, respect_gitignore=False)
    assert {m.file_path for m in manifests} == {"requirements.txt", "requirements-extra.txt"}


def test_max_depth_limits_walk(tmp_path):
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "requirements.txt").write_text("openai\n")
    (tmp_path / "requirements.txt").write_text("openai\n")

    manifests, _truncated = discover_manifests(tmp_path, max_depth=1)
    assert [m.file_path for m in manifests] == ["requirements.txt"]


def test_max_files_budget_reports_truncation(tmp_path):
    # Regression test for the real pathological case found in live system
    # scanning: a project with a huge dataset directory. A truncated walk
    # must be flagged, never reported as a complete clean result.
    data = tmp_path / "data"
    data.mkdir()
    for i in range(60):
        (data / f"row_{i}.csv").write_text("x")
    (tmp_path / "requirements.txt").write_text("openai\n")

    _manifests, truncated = discover_manifests(tmp_path, max_files=10)
    assert truncated is True


def test_no_truncation_when_budget_not_hit(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai\n")
    manifests, truncated = discover_manifests(tmp_path, max_files=1000)
    assert truncated is False
    assert [m.file_path for m in manifests] == ["requirements.txt"]


def test_symlinks_are_not_followed(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "requirements.txt").write_text("openai\n")
    link = tmp_path / "link"
    try:
        link.symlink_to(real_dir, target_is_directory=True)
    except OSError:
        import pytest
        pytest.skip("symlink creation requires elevated privileges on this platform")

    manifests, _truncated = discover_manifests(tmp_path)
    assert [m.file_path for m in manifests] == ["real/requirements.txt"]
