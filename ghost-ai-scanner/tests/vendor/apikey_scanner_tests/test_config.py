from __future__ import annotations

from pathlib import Path

from apikey_scanner.config import ScannerConfig, load_config


def test_load_config_defaults_when_no_path():
    cfg = load_config(None)
    assert cfg.roots == ()
    assert cfg.enable_entropy is True


def test_load_config_from_toml(tmp_path: Path):
    toml_path = tmp_path / "scanner.toml"
    toml_path.write_text(
        """
        roots = ["/a", "/b"]
        db_path = "custom.db"
        jobs = 4
        max_file_size_bytes = 1000
        max_line_length = 200
        min_entropy_base64 = 4.0
        min_entropy_hex = 2.5
        min_candidate_length = 10
        enable_entropy = false
        track_rotation = true
        hash_authors = true
        disabled_pattern_ids = ["aws_access_key_id"]
        extra_prune_dirs = ["my_vendor_dir"]
        per_repo_file_budget = 500
        """,
        encoding="utf-8",
    )
    cfg = load_config(toml_path)
    assert cfg.roots == ("/a", "/b")
    assert cfg.db_path == "custom.db"
    assert cfg.jobs == 4
    assert cfg.max_file_size_bytes == 1000
    assert cfg.max_line_length == 200
    assert cfg.min_entropy_base64 == 4.0
    assert cfg.min_entropy_hex == 2.5
    assert cfg.min_candidate_length == 10
    assert cfg.enable_entropy is False
    assert cfg.track_rotation is True
    assert cfg.hash_authors is True
    assert cfg.disabled_pattern_ids == ("aws_access_key_id",)
    assert "my_vendor_dir" in cfg.prune_dirs
    assert cfg.per_repo_file_budget == 500


def test_scanner_config_default_prune_dirs_include_node_modules():
    cfg = ScannerConfig()
    assert "node_modules" in cfg.prune_dirs
    assert ".git" in cfg.prune_dirs
