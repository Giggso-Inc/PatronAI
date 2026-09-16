from __future__ import annotations

from pathlib import Path

from apikey_scanner.cli import main
from .conftest import commit_all, init_git_repo


def test_scan_then_report_end_to_end(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "app.py").write_text('key = "AKIAQ7ZP4XKM9LWD2FTR"\n', encoding="utf-8")
    commit_all(repo, "initial key")

    db_path = tmp_path / "store" / "findings.db"
    rc = main(["scan", "--root", str(repo), "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 finding" in out
    assert db_path.exists()
    assert (db_path.parent / ".gitignore").exists()

    rc = main(["report", "--db", str(db_path), "--format", "table"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "aws_access_key_id" in out
    assert "AKIAQ7ZP4XKM9LWD2FTR" not in out

    rc = main(["report", "--db", str(db_path), "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AKIAQ7ZP4XKM9LWD2FTR" not in out

    rc = main(["scans", "list", "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "repos=1" in out


def test_scan_with_no_roots_errors_cleanly(tmp_path: Path, capsys):
    rc = main(["scan", "--db", str(tmp_path / "x.db")])
    assert rc == 2


def test_patterns_list(capsys):
    rc = main(["patterns", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "aws_access_key_id" in out


def test_report_without_existing_db_errors_cleanly(tmp_path: Path, capsys):
    rc = main(["report", "--db", str(tmp_path / "nope.db")])
    assert rc == 2


def test_patterns_list_filtered_by_provider(capsys):
    rc = main(["patterns", "list", "--provider", "aws"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "aws_access_key_id" in out
    assert "github_pat_classic" not in out


def test_allowlist_add_list_remove_via_cli(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "app.py").write_text('key = "AKIAQ7ZP4XKM9LWD2FTR"\n', encoding="utf-8")
    commit_all(repo, "initial key")

    db_path = tmp_path / "findings.db"
    main(["scan", "--root", str(repo), "--db", str(db_path)])
    capsys.readouterr()

    from apikey_scanner.store.sqlite_store import SqliteStore

    with SqliteStore(db_path) as store:
        finding_id = store.query_findings()[0]["finding_id"]

    rc = main(["allowlist", "add", finding_id, "--reason", "test fixture", "--db", str(db_path)])
    assert rc == 0
    assert "allowlisted" in capsys.readouterr().out

    rc = main(["allowlist", "list", "--db", str(db_path)])
    assert rc == 0
    assert finding_id in capsys.readouterr().out

    rc = main(["allowlist", "remove", finding_id, "--db", str(db_path)])
    assert rc == 0
    assert "removed" in capsys.readouterr().out


def test_diff_command_via_cli(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "app.py").write_text('key = "AKIAQ7ZP4XKM9LWD2FTR"\n', encoding="utf-8")
    commit_all(repo, "initial key")

    db_path = tmp_path / "findings.db"
    main(["scan", "--root", str(repo), "--db", str(db_path)])
    capsys.readouterr()
    main(["scan", "--root", str(repo), "--db", str(db_path)])
    capsys.readouterr()

    rc = main(["diff", "--from", "1", "--to", "2", "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "persisting: 1" in out


def test_scan_with_track_rotation_and_hash_authors(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    init_git_repo(repo)
    (repo / "app.py").write_text('key = "AKIAQ7ZP4XKM9LWD2FTR"\n', encoding="utf-8")
    commit_all(repo, "initial key")

    db_path = tmp_path / "findings.db"
    rc = main(
        [
            "scan", "--root", str(repo), "--db", str(db_path),
            "--track-rotation", "--hash-authors",
        ]
    )
    assert rc == 0
    capsys.readouterr()

    from apikey_scanner.store.sqlite_store import SqliteStore

    with SqliteStore(db_path) as store:
        row = store.query_findings()[0]
    assert row["secret_fingerprint"] is not None
    assert row["author_name"] != "Tester"
    assert (db_path.parent / "salt").exists()
