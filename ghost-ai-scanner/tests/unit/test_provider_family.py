# =============================================================
# FILE: tests/unit/test_provider_family.py
# VERSION: 1.0.0
# UPDATED: 2026-07-01
# OWNER: Giggso Inc
# PURPOSE: provider_family() — family collapse for glob-level allow/deny. Pure.
# =============================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from scoring.provider_family import is_family, provider_family


def test_three_segment_collapses_to_type_tool():
    assert provider_family("vdb:faiss:testcorpus.low.index") == ("vdb:faiss", "vdb:faiss:*")
    assert provider_family("mcp:claude_desktop:puppeteer") == ("mcp:claude_desktop", "mcp:claude_desktop:*")
    # many faiss instances share one family
    a = provider_family("vdb:faiss:testcorpus.mm.index")[1]
    b = provider_family("vdb:faiss:variables.index")[1]
    assert a == b == "vdb:faiss:*"


def test_two_segment_is_its_own_tool():
    assert provider_family("pip:openai") == ("pip:openai", "pip:openai")
    assert provider_family("tools:buildandbreak") == ("tools:buildandbreak", "tools:buildandbreak")


def test_domain_uses_registrable():
    assert provider_family("gemini.google.com") == ("google.com", "*.google.com")
    assert provider_family("claude.ai") == ("claude.ai", "*.claude.ai")


def test_bare_name_is_itself():
    assert provider_family("copilot") == ("copilot", "copilot")
    assert provider_family("") == ("", "")


def test_is_family_flag():
    assert is_family("vdb:faiss:testcorpus.low.index") is True     # covers more than itself
    assert is_family("gemini.google.com") is True                  # *.google.com
    assert is_family("pip:openai") is False                        # only itself
    assert is_family("copilot") is False
