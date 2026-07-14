# =============================================================
# FILE: src/scoring/provider_family.py
# VERSION: 1.0.0
# UPDATED: 2026-07-01
# OWNER: Giggso Inc
# PURPOSE: Collapse near-identical providers into a "family" so admins can
#          allow/deny a whole tool in one glob rule instead of managing
#          many instances. Pure (no I/O), unit-testable.
#
#          Provider keys are `type:tool:instance` for code/endpoint findings
#          and domains for network. The family is the tool; the family glob
#          is what a single allow/deny rule would use (the backend already
#          matches globs via fnmatch, so no schema change is needed).
#
#   vdb:faiss:testcorpus.low.index   -> ("vdb:faiss", "vdb:faiss:*")
#   mcp:claude_desktop:puppeteer     -> ("mcp:claude_desktop", "mcp:claude_desktop:*")
#   pip:openai                       -> ("pip:openai", "pip:openai")   # 2-seg = its own tool
#   gemini.google.com                -> ("google.com", "*.google.com") # registrable domain
#   copilot                          -> ("copilot", "copilot")
# =============================================================


def provider_family(provider: str) -> tuple:
    """Return (family_key, family_glob) for a provider string.

    family_key groups instances of the same tool; family_glob is the
    pattern a single family-level allow/deny rule would store."""
    p = (provider or "").strip().lower()
    if not p:
        return "", ""
    if ":" in p:
        parts = p.split(":")
        if len(parts) >= 3:                    # type:tool:instance -> family = type:tool
            fam = f"{parts[0]}:{parts[1]}"
            return fam, f"{fam}:*"
        return p, p                            # type:tool (2-seg) is its own tool
    if "." in p:                               # domain -> registrable (last two labels)
        labels = p.split(".")
        reg = ".".join(labels[-2:]) if len(labels) >= 2 else p
        return reg, f"*.{reg}"
    return p, p                                # bare name (process etc.)


def is_family(provider: str) -> bool:
    """True if the provider collapses to a family broader than itself
    (i.e. a family-level glob rule would cover more than this one instance)."""
    p = (provider or "").strip().lower()
    _key, glob = provider_family(p)
    return bool(glob) and glob != p
