# =============================================================
# FILE: src/matcher/outcomes.py
# VERSION: 1.1.0
# UPDATED: 2026-09-04
# PURPOSE: Defines the five possible match outcomes and the
#          verdict dict schema returned by engine.match().
#          Token anomaly and personal key resolution happen
#          in alerter.py post-match — not here.
# OWNER: Ravi Venugopal, Giggso Inc
# AUDIT LOG:
#   v1.0.0  2026-04-18  Initial.
#   v1.1.0  2026-09-04  Add GREYLIST outcome for three-tier list system.
# =============================================================


class Outcome:
    """
    Five outcomes. Every event gets exactly one.
    No event ever passes without a verdict.
    """
    SUPPRESS      = "SUPPRESS"       # authorized domain — no alert
    DOMAIN_ALERT  = "DOMAIN_ALERT"   # unauthorized domain match
    PORT_ALERT    = "PORT_ALERT"     # unauthorized port match (local AI server)
    GREYLIST      = "GREYLIST"       # greylist domain — allowed but logged + queued
    UNKNOWN       = "UNKNOWN"        # no match in either list — flag LOW


# Severity assigned per outcome when not overridden by CSV
OUTCOME_SEVERITY = {
    Outcome.SUPPRESS:     "CLEAN",
    Outcome.DOMAIN_ALERT: "HIGH",    # overridden by severity column in CSV
    Outcome.PORT_ALERT:   "MEDIUM",  # always MEDIUM — no external transfer confirmed
    Outcome.GREYLIST:     "LOW",     # monitored — not blocked
    Outcome.UNKNOWN:      "LOW",     # never silently pass
}


def make_verdict(
    outcome: str,
    provider: str = "",
    category: str = "",
    severity: str = "",
    matched_domain: str = "",
    matched_port: int = 0,
    notes: str = "",
) -> dict:
    """
    Build a verdict dict returned by engine.match().
    Merged into the flat event by ingestor.py before writing.
    """
    return {
        "outcome":        outcome,
        "provider":       provider,
        "category":       category,
        "severity":       severity or OUTCOME_SEVERITY.get(outcome, "LOW"),
        "matched_domain": matched_domain,
        "matched_port":   matched_port,
        "notes":          notes,
    }
