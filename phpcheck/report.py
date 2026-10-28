"""Table, JSON and --explain output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from . import __version__
from .advisories import ADVISORIES, EOL_NOTE, MITIGATION_CHECKLIST, VENDOR_NOTE
from .model import NOT_FOUND, Result, RunInfo
from .remote import NO_BANNER_NOTE
from .scope import safe_text
from .settings import short_settings
from .versions import EOL, FIXED, UNKNOWN, VULNERABLE, fix_table

# Modes whose targets are other people's hosts: their reports carry the scope block.
SCOPED_MODES = ("remote", "fleet")

COLUMNS = (
    ("TARGET", "target"),
    ("SAPI", "sapi"),
    ("VERSION", "version"),
    ("BRANCH", "branch"),
    ("FIXED IN", "fixed_in"),
    ("STATUS", "status"),
    ("CONFIDENCE", "confidence"),
)


def summary(results: Sequence[Result]) -> Dict[str, int]:
    counts = {"checked": len(results), VULNERABLE: 0, EOL: 0, FIXED: 0, UNKNOWN: 0, NOT_FOUND: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def _cell(r: Result, attr: str) -> str:
    v = getattr(r, attr)
    return "-" if v in (None, "") else safe_text(v)


def render_table(results: Sequence[Result]) -> str:
    rows = [[h for h, _ in COLUMNS]] + [[_cell(r, a) for _, a in COLUMNS] for r in results]
    widths = [max(len(row[i]) for row in rows) for i in range(len(COLUMNS))]
    lines = []
    for row in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    return "\n".join(lines)


def render_details(results: Sequence[Result]) -> str:
    # Every value here may have come from a target. The modes already clean
    # what they collect; this is the last line of defence before the terminal.
    s = safe_text
    out: List[str] = []
    for i, r in enumerate(results, 1):
        head = "[%d] %s  %s" % (i, s(r.target), s(r.sapi))
        if r.path:
            head += "  " + s(r.path)
        out.append(head)
        if r.error:
            out.append("    error: " + s(r.error))
        if r.affected_by:
            out.append("    affected by: " + ", ".join(s(a) for a in r.affected_by))
        if r.settings:
            out.append("    settings: " + s(short_settings(r.settings)))
        if r.settings or r.mitigations_in_place or r.mitigation_gaps:
            for label, items in (("in place", r.mitigations_in_place), ("gaps", r.mitigation_gaps)):
                if not items:
                    out.append("    %s: none" % label)
                    continue
                out.append("    %s:" % label)
                out.extend("      - " + s(i) for i in items)
        for e in r.evidence:
            out.append("    evidence: " + s(e))
        for f in r.findings:
            out.append("    finding: " + s(f))
        for n in r.notes:
            out.append("    note: " + s(n))
    return "\n".join(out)


def render_run_info(run: Optional[RunInfo], mode: str) -> List[str]:
    """The scope block printed under the report header for remote and fleet runs."""
    if run is None or mode not in SCOPED_MODES:
        return []
    lines = ["Scope: %s" % (", ".join(safe_text(e) for e in run.scope) if run.scope else "none")]
    if run.refused:
        lines.append("Confirmation: not given (%s). Nothing was sent to any target." % safe_text(run.refused))
    else:
        lines.append("Confirmation: %s" % safe_text(run.confirmation or "none"))
    if run.out_of_scope:
        lines.append("Out of scope, not checked (%d):" % len(run.out_of_scope))
        for item in run.out_of_scope:
            ips = ", ".join(safe_text(ip) for ip in item.get("ips", [])) or "did not resolve"
            lines.append("  %s -> %s (%s)" % (safe_text(item.get("target")), safe_text(item.get("host")), ips))
    return lines


def render_text(results: Sequence[Result], mode: str, run: Optional[RunInfo] = None) -> str:
    ids = ", ".join("%s (%s)" % (a.cve, a.ghsa) for a in ADVISORIES)
    parts = ["atarus-phpcheck %s  mode=%s  checks: %s" % (__version__, mode, ids)]
    parts.extend(render_run_info(run, mode))
    parts.append("")
    if not results:
        parts.append("Nothing was checked.")
        return "\n".join(parts) + "\n"
    parts.append(render_table(results))
    parts.append("")
    parts.append(render_details(results))
    parts.append("")
    s = summary(results)
    targets = len({r.target for r in results})
    line = "Summary: %d result%s across %d target%s: %d vulnerable, %d end-of-life-unfixed, %d fixed, %d unknown" % (
        s["checked"], "" if s["checked"] == 1 else "s", targets, "" if targets == 1 else "s",
        s[VULNERABLE], s[EOL], s[FIXED], s[UNKNOWN])
    if s[NOT_FOUND]:
        line += ", %d with no PHP found" % s[NOT_FOUND]
    parts.append(line)
    if mode == "remote":
        parts.append(NO_BANNER_NOTE)
    if s[VULNERABLE]:
        fixes = [v for _, v, _ in fix_table()]
        parts.append("Patch to the fixed release for the branch: %s or %s." % (", ".join(fixes[:-1]), fixes[-1]))
    if s[EOL]:
        parts.append("End-of-life branches get no fix: move them to a supported branch.")
    if s[VULNERABLE] or s[EOL]:
        parts.append("Run with --explain for the mitigation checklist.")
    return "\n".join(parts) + "\n"


def explain_data() -> dict:
    return {
        "advisories": [
            {"cve": a.cve, "ghsa": a.ghsa, "title": a.title, "published": a.published,
             "url": a.url, "fixed": dict(a.fixed)} for a in ADVISORIES
        ],
        "fixed_in": [{"branch": b, "fixed_in": v, "cves": c} for b, v, c in fix_table()],
        "eol_note": EOL_NOTE,
        "vendor_note": VENDOR_NOTE,
        "mitigation_checklist": list(MITIGATION_CHECKLIST),
    }


def render_explain() -> str:
    lines = ["Advisories"]
    for a in ADVISORIES:
        lines.append("  %s  %s  %s (published %s)" % (a.cve, a.ghsa, a.title, a.published))
        lines.append("      %s" % a.url)
    lines += ["", "Fixed releases"]
    for branch, version, cves in fix_table():
        lines.append("  PHP %-4s fixed in %-8s (%s)" % (branch, version, ", ".join(cves)))
    lines.append("  PHP 8.1 and older: no fix (end of life)")
    lines += ["", "End of life", "  " + EOL_NOTE, "", "Vendor packages", "  " + VENDOR_NOTE, "", "Mitigation checklist"]
    for i, item in enumerate(MITIGATION_CHECKLIST, 1):
        lines.append("  %d. %s" % (i, item))
    lines += ["", "Only patching closes these issues. Settings above reduce exposure until you can patch."]
    return "\n".join(lines) + "\n"


def render_json(results: Sequence[Result], mode: str, include_explain: bool = False,
                now: Optional[datetime] = None, run: Optional[RunInfo] = None) -> str:
    """JSON output. json.dumps escapes every control character (\\u001b and so
    on) and every non-ASCII character, so the document itself is safe to print;
    the values inside were already cleaned by safe_text when collected."""
    doc = {
        "tool": "atarus-phpcheck",
        "version": __version__,
        "mode": mode,
        "generated_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "advisories": [{"cve": a.cve, "ghsa": a.ghsa} for a in ADVISORIES],
    }
    if mode in SCOPED_MODES:
        doc["scope"] = list(run.scope) if run and run.scope else None
        doc["confirmation"] = run.confirmation if run else None
        doc["refused"] = run.refused if run else None
        doc["out_of_scope"] = list(run.out_of_scope) if run else []
    doc["summary"] = summary(results)
    doc["results"] = [r.to_dict() for r in results]
    if mode == "remote":
        doc["note"] = NO_BANNER_NOTE
    if include_explain:
        doc["explain"] = explain_data()
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"
