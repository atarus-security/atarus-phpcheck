"""The result record shared by every mode."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence

from .advisories import SAPI_NOTES
from .settings import Pool, assess_settings
from .versions import EOL, FAILING, FIXED, UNKNOWN, VULNERABLE, assess


NOT_FOUND = "no-php-found"


@dataclass
class Result:
    target: str
    mode: str
    sapi: str = "-"
    path: Optional[str] = None
    version: Optional[str] = None
    branch: Optional[str] = None
    fixed_in: Optional[str] = None
    status: str = UNKNOWN
    confidence: str = "none"
    affected_by: List[str] = field(default_factory=list)
    settings: Dict[str, str] = field(default_factory=dict)
    mitigations_in_place: List[str] = field(default_factory=list)
    mitigation_gaps: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def failing(self) -> bool:
        return self.status in FAILING

    def to_dict(self) -> dict:
        return asdict(self)


def build_result(target: str, mode: str, version_text: Optional[str], *, sapi: str = "-",
                 path: Optional[str] = None, settings: Optional[Dict[str, str]] = None,
                 pools: Sequence[Pool] = (), confidence: Optional[str] = None,
                 notes: Sequence[str] = ()) -> Result:
    a = assess(version_text)
    r = Result(target=target, mode=mode, sapi=sapi, path=path)
    r.version = a.version.raw if a.version else (version_text or None)
    r.branch = a.branch
    r.fixed_in = a.fixed_in
    r.status = a.status
    r.affected_by = a.affected_by
    r.notes.extend(notes)
    r.notes.extend(a.notes)
    if confidence is None:
        if a.version is None:
            confidence = "none"
        elif a.version.is_vendor_build or a.version.patch is None:
            confidence = "medium"
        else:
            confidence = "high"
    r.confidence = confidence
    if settings:
        r.settings = dict(settings)
    if settings or pools:
        r.mitigations_in_place, r.mitigation_gaps = assess_settings(r.settings, r.branch, pools, patched=r.status == FIXED)
    if r.status in (VULNERABLE, EOL) and sapi in SAPI_NOTES:
        r.notes.append(SAPI_NOTES[sapi])
    return r
