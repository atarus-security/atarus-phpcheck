"""PHP version parsing, ordering and assessment against the advisory table."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .advisories import ADVISORIES, EOL_BELOW, Advisory

FIXED = "fixed"
VULNERABLE = "vulnerable"
EOL = "end-of-life-unfixed"
UNKNOWN = "unknown"

# Worst first. A version is reported with the worst status across advisories.
_STATUS_ORDER = (EOL, VULNERABLE, UNKNOWN, FIXED)
FAILING = (EOL, VULNERABLE)

_PRE_RANK = {"dev": 0, "alpha": 1, "beta": 2, "rc": 3}
_FINAL_RANK = 4

_VERSION_RE = re.compile(
    r"(?<![\w.])(?P<major>\d{1,2})\.(?P<minor>\d{1,2})(?:\.(?P<patch>\d{1,3}))?"
    r"(?:[-.]?(?P<pre>alpha|beta|RC|rc|dev)(?P<prenum>\d*))?"
    r"(?P<extra>[-+~][0-9A-Za-z.+~:-]*)?"
)


@dataclass(frozen=True)
class PhpVersion:
    raw: str
    major: int
    minor: int
    patch: Optional[int]
    pre: Optional[str] = None  # "dev", "alpha", "beta", "rc"
    prenum: int = 0
    extra: str = ""  # vendor suffix such as "-1~deb12u1"

    @property
    def branch(self) -> Tuple[int, int]:
        return self.major, self.minor

    @property
    def branch_str(self) -> str:
        return "%d.%d" % self.branch

    @property
    def upstream(self) -> str:
        """The version without any vendor suffix."""
        return self.raw[: len(self.raw) - len(self.extra)] if self.extra else self.raw

    def key(self) -> Tuple[int, int, int, int, int]:
        rank = _PRE_RANK[self.pre] if self.pre else _FINAL_RANK
        return (self.major, self.minor, self.patch or 0, rank, self.prenum)

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None

    @property
    def is_vendor_build(self) -> bool:
        return bool(self.extra)


def parse_version(text: Optional[str]) -> Optional[PhpVersion]:
    """Find the first PHP-looking version in text and parse it."""
    if not text:
        return None
    m = _VERSION_RE.search(text.strip())
    if not m:
        return None
    major = int(m.group("major"))
    if major < 4 or major > 20:
        return None
    pre = m.group("pre")
    prenum = m.group("prenum")
    raw_end = m.end()
    return PhpVersion(
        raw=text.strip()[m.start():raw_end],
        major=major,
        minor=int(m.group("minor")),
        patch=int(m.group("patch")) if m.group("patch") is not None else None,
        pre=pre.lower() if pre else None,
        prenum=int(prenum) if prenum else 0,
        extra=m.group("extra") or "",
    )


def compare(a: str, b: str) -> int:
    """Return -1, 0 or 1 comparing two PHP version strings by upstream order."""
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        raise ValueError("unparseable version: %r / %r" % (a, b))
    ka, kb = va.key(), vb.key()
    return (ka > kb) - (ka < kb)


def worst(statuses: Sequence[str]) -> str:
    for s in _STATUS_ORDER:
        if s in statuses:
            return s
    return UNKNOWN


@dataclass
class Assessment:
    status: str
    version: Optional[PhpVersion] = None
    fixed_in: Optional[str] = None
    affected_by: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def branch(self) -> Optional[str]:
        return self.version.branch_str if self.version else None


def assess(text: Optional[str], advisories: Sequence[Advisory] = ADVISORIES,
           eol_below: Tuple[int, int] = EOL_BELOW) -> Assessment:
    v = parse_version(text)
    if v is None:
        return Assessment(UNKNOWN, notes=["version not recognised" if text else "no version observed"])

    statuses: List[str] = []
    fixed_versions: List[str] = []
    affected: List[str] = []
    notes: List[str] = []
    for adv in advisories:
        branches = adv.branches()
        fixed = adv.fixed_for(v.branch)
        if fixed:
            fixed_versions.append(fixed)
            if v.patch is None:
                statuses.append(UNKNOWN)
            elif v.key() < parse_version(fixed).key():  # type: ignore[union-attr]
                statuses.append(VULNERABLE)
                affected.append(adv.cve)
            else:
                statuses.append(FIXED)
        elif branches and v.branch < branches[0]:
            if not adv.affects_older:
                statuses.append(FIXED)
            elif v.branch < eol_below:
                statuses.append(EOL)
                affected.append(adv.cve)
            else:
                statuses.append(UNKNOWN)
                notes.append("branch %s is missing from the %s fix table" % (v.branch_str, adv.cve))
        elif branches and v.branch > branches[-1]:
            statuses.append(FIXED)
            notes.append("branch %s is newer than every branch in the %s fix table; assumed to include the fix" % (v.branch_str, adv.cve))
        else:
            statuses.append(UNKNOWN)
            notes.append("branch %s is missing from the %s fix table" % (v.branch_str, adv.cve))

    status = worst(statuses)
    if status == EOL:
        fixed_in = "none (EOL)"
    elif fixed_versions:
        fixed_in = max(fixed_versions, key=lambda s: parse_version(s).key())  # type: ignore[union-attr]
    else:
        fixed_in = "n/a"

    if v.patch is None and status == UNKNOWN:
        notes.append("only the branch is visible, the patch level is needed to decide")
    if v.is_prerelease and status == VULNERABLE:
        notes.append("pre-release build (%s) of a version at or below the fix; pre-releases are ordered before the final release" % v.upstream)
    if v.is_vendor_build:
        notes.append("vendor build suffix %r: the vendor may have backported the fix, check its security tracker" % v.extra)

    return Assessment(status, v, fixed_in, sorted(set(affected)), notes)


def fix_table(advisories: Sequence[Advisory] = ADVISORIES) -> List[Tuple[str, str, List[str]]]:
    """Rows of (branch, first fixed release, CVEs) across all advisories."""
    rows = {}
    for adv in advisories:
        for branch, version in adv.fixed.items():
            cur = rows.setdefault(branch, [version, []])
            if parse_version(version).key() > parse_version(cur[0]).key():  # type: ignore[union-attr]
                cur[0] = version
            cur[1].append(adv.cve)
    out = []
    for branch in sorted(rows, key=lambda b: tuple(int(x) for x in b.split(".")), reverse=True):
        out.append((branch, rows[branch][0], rows[branch][1]))
    return out
