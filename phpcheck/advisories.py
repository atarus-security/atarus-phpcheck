"""Advisory data.

Everything the checker knows about which PHP versions are fixed lives here.
To track a new PHP core CVE, add one Advisory line to ADVISORIES. Nothing
else in the package needs to change.

Versions below were checked against the php-src GitHub security advisories
(GET /repos/php/php-src/security-advisories/<GHSA id>) on 2026-10-21.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class Advisory:
    cve: str
    ghsa: str
    title: str
    published: str
    # Supported branch ("8.2") -> first fixed release on that branch ("8.2.35").
    fixed: Dict[str, str] = field(default_factory=dict)
    # True when branches older than the oldest listed branch are affected too.
    # Those branches get no fix: they are reported as end-of-life-unfixed when
    # they are below EOL_BELOW.
    affects_older: bool = True

    @property
    def url(self) -> str:
        return "https://github.com/php/php-src/security/advisories/" + self.ghsa

    def branches(self) -> Tuple[Tuple[int, int], ...]:
        return tuple(sorted(_branch_key(b) for b in self.fixed))

    def fixed_for(self, branch: Tuple[int, int]) -> Optional[str]:
        for name, version in self.fixed.items():
            if _branch_key(name) == branch:
                return version
        return None


def _branch_key(name: str) -> Tuple[int, int]:
    major, minor = name.split(".")[:2]
    return int(major), int(minor)


# One line per CVE.
ADVISORIES: Tuple[Advisory, ...] = (
    Advisory("CVE-2026-109618", "GHSA-w8hw-w9fx-j79w", "RCE via OOM corruption", "2026-10-21", {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}),
    Advisory("CVE-2026-109619", "GHSA-6wmf-4rv5-p3rp", "RCE via stale global state", "2026-10-21", {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}),
)

# Upstream PHP branches older than this are end of life and receive no fixes.
EOL_BELOW: Tuple[int, int] = (8, 2)

EOL_NOTE = (
    "PHP 8.1 and older are end of life upstream and will not receive a fix for "
    "these CVEs. The only upstream remedy is to move to a supported branch."
)

VENDOR_NOTE = (
    "Distribution packages (Debian, Ubuntu, RHEL and others) can carry a "
    "backported fix under an older upstream version number. A vendor-suffixed "
    "version is judged on its upstream number; confirm against the vendor's "
    "security tracker before closing it out."
)

SAPI_NOTES = {
    "apache2handler": "Apache mod_php: both advisories report confirmed remote code execution against this SAPI.",
    "fpm": "PHP-FPM: GHSA-6wmf-4rv5-p3rp validated RCE on FPM; GHSA-w8hw-w9fx-j79w rates FPM susceptible by source analysis.",
    "lsapi": "LiteSpeed LSAPI: the advisories rate it a conditional candidate.",
    "embed": "libphp embed library: GHSA-w8hw-w9fx-j79w rates FrankenPHP, which links it, likely susceptible.",
    "frankenphp": "FrankenPHP: GHSA-w8hw-w9fx-j79w rates it likely susceptible.",
}

# Printed by --explain. Order matters: patching is the only complete fix.
MITIGATION_CHECKLIST = (
    "Patch. Upgrade to a release that contains the fix (see the table above). "
    "Both advisories state that updating is the only complete mitigation.",
    "If you cannot patch yet, cap multipart and request body sizes at the web "
    "server or proxy (nginx client_max_body_size, Apache LimitRequestBody), "
    "and block multipart/form-data at the frontend for applications that do not use it.",
    "Disable file_uploads where the application does not accept uploads, and keep "
    "post_max_size, max_input_vars, max_input_nesting_level and max_multipart_body_parts conservative.",
    "Set session.upload_progress.enabled=0 administratively unless you need it "
    "(GHSA-6wmf-4rv5-p3rp, removes the demonstrated session producer and consumer).",
    "On PHP 8.5, set fatal_error_backtraces=0 administratively (GHSA-6wmf-4rv5-p3rp, "
    "removes the producer used in the confirmed RCE case).",
    "GHSA-w8hw-w9fx-j79w names memory_limit=-1, enforced administratively, as the primary "
    "interim setting for CVE-2026-109618. It is partial and removes PHP's own per-request "
    "memory cap, so pair it with a per-worker container or cgroup limit. Do not use "
    "RLIMIT_AS or RLIMIT_DATA, which trigger the vulnerable path.",
    "Set pm.max_requests on every FPM pool so workers are recycled (the advisory suggests "
    "pm.max_requests=1 where performance allows), and restart every PHP worker after any "
    "ini change so no old process keeps the old settings.",
    "Avoid per-request ini overrides (.htaccess php_value, PHP_VALUE or PHP_ADMIN_VALUE "
    "from the frontend) that raise warnings before request startup; prefer php.ini or pool config.",
    "Watch error logs for OOM bailouts ('Allowed memory size of N bytes exhausted'), "
    "fatal errors, 'Maximum execution time exceeded', and FPM children exiting unexpectedly. "
    "A clean log is not proof of safety.",
)
