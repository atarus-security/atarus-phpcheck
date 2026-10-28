# atarus-phpcheck

atarus-phpcheck is a detection and inventory tool for CVE-2026-109618 and CVE-2026-109619, the two PHP core remote code execution bugs published on 21 October 2026 (GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp).

It finds PHP installs, reads their version and the settings that matter for these bugs, and tells you whether each one is fixed, vulnerable, end of life with no fix coming, or unknown. It does not try to trigger either bug and it cannot prove that a host is safe.

`local` and `image` only touch this machine. `remote` and `fleet` touch other hosts, so they run only against hosts you placed in `--scope` and after you typed `yes` on the terminal. See [Scope and confirmation](#scope-and-confirmation-for-remote-and-fleet).

## What it checks

- The PHP version of every binary and module it can find, compared against the fixed releases: 8.5.12, 8.4.27, 8.3.36 and 8.2.35. PHP 8.1 and older are end of life and will not be fixed.
- Which SAPIs are present: CLI, FPM, CGI, LiteSpeed, Apache mod_php and the libphp embed library. The advisories rate mod_php as the most exposed.
- The settings that the advisories name: `memory_limit`, `post_max_size`, `upload_max_filesize`, `max_file_uploads`, `file_uploads`, `max_input_vars`, `max_input_nesting_level`, `max_multipart_body_parts`, `session.upload_progress.enabled` and, on 8.5, `fatal_error_backtraces`.
- FPM pool files: `pm`, `pm.max_requests` and any `php_admin_value` overrides of the settings above.
- For remote hosts: the `X-Powered-By` and `Server` banners, PHP session cookies, and whether common phpinfo paths answer a HEAD request.

## What it cannot prove

- A missing banner means nothing. Most production sites set `expose_php=Off` or strip headers at a proxy. Remote mode can only report what a server chooses to say.
- A banner can be stale, rewritten or spoofed, so remote results are never rated above medium confidence.
- Distribution packages (Debian, Ubuntu, RHEL and others) can carry a backported fix under an older upstream number. A version such as `8.2.28-1~deb12u1` is judged on `8.2.28`, flagged as a vendor build, and rated medium confidence. Check the vendor's security tracker before closing it out.
- Settings are read from the CLI, `php-fpm -i` and the Debian per-SAPI `php.ini` files. Per-vhost `php_value` lines, `.user.ini` files and `PHP_VALUE` parameters sent by a frontend are not read.
- A "fixed" status means the version number is at or above the fixed release. It says nothing about other bugs.

## Requirements

- Python 3.9 or newer, standard library only. The system `python3` on Kali, Debian, Ubuntu and macOS is enough. No pip, no venv.
- `local` and `fleet`: a POSIX `sh` on the target, which every Linux and macOS host has.
- `image`: the `docker` CLI and the images already present locally. The tool never pulls.
- `fleet`: OpenSSH with keys or an agent already set up for the hosts.
- `remote` and `fleet`: a terminal to type the confirmation on, or `--yes` together with `--scope` for scripted runs.

## Install

```
git clone https://github.com/atarus-security/atarus-phpcheck.git
cd atarus-phpcheck
python3 -m phpcheck --help
```

That is all that is needed. `python3 -m phpcheck` works from the repository directory without installing anything.

To get a `phpcheck` command on your PATH, optionally:

```
pipx install .
phpcheck --help
```

## Usage

Every mode takes `--json` for machine output, `--explain` to append the fix table, the end-of-life note and the mitigation checklist, and `--fail-on-unknown` to make unknown results fail the run.

### Scope and confirmation for remote and fleet

atarus-phpcheck follows one rule: it inspects this machine freely, and it contacts another host only when you placed that host in scope and confirmed it yourself.

`remote` and `fleet` need two things:

1. **A scope lock.** `--scope` takes a file (one entry per line, `#` comments allowed) or a comma-separated list. Four entry forms:

   | Entry | Covers |
   |---|---|
   | `app.example.com` | exactly that host; a single-label ssh alias such as `web-01` is allowed |
   | `*.example.com` | every name under `example.com`, at any depth, but not the apex |
   | `203.0.113.7` | that address |
   | `203.0.113.0/24` | every address in that network |

   A target is covered when its host name matches a host or domain entry, or when every address it resolves to falls inside a network entry. A target that is not covered is refused, not warned about: nothing is sent to it, it is listed as out of scope in the terminal, and it appears in the report (table, details and JSON `out_of_scope`) as `not checked: outside --scope`. An ssh alias that exists only in your `~/.ssh/config` does not resolve through DNS, so list it by name.

2. **A confirmation the software cannot give for you.** Before the first request or ssh session, the tool resolves every target and prints the mode, the exact scope, every target it would contact with its addresses, and every target outside the scope, then waits for you to type the word `yes` on the controlling terminal (`/dev/tty`). Anything else, end of file, or no terminal at all means nothing is sent: the report is still written, with every target marked `not checked`, and the exit code is 2.

   For non-interactive runs, `--yes` stands in for the typed word. It is accepted only together with `--scope`, it is printed at the start of the run, and it is recorded in the report (`confirmation`). No environment variable and no configuration file can stand in for the confirmation: the tool reads neither for these options. An automation or AI agent driving the CLI can pass flags, but it cannot answer `/dev/tty`, which is the point.

   `remote` or `fleet` without `--scope`, `--yes` without `--scope`, an unparseable `--scope`, and a run with neither a terminal nor `--yes` all stop with a usage error (exit 2) before anything runs.

The gate's listing goes to stderr, so `--json > report.json` keeps a clean document. What the gate shows:

```
Remote checks requested
  Scope: *.example.com
  Targets to check (1):
    https://www.example.com -> www.example.com (203.0.113.10)
  Out of scope, not checked (1):
    https://cdn.example.net -> cdn.example.net (198.51.100.4)

Type yes to send requests to the 1 target(s) listed above (scope: *.example.com):
```

### local

Checks the host you are on.

```
python3 -m phpcheck local
```

It runs a short read-only `sh` script that looks for `php`, `php8.x`, `php-fpm*`, `php-cgi*` and `lsphp*` on PATH and in the usual package locations (Debian, RHEL and Remi, cPanel, Plesk, Homebrew, Bitnami, the official Docker images), runs `-v` and either `php -r` with a small read-only probe or `-i` on each, reads the version string embedded in any `libphp*.so`, and greps the relevant lines out of FPM pool files. Run it as root if you want it to read pool files that are only readable by root.

Sample output, from a macOS workstation with no PHP installed:

```
atarus-phpcheck 0.2.0  mode=local  checks: CVE-2026-109618 (GHSA-w8hw-w9fx-j79w), CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)

TARGET     SAPI  VERSION  BRANCH  FIXED IN  STATUS        CONFIDENCE
localhost  -     -        -       -         no-php-found  none

[1] localhost  -
    note: no PHP binaries or modules found in the usual locations

Summary: 1 result across 1 target: 0 vulnerable, 0 end-of-life-unfixed, 0 fixed, 0 unknown, 1 with no PHP found
```

### image

Checks Docker images, for container fleets.

```
python3 -m phpcheck image php:8.2-cli php:8.1-cli
```

For each image it runs `php -v` in a container, then the same settings probe with `php -r`. If the image has `sh`, it then runs the inventory script inside a third container to find FPM binaries, pool files and `libphp*.so`. `--php-only` skips that third run.

Every container is started the same way:

```
docker run --rm --pull=never --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --entrypoint php <image> -v
```

- `--pull=never`: the image must already be present. The tool never pulls. A missing image is reported with the `docker pull` command to run yourself if you trust the image.
- `--network none`: nothing in the container can reach the network.
- `--read-only` with a small private `/tmp`: the image's filesystem cannot be written; the tmpfs is there for shells that need it for here-documents.
- `--cap-drop ALL` and `no-new-privileges`: no capabilities, and setuid binaries cannot regain any.
- `--user 65534:65534`: runs as nobody. If php cannot run as that user in a given image, the tool reruns once as the image's own default user and says so in the result's notes.

Sample output against the public images (pulled beforehand with `docker pull`) on 21 October 2026:

Sample output against the public images on 21 October 2026:

```
atarus-phpcheck 0.2.0  mode=image  checks: CVE-2026-109618 (GHSA-w8hw-w9fx-j79w), CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)

TARGET       SAPI   VERSION  BRANCH  FIXED IN    STATUS               CONFIDENCE
php:8.2-cli  cli    8.2.35   8.2     8.2.35      fixed                high
php:8.2-cli  cgi    8.2.35   8.2     8.2.35      fixed                high
php:8.2-cli  embed  8.2.35   8.2     8.2.35      fixed                medium
php:8.1-cli  cli    8.1.34   8.1     none (EOL)  end-of-life-unfixed  high
php:8.1-cli  cgi    8.1.34   8.1     none (EOL)  end-of-life-unfixed  high
php:8.1-cli  embed  8.1.34   8.1     none (EOL)  end-of-life-unfixed  medium

[1] php:8.2-cli  cli  php (entrypoint override)
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
[2] php:8.2-cli  cgi  /usr/local/bin/php-cgi
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
[3] php:8.2-cli  embed  /usr/local/lib/libphp.so
    note: version read from the string embedded in the module binary
    note: libphp shared library outside an Apache module directory (embed SAPI)
[4] php:8.1-cli  cli  php (entrypoint override)
    affected by: CVE-2026-109618, CVE-2026-109619
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - memory_limit=128M is finite; GHSA-w8hw-w9fx-j79w interim setting is -1 (partial, pair with a cgroup limit)
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
[5] php:8.1-cli  cgi  /usr/local/bin/php-cgi
    affected by: CVE-2026-109618, CVE-2026-109619
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - memory_limit=128M is finite; GHSA-w8hw-w9fx-j79w interim setting is -1 (partial, pair with a cgroup limit)
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
[6] php:8.1-cli  embed  /usr/local/lib/libphp.so
    affected by: CVE-2026-109618, CVE-2026-109619
    note: version read from the string embedded in the module binary
    note: libphp shared library outside an Apache module directory (embed SAPI)
    note: libphp embed library: GHSA-w8hw-w9fx-j79w rates FrankenPHP, which links it, likely susceptible.

Summary: 6 results across 2 targets: 0 vulnerable, 3 end-of-life-unfixed, 3 fixed, 0 unknown
End-of-life branches get no fix: move them to a supported branch.
Run with --explain for the mitigation checklist.
```

The `embed` rows are the `libphp.so` shared library that the official images ship. 8.1.34 is end of life upstream, so it is reported as unfixed even though it is the latest 8.1 release.

### remote

Passive checks of web hosts you own or are authorised to test. Needs `--scope` and the typed confirmation (or `--yes`).

```
python3 -m phpcheck remote https://www.example.com --scope www.example.com
python3 -m phpcheck remote hosts.txt --scope scope.txt --delay 2
python3 -m phpcheck remote hosts.txt --scope scope.txt --yes --json > report.json
```

Before the first request the tool resolves every target through your system resolver and runs the confirmation gate described above. Then, per in-scope target, it sends, one at a time with `--delay` seconds between requests (default 1.0):

1. `HEAD` and `GET` of the URL you gave. The GET body is read up to 64 KiB and discarded. Same-host redirects are followed up to three times, other hosts are not.
2. `HEAD` of a random path such as `/atarus-phpcheck-baseline-1a2b3c4d.php`, to see whether the site answers 200 for everything.
3. `HEAD` of `/phpinfo.php`, `/info.php`, `/php_info.php` and `/php-info.php`. A 200 is reported as a finding. The content of these pages is never fetched. `--no-paths` skips steps 2 and 3.

The User-Agent is `atarus-phpcheck/<version> (passive PHP version check)`, so the requests are easy to find in your logs. A bare host name is tried over https first, then http. `--insecure` skips certificate checks for internal hosts with self-signed certificates.

Sample output against a local test server on 127.0.0.1 that sends `X-Powered-By: PHP/8.3.14` and answers 200 on `/info.php`, run with `--scope 127.0.0.1` and `yes` typed at the prompt:

```
atarus-phpcheck 0.2.0  mode=remote  checks: CVE-2026-109618 (GHSA-w8hw-w9fx-j79w), CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)
Scope: 127.0.0.1
Confirmation: typed yes on the terminal

TARGET                 SAPI  VERSION  BRANCH  FIXED IN  STATUS      CONFIDENCE
http://127.0.0.1:8089  -     8.3.14   8.3     8.3.36    vulnerable  medium

[1] http://127.0.0.1:8089  -
    affected by: CVE-2026-109618, CVE-2026-109619
    evidence: 7 requests answered: HEAD / 200, GET / 200, HEAD /atarus-phpcheck-baseline-f10ae74e.php 404, HEAD /phpinfo.php 404, HEAD /info.php 200, HEAD /php_info.php 404, HEAD /php-info.php 404
    evidence: Server: Apache/2.4.62 (Debian) [HEAD / and 6 more]
    evidence: X-Powered-By: PHP/8.3.14 [HEAD / and 6 more]
    evidence: Set-Cookie PHPSESSID (PHP session cookie, no version) [HEAD / and 1 more]
    finding: HEAD /info.php returned 200: possible phpinfo page exposed (content not fetched); remove it
    note: version taken from a response banner; banners can be stale, rewritten or spoofed

Summary: 1 result across 1 target: 1 vulnerable, 0 end-of-life-unfixed, 0 fixed, 0 unknown
Remote mode: absence of a PHP banner proves nothing. Banners are often removed (expose_php=Off) or rewritten by proxies.
Patch to the fixed release for the branch: 8.5.12, 8.4.27, 8.3.36 or 8.2.35.
Run with --explain for the mitigation checklist.
```

### fleet

Runs the local checks over SSH and puts the results in one table. Needs `--scope` and the typed confirmation (or `--yes`).

```
python3 -m phpcheck fleet web-01 web-02 db-01 --scope web-01,web-02,db-01
python3 -m phpcheck fleet hosts.txt --scope hosts.txt --parallel 8 --json > fleet.json
```

The host list can double as the scope file when it lists exactly the hosts you are authorized to reach. Each in-scope host is reached with `ssh -o BatchMode=yes -o ConnectTimeout=10 -T -- <host> 'sh -s'` and the inventory script is sent on stdin. Nothing is copied to or left on the host. Your own `~/.ssh/config` decides users, keys, jump hosts and ports. The tool never asks for or handles passwords; BatchMode makes ssh fail instead of prompting. `--ssh` points at a different ssh binary.

Sample output. To keep the sample reproducible, `--ssh` pointed at a small wrapper that pipes the script into local containers: web-01 is `php:8.3.14-fpm`, web-02 is `php:8.2-fpm`, and db-01 does not resolve. All three were listed by name in `--scope`.

```
atarus-phpcheck 0.2.0  mode=fleet  checks: CVE-2026-109618 (GHSA-w8hw-w9fx-j79w), CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)
Scope: web-01, web-02, db-01
Confirmation: typed yes on the terminal

TARGET  SAPI  VERSION  BRANCH  FIXED IN  STATUS      CONFIDENCE
web-01  fpm   8.3.14   8.3     8.3.36    vulnerable  high
web-01  cli   8.3.14   8.3     8.3.36    vulnerable  high
web-02  fpm   8.2.35   8.2     8.2.35    fixed       high
web-02  cli   8.2.35   8.2     8.2.35    fixed       high
db-01   -     -        -       -         unknown     none

[1] web-01  fpm  /usr/local/sbin/php-fpm
    affected by: CVE-2026-109618, CVE-2026-109619
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - memory_limit=128M is finite; GHSA-w8hw-w9fx-j79w interim setting is -1 (partial, pair with a cgroup limit)
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
      - pool www: pm.max_requests=unset, default 0 (workers never recycled)
    note: PHP-FPM: GHSA-6wmf-4rv5-p3rp validated RCE on FPM; GHSA-w8hw-w9fx-j79w rates FPM susceptible by source analysis.
[2] web-01  cli  /usr/local/bin/php
    affected by: CVE-2026-109618, CVE-2026-109619
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - memory_limit=128M is finite; GHSA-w8hw-w9fx-j79w interim setting is -1 (partial, pair with a cgroup limit)
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
[3] web-02  fpm  /usr/local/sbin/php-fpm
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
      - pool www: pm.max_requests=unset, default 0 (workers never recycled)
[4] web-02  cli  /usr/local/bin/php
    settings: memory_limit=128M post_max_size=8M upload_max_filesize=2M max_file_uploads=20 file_uploads=On max_input_vars=1000 max_input_nesting_level=64 max_multipart_body_parts=-1 session.upload_progress.enabled=On
    in place: none
    gaps:
      - file_uploads=On (disable where uploads are unused)
      - session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)
[5] db-01  -
    error: ssh failed: ssh: Could not resolve hostname db-01
    note: no version observed

Summary: 5 results across 3 targets: 2 vulnerable, 0 end-of-life-unfixed, 2 fixed, 1 unknown
Patch to the fixed release for the branch: 8.5.12, 8.4.27, 8.3.36 or 8.2.35.
Run with --explain for the mitigation checklist.
```

### --explain

```
python3 -m phpcheck --explain
```

```
Advisories
  CVE-2026-109618  GHSA-w8hw-w9fx-j79w  RCE via OOM corruption (published 2026-10-21)
      https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  CVE-2026-109619  GHSA-6wmf-4rv5-p3rp  RCE via stale global state (published 2026-10-21)
      https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

Fixed releases
  PHP 8.5  fixed in 8.5.12   (CVE-2026-109618, CVE-2026-109619)
  PHP 8.4  fixed in 8.4.27   (CVE-2026-109618, CVE-2026-109619)
  PHP 8.3  fixed in 8.3.36   (CVE-2026-109618, CVE-2026-109619)
  PHP 8.2  fixed in 8.2.35   (CVE-2026-109618, CVE-2026-109619)
  PHP 8.1 and older: no fix (end of life)

End of life
  PHP 8.1 and older are end of life upstream and will not receive a fix for these CVEs. The only upstream remedy is to move to a supported branch.

Vendor packages
  Distribution packages (Debian, Ubuntu, RHEL and others) can carry a backported fix under an older upstream version number. A vendor-suffixed version is judged on its upstream number; confirm against the vendor's security tracker before closing it out.

Mitigation checklist
  1. Patch. Upgrade to a release that contains the fix (see the table above). Both advisories state that updating is the only complete mitigation.
  2. If you cannot patch yet, cap multipart and request body sizes at the web server or proxy (nginx client_max_body_size, Apache LimitRequestBody), and block multipart/form-data at the frontend for applications that do not use it.
  3. Disable file_uploads where the application does not accept uploads, and keep post_max_size, max_input_vars, max_input_nesting_level and max_multipart_body_parts conservative.
  4. Set session.upload_progress.enabled=0 administratively unless you need it (GHSA-6wmf-4rv5-p3rp, removes the demonstrated session producer and consumer).
  5. On PHP 8.5, set fatal_error_backtraces=0 administratively (GHSA-6wmf-4rv5-p3rp, removes the producer used in the confirmed RCE case).
  6. GHSA-w8hw-w9fx-j79w names memory_limit=-1, enforced administratively, as the primary interim setting for CVE-2026-109618. It is partial and removes PHP's own per-request memory cap, so pair it with a per-worker container or cgroup limit. Do not use RLIMIT_AS or RLIMIT_DATA, which trigger the vulnerable path.
  7. Set pm.max_requests on every FPM pool so workers are recycled (the advisory suggests pm.max_requests=1 where performance allows), and restart every PHP worker after any ini change so no old process keeps the old settings.
  8. Avoid per-request ini overrides (.htaccess php_value, PHP_VALUE or PHP_ADMIN_VALUE from the frontend) that raise warnings before request startup; prefer php.ini or pool config.
  9. Watch error logs for OOM bailouts ('Allowed memory size of N bytes exhausted'), fatal errors, 'Maximum execution time exceeded', and FPM children exiting unexpectedly. A clean log is not proof of safety.

Only patching closes these issues. Settings above reduce exposure until you can patch.
```

## Results

| Status | Meaning |
| --- | --- |
| `fixed` | The version is at or above the fixed release for its branch, or the branch is newer than every branch in the advisories. |
| `vulnerable` | The version is below the fixed release for a supported branch. Pre-releases (RC, beta, alpha, -dev) sort before the final release. |
| `end-of-life-unfixed` | The branch is 8.1 or older. No upstream fix exists. |
| `unknown` | No version was seen, the version could not be parsed, or only the branch is known for a supported branch. |
| `no-php-found` | `local` or `fleet` found no PHP on the host. |

Confidence is `high` for a plain upstream version read from the binary, `medium` for vendor builds, versions read from a module file and remote banners, `low` for remote vendor builds or when PHP is indicated without a version, and `none` when nothing was seen.

Exit codes: `0` when nothing is vulnerable or end of life, `1` when anything is (and, with `--fail-on-unknown`, when anything is unknown), `2` for usage errors and for a `remote` or `fleet` run whose confirmation gate did not open (nothing was sent).

JSON output (`--json`) has `tool`, `version`, `mode`, `generated_at`, `advisories`, `summary` and a `results` list. For `remote` and `fleet` it also has `scope` (the entries), `confirmation` (`typed yes on the terminal`, `--yes flag (no terminal confirmation)` or null), `refused` (the reason when nothing was sent, else null) and `out_of_scope` (target, host and resolved addresses of every refused target). Each result has `target`, `sapi`, `path`, `version`, `branch`, `fixed_in`, `status`, `confidence`, `affected_by`, `settings`, `mitigations_in_place`, `mitigation_gaps`, `evidence`, `findings`, `notes` and `error`.

## What it does not do

- It never sends a malformed, oversized, multipart or otherwise crafted request, and never tries to trigger either bug.
- It does not fetch the content of phpinfo pages, scan ports, brute-force paths or follow redirects to other hosts.
- It does not change any configuration, install anything on a target, or restart anything.
- It does not handle credentials. Fleet mode relies entirely on your existing SSH setup.
- It does not pull Docker images, and it gives containers no network.
- It does not phone home. The only network traffic is what you ask for: the remote requests and your ssh sessions, both only to hosts inside `--scope`.
- It does not let a target write to your terminal. Every string taken from a target (response headers, command output, error lines) has its control characters escaped (`\x1b`, `\u202e`) before it is printed or stored, so a hostile banner stays visible evidence and nothing more.

## What this tool sends over the network

| Mode | Destination | What is sent | When |
|---|---|---|---|
| local | nothing | nothing; runs a read-only `sh` script on this machine | every run |
| image | nothing | nothing; `docker run` with `--pull=never` and `--network none`, images must already be present | every run |
| remote | your system DNS resolver | one lookup per target, to check it against `--scope` | before the confirmation |
| remote | each in-scope target | one HEAD and one GET of the named URL (GET body read up to 64 KiB and discarded), same-host redirects followed up to three times; then one HEAD of a random baseline path and one HEAD each of `/phpinfo.php`, `/info.php`, `/php_info.php` and `/php-info.php` (skipped with `--no-paths`); `--delay` seconds apart; User-Agent `atarus-phpcheck/<version> (passive PHP version check)` | after the confirmation |
| fleet | your system DNS resolver | one lookup per host that is not listed by name, to check it against `--scope` | before the confirmation |
| fleet | each in-scope host | one ssh session (`ssh -o BatchMode=yes -o ConnectTimeout=N -T -- <host> 'sh -s'`) with the read-only inventory script on stdin; nothing is copied to the host | after the confirmation |

There are no update checks, no telemetry and no other destinations. A redirect to another host is never followed; it is recorded in the result's notes.

## Authorisation

Only run `remote` and `fleet` against hosts you own or are explicitly authorised to test, and put only those hosts in `--scope`. The requests are ordinary and few, but probing third-party systems without permission may still breach their terms or the law where you are. The scope lock and the typed confirmation are there to make the authorized set explicit and to stop a stale host list or an automation from reaching past it; they do not replace the authorization itself.

## Known issues

- The confirmation prompt shows each target's resolved addresses but not their owner (CNAME target, ASN). Check the printed addresses against your authorization before typing `yes`.
- An ssh alias that exists only in `~/.ssh/config` is matched by name, not by the address ssh will connect to. List such aliases by name, or by the network ssh resolves them into if you prefer a network entry.
- `image` mode falls back to the image's default user (often root) when php cannot run as uid 65534. The fallback is recorded in the result's notes; the other hardening flags still apply.

## Adding a CVE

The fix table is data. To track a new PHP core CVE, add one line to `ADVISORIES` in `phpcheck/advisories.py`:

```python
Advisory("CVE-YYYY-NNNNN", "GHSA-xxxx-xxxx-xxxx", "short title", "YYYY-MM-DD", {"8.2": "8.2.x", "8.3": "8.3.x", "8.4": "8.4.x", "8.5": "8.5.x"}),
```

Status, the fixed-in column, the summary and `--explain` all pick it up. Set `affects_older=False` if branches older than the ones listed were never affected. The versions in this release were checked against the php-src advisories with `gh api repos/php/php-src/security-advisories/<GHSA id>` on 21 October 2026.

## Tests

```
python3 -m unittest -v
```

The tests use only the standard library. Outbound network connections are blocked for the whole run, so remote, image and fleet behaviour is tested against recorded and mocked responses; the gate tests stand in for DNS resolution and the terminal. One test runs the real inventory script against a fake `php` binary in a temporary directory. `tests/test_scope.py` covers the scope entries, `safe_text` and the terminal helpers; the gate itself is tested in `tests/test_cli.py`. GitHub Actions runs the suite on Linux and macOS with Python 3.9, 3.11 and 3.13.

## Licence

MIT. See [LICENSE](LICENSE). Security reports: security@atarussecurity.com, see [SECURITY.md](SECURITY.md).

Atarus Offensive Security, info@atarussecurity.com
