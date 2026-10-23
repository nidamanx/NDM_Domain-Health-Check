# Changelog

All notable changes to NDM Domain Health Check are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-23

### Added

- `-A`, `--active`: active mode for one run (only for domains you own or manage). `-A` is the
  uppercase of `-a` (`--all`): with CAPS LOCK on, `-a EXAMPLE.COM` would arrive as
  `-A EXAMPLE.COM`, so an all-uppercase domain after `-A` is refused (exit code 2).
  `--active` together with `--passive` is also refused.
- `ACTIVE_DOMAINS` config setting: your own domains, checked in active mode without
  `--active`; every other domain stays passive. Exact names, read only from the config
  file (never from the environment).
- README: section "Passive and active mode", which explains what each mode does and why
  the active checks are kept separate.

### Changed

- **Passive mode is now the default.** A plain `./ndm_domain-health-check.sh example.com`
  no longer sends an AXFR request, tests obsolete TLS and weak ciphers, connects to the mail
  ports or probes the nameservers and the names found in the CT logs: these checks look like
  a scan to the owner of a domain that is not yours, and the tool should never run them by
  accident. **To keep the previous behaviour on your own domains**, list them in
  `ACTIVE_DOMAINS` in the config file, or add `--active`.
- The report header always states the mode, right under the domain name:
  `Mode: passive (…)` or `Mode: active (…)` (in yellow), followed by what it includes or
  leaves out.
- Certificate Transparency (section 12): when names still in DNS have only expired
  certificates, a note says they may be forgotten services and that the data is public
  (CT logs and DNS), so it is shown in every mode.
- Certificate Transparency (section 12): a link to crt.sh whenever names are missing from
  the list. `… and N more` now also counts the expired names gone from DNS, which are not
  listed; the link is also shown when crt.sh is temporarily unavailable ("Check them later
  at …"), with `CT_LOOKUP=off` and without python3.
- `--all`: each domain is checked in its own mode, and a line under the summary table lists
  the domains checked in active mode.
- `--passive` (`-p`) is still accepted: it forces passive mode, even for a domain listed in
  `ACTIVE_DOMAINS`.

### Fixed

- `--related-domains ''` (`-r ''`) now ignores `RELATED_DOMAINS` for one run also with
  `--output` and `--all`: the child processes reloaded the list from the config file.

## [1.2.0] - 2026-10-23

### Added

- `-d` as short form of `--output-dir`.
- `CITATION.cff`, so GitHub shows a **Cite this repository** button, and a request in the
  README to credit the author when the tool or its code is reused.
- Saved reports explain their comparison data: a few `#NDM_NOTE` lines precede the
  `#NDM_FACT` lines (both hidden on screen). Reports saved by earlier versions are still
  compared as before.

### Changed

- Certificate Transparency (section 12): names gone from DNS whose certificates have all
  expired, expired wildcards included, are counted in the header line instead of being
  listed one by one. CT logs are append-only, so these names stay public forever; names
  with a valid certificate, or still in DNS, are listed as before.
- `--help`: the informational options (`--requirements`, `--version`, `--help`) are grouped
  at the end.
- README: long option names in the descriptive text.

### Fixed

- `--help`: the report file name format now matches the real one,
  `<domain>_<YYYYMMDD>-<HHMMSS>.txt`.

## [1.1.0] - 2026-10-21

First public release. Earlier versions were used privately by the author and were not
published.

### Added

- Graded report in numbered sections, each stating the source of its data: registration
  (RDAP, WHOIS fallback), availability, registry delegation, authoritative DNS, DNSSEC,
  web and TLS, mail DNS (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI), mail servers,
  blocklists, IP ownership, CAA and Certificate Transparency.
- "How to fix" section with the most urgent steps first and values ready to copy, plus
  notes for changing registrar, DNS provider, hosting or mail server.
- Passive mode (`--passive`) for domains that are not yours.
- Plain-text reports (`--output`, `--output-dir`) and comparison with the last saved
  report of the domain (`--compare`).
- Summary table for several domains (`--all`) and recognition of your other domains
  (`--related-domains`).
- Optional configuration file (`KEY=value` lines, never executed).
- CI on GitHub Actions (ShellCheck, Python helpers compile, smoke tests) with monthly
  Dependabot updates.

[Unreleased]: https://github.com/nidamanx/NDM_Domain-Health-Check/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/nidamanx/NDM_Domain-Health-Check/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/nidamanx/NDM_Domain-Health-Check/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/nidamanx/NDM_Domain-Health-Check/releases/tag/v1.1.0
