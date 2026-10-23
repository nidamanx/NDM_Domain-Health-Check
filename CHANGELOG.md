# Changelog

All notable changes to NDM Domain Health Check are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `-d` as short form of `--output-dir`.
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

[Unreleased]: https://github.com/nidamanx/NDM_Domain-Health-Check/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/nidamanx/NDM_Domain-Health-Check/releases/tag/v1.1.0
