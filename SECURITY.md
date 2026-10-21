# Security Policy

## Supported versions

Only the latest release receives fixes.

| Version | Supported |
| ------- | --------- |
| latest  | yes       |
| older   | no        |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting instead: open the **Security** tab of this
repository and click **Report a vulnerability**. You will get a private
channel with the maintainer.

Useful details to include:

- script version (`./ndm_domain-health-check.sh --version`) and the output of
  `./ndm_domain-health-check.sh --requirements`;
- operating system;
- steps to reproduce, using a documentation domain (`example.com`) or one you
  own, never a third party's;
- the impact you expect (for example "command injection" or "wrong advice").

## What is in scope

- Unsafe handling of the domain name, command-line options, environment or
  configuration file (code execution, injection, writing outside the report
  directory).
- Active checks run in `--passive` mode (AXFR, obsolete-TLS test, connections
  to mail ports).
- Connections to non-public addresses (loopback, the LAN, other private ranges),
  whether reached through a redirect or through a name of the audited domain;
  redirects to non-HTTP(S) schemes.
- DNS data that a tool reads as an option or a command (for example a record
  value passed to `dig`), SPF trees or other answers that make the script run
  without end, unbounded responses, and servers that keep a probe waiting
  indefinitely.
- Findings that report a broken setup as correct, or advice in section 14
  that would make the domain or its mail unreachable.
- Data sent to services other than those listed in the README ("External
  services contacted").

## What is out of scope

- Content of the reports: they contain your domain's real data and are saved
  in plain text (`--output`); protecting them is up to you.
- Results that depend on third-party services (RDAP, WHOIS, crt.sh, RIPEstat,
  DNS blocklists) being unavailable or wrong.
- Active checks (AXFR, obsolete TLS, mail ports) run against domains you do not
  own: use `--passive`, as described in the README.

## Disclosure

This is a personal project maintained on a best-effort basis. Reports are
acknowledged as soon as reasonably possible and fixes are released before any
public disclosure.
