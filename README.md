# NDM Domain Health Check

**English** · [Italiano](README.it.md)

[![License: AGPL v3+](https://img.shields.io/badge/License-AGPL_v3%2B-blue.svg)](LICENSE)
![Version](https://img.shields.io/badge/version-1.1.0-informational)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25)

**NDM Domain Health Check** checks a domain's registration, DNS, DNSSEC, web/TLS and mail
setup (SPF, DKIM, DMARC, mail servers, blocklists, IP ownership) and grades every
finding, in a single colored report that tells you where each value comes from.

It is one Bash script with no extra libraries: it relies on `dig` and, when available,
on standard tools such as `python3` (standard library only), `delv`, `openssl` and `curl`.

## Background

I have been a system administrator since 1993. Checking a domain has always meant the
same routine: a few `dig` queries, a look at the certificate, a test of the mail server.
The routine grew with the internet itself: SPF, DKIM, DMARC, DNSSEC, Certificate
Transparency and MTA-STS each brought new things to check, and I added them to a script
whenever my work needed them. NDM Domain Health Check is that script, largely rewritten
and documented for public release; 1.1.0 is its first public version.

---

## Contents

- [What it checks](#what-it-checks)
  - [How to fix](#how-to-fix)
- [Result levels](#result-levels)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Windows (WSL)](#windows-wsl)
- [Usage](#usage)
- [Configuration](#configuration)
- [Saving reports](#saving-reports)
- [Sample output](#sample-output)
- [Delicate operations](#delicate-operations)
- [Responsible use and passive mode](#responsible-use-and-passive-mode)
- [External services contacted](#external-services-contacted)
- [Exit codes](#exit-codes)
- [Project layout](#project-layout)
- [Versioning](#versioning)
- [License and disclaimer](#license-and-disclaimer)

---

## What it checks

The report is split into numbered sections; each one states its **source** (registry,
authoritative nameservers, public resolver, web or mail server, external service).

| # | Section | Main checks |
|---|---------|-------------|
| 1 | Registration | Registrar, registrant (when published), creation, expiry with days left, status and transfer lock (via RDAP, falling back to WHOIS) |
| 2 | Availability | Ping, website online with HTTP code and response time, mail service answering |
| 3 | Registry (delegation) | Nameservers and DS records as published by the TLD registry itself, glue records, expiry of the domains that host the nameservers |
| 4 | Authoritative DNS | SOA serial consistency on every nameserver, nameservers in the zone vs. at the registry, glue records, DNS over TCP, nameserver diversity, SOA timers, wildcard and TTLs, zone transfer (AXFR) refused, DNSKEY; open recursion and software version of the nameservers *(own domains only)* |
| 5 | DNSSEC | Every DS matched against the published keys (catches wrong algorithm or digest), NSEC/NSEC3 zone walking, signature lifetime, algorithms in use, CDS/CDNSKEY, NSEC3 parameters, full validation |
| 6 | Web & TLS | A/AAAA, HTTP→HTTPS redirect, HSTS, security headers, TLS version, certificate issuer, names and expiry, certificates of `www`/`mail`/`webmail`, HTTP version, cookie flags, `security.txt`, software versions in headers, HSTS preload, certificate key, signature, lifetime and chain, obsolete TLS 1.0/1.1 and weak cipher suites *(own domains only)* |
| 7 | Mail (DNS) | MX, SPF fully expanded (every `include` down to the networks, optional labels for your providers, exact DNS lookup count), senders authorized by SPF and their consistency with the domain's hosts, DMARC (subdomain policy, `pct`, alignment, report addresses at other domains that do not authorize them), DKIM (key size, test mode, revoked keys), MTA-STS, TLS-RPT, BIMI |
| 8 | Mail servers | Ports 25, 465, 587, 993, 995, 143, 110: STARTTLS / TLS, certificate, login offered before encryption, plaintext logins, SMTP banner and `VRFY`/`EXPN`, TLSA records against the certificate shown *(own domains only)* |
| 9 | Blocklists | Mail-sending IPs on common DNSBLs (Spamhaus PBL told apart from real listings), IPv6 where the list supports it, and the domain name itself on domain blocklists |
| 10 | IP addresses | Owner, network, ASN and abuse contact (RDAP via the IANA bootstrap, RIPEstat); reverse DNS present, forward-confirmed, generic or provider-owned |
| 11 | CAA | Which certificate authorities may issue for the domain |
| 12 | Certificate Transparency | Every name that ever had a certificate (crt.sh), whether it is still valid and still in DNS; CNAMEs that point to a target that does not exist (subdomain takeover risk); *own domains only:* HTTPS of every live name, CNAMEs to services that report the site as unclaimed |
| 13 | Provider change notes | What to do, for *this* domain's setup, when changing registrar, DNS provider, hosting or mail server, and how to turn DNSSEC or MTA-STS off safely (see [Delicate operations](#delicate-operations)) |
| 14 | How to fix | Practical steps for the findings above, most urgent first, with the values ready to copy (see below) |
| 15 | Changes | With `--output` or `--compare`: what changed since the last saved report (nameservers, DS, MX, SPF, DMARC, DKIM, certificates…) |

A final **summary** lists errors, warnings, items to check and possible improvements.

**IPv6:** AAAA records are checked next to A records everywhere: website, MX hosts, mail host,
SPF (`ip6:` and the IPv6 length of `a`/`mx`, e.g. `a:host/24//64`), reverse DNS and owner/ASN
of each address. Blocklists are queried over IPv6 only on Spamhaus ZEN and on the zones marked
`zone:level:6` in `DNSBLS`; the others are reported as not covering IPv6. Connections to web
and mail servers use the IPv6 of the machine running the script, if it has any.

### How to fix

Sections 1–12 stay compact: they only diagnose. Section 14 collects what to do, numbered
from the most urgent (errors, then warnings, items to check, improvements), and computes
the values for *this* domain wherever it can:

- **DNSSEC**: when the zone is signed but the registry has no DS, the parameters to enter
  in the registrar's panel (key tag, algorithm, digest type, digest), the complete DS
  record and, for panels that ask for it, the DNSKEY; which DS to remove when one is stale
  or when the zone is no longer signed;
- **mail**: the SPF, DMARC (with a step-by-step path from `p=none` to enforcement),
  MTA-STS policy file (built from the MX hosts) and TLS-RPT records to publish;
- **web**: HTTP→HTTPS redirect, HSTS and security headers for Apache and nginx;
- **servers**: TLS versions, encryption and plaintext logins for Postfix, Dovecot and Exim;
- **reverse DNS, CAA and blocklists**: the PTR to ask for, the CAA record for the CA of
  the current certificate, the removal page of each blocklist.

Use `--brief` to skip sections 13 and 14 when only the diagnosis is needed.

## Result levels

| Symbol | Level | Meaning |
|:------:|-------|---------|
| ✔ | OK | Correct |
| ↑ | Improvable | Works, but could be improved |
| ◆ | To check | Cannot be judged automatically: a person must confirm it is intended |
| ⚠ | Warning | Works, but is risky or needs attention soon |
| ✘ | Error | Broken or insecure |
| ℹ | Info | Neutral information |

The "to check" level exists for findings such as an IP address authorized in SPF that
matches no host of the domain: it may be a legitimate external service or a forgotten
server, and only you can tell.

## Requirements

| Tool | Needed for | |
|------|------------|---|
| `dig` | All DNS queries | **required** |
| `python3` | Registration, TLS and mail probes, SPF analysis, IP data, CT logs (standard library only) | optional |
| `delv` | Full DNSSEC validation | optional |
| `openssl` | Certificate details | optional |
| `curl` | Web checks, MTA-STS policy | optional |
| `ping` | Availability | optional |

Missing optional tools only skip the related checks; the report says which ones.
Run `./ndm_domain-health-check.sh --requirements` to see what is missing and the exact install
command for your system:

| System | Command |
|--------|---------|
| Debian / Ubuntu | `sudo apt install dnsutils python3 openssl curl iputils-ping` |
| Fedora / RHEL 8+ | `sudo dnf install bind-utils python3 openssl curl iputils` |
| CentOS / RHEL 7 | `sudo yum install bind-utils python3 openssl curl iputils` |
| openSUSE | `sudo zypper install bind-utils python3 openssl curl iputils` |
| Arch / Manjaro | `sudo pacman -S bind python openssl curl iputils` |
| Alpine | `sudo apk add bind-tools python3 openssl curl iputils` |
| macOS (Homebrew) | `brew install bind python openssl curl` |
| Windows | Run it in WSL: see [Windows (WSL)](#windows-wsl) |

## Installation

```bash
git clone https://github.com/nidamanx/NDM_Domain-Health-Check.git
cd NDM_Domain-Health-Check
chmod +x ndm_domain-health-check.sh
./ndm_domain-health-check.sh --requirements      # check the needed tools
```

Optional: make it available everywhere through a symbolic link. The script still finds
its configuration file and `reports/` directory next to its real location.

```bash
ln -s "$PWD/ndm_domain-health-check.sh" ~/.local/bin/ndm_domain-health-check
```

### Windows (WSL)

The script needs a Linux or macOS shell. On Windows 10 and 11 run it inside **WSL**
(Windows Subsystem for Linux), which provides a real Ubuntu environment. Git Bash,
MSYS2 and Cygwin are not supported.

1. Open **PowerShell as administrator**, install WSL (Ubuntu by default) and restart
   Windows when asked:

   ```powershell
   wsl --install
   ```

2. Open **Ubuntu** from the Start menu, create your Linux user when asked, then install
   the tools and the script inside your Linux home directory:

   ```bash
   sudo apt update
   sudo apt install git dnsutils python3 openssl curl iputils-ping
   cd ~
   git clone https://github.com/nidamanx/NDM_Domain-Health-Check.git
   cd NDM_Domain-Health-Check
   ./ndm_domain-health-check.sh --requirements
   ```

Notes for Windows:

- Keep the folder in the Linux home (`~`), not under `/mnt/c/...`: on Windows drives the
  executable permission may be lost and file access is slower.
- Clone from inside WSL. The repository's `.gitattributes` keeps Linux line endings even
  if you clone with Git for Windows: Windows line endings (CRLF) would break the script
  with errors like `/usr/bin/env: 'bash\r': No such file or directory`.
- To open the saved reports in Windows Explorer, run `explorer.exe reports` from the
  script folder.

## Usage

```
./ndm_domain-health-check.sh [options] [domain]
```

Without a domain, the script asks for it. Give the registered domain (`example.com`),
not a subdomain: `www`, the MX and the other names are checked automatically.

| Option | Description |
|--------|-------------|
| `-p`, `--passive` | DNS lookups and normal web visits only: no AXFR request, no obsolete-TLS test, no connections to mail ports |
| `-b`, `--brief` | Diagnosis only: skip sections 13 (provider change notes) and 14 (how to fix) |
| `-c`, `--compare` | Show what changed since the last saved report of the domain (saving with `--output` always does it) |
| `-a`, `--all` | Check the domain given and every domain in `RELATED_DOMAINS`, four at a time, and print one summary table |
| `-r`, `--related-domains LIST` | Your other domains, comma or space separated. A mail-sending IP whose reverse DNS is a forward-confirmed host of one of them is recognized as yours. Overrides `RELATED_DOMAINS` |
| `-o`, `--output` | Also save the report as plain text (see [Saving reports](#saving-reports)) |
| `-d`, `--output-dir DIR` | Save the report in `DIR` (implies `--output`) |
| `--requirements` | Show the needed tools and how to install them |
| `-v`, `--version` | Show name, version, author, license and disclaimer |
| `-h`, `--help` | Show the help |

Examples:

```bash
# Full check of YOUR domain (replace example.com with it)
./ndm_domain-health-check.sh example.com

# A domain that is not yours: passive mode
./ndm_domain-health-check.sh --passive example.org

# Your domain; hosts of your other domains are recognized as yours
./ndm_domain-health-check.sh --related-domains "example.net example.org" example.com

# Your domain, with the report also saved in reports/
./ndm_domain-health-check.sh -o example.com
```

The `example.*` names above are placeholders reserved for documentation (RFC 2606):
run the full check only on domains you own or manage, and `--passive` on all the
others (see [Responsible use and passive mode](#responsible-use-and-passive-mode)).
Some networks block outgoing connections to port 25: from there the mail server
checks may report port 25 as unreachable even when it works.

## Configuration

Settings live in a file **next to the script**, with the same name and the `.conf`
extension: `ndm_domain-health-check.conf`. Start from the template:

```bash
cp ndm_domain-health-check.conf.example ndm_domain-health-check.conf
```

One `KEY=value` per line; lines starting with `#` are ignored. The file is **only read,
never executed**. It is personal (it contains your domains), so it is listed in
`.gitignore`: only the `.example` template belongs in the repository.

| Key | Default | Description |
|-----|---------|-------------|
| `RELATED_DOMAINS` | *(none)* | Your other domains (see `--related-domains`) |
| `RESOLVER` | `9.9.9.10` | Validating resolver used for the checks (Quad9 without malware filtering, see [External services contacted](#external-services-contacted)) |
| `DKIM_SELECTORS` | the most common ones (see the template) | DKIM selectors to look for: the DNS cannot list them, so add yours if it is not found |
| `OUTPUT_DIR` | `reports` | Directory for `--output`; relative paths start from the script's directory |
| `NO_COLOR` | *(empty)* | Any value disables colors |
| `DNSBLS` | PSBL, Spamhaus ZEN | Blocklists to check, as `zone:level` (`fail` or `warn` when listed); add `:6` (`zone:level:6`) if the list also answers for IPv6 |
| `DOMAIN_DNSBLS` | Spamhaus DBL | Blocklists of domain names, as `zone:level`; set it empty to skip them |
| `DNSBL_RESOLVER` | *(system resolver)* | Resolver used only for the blocklists: Spamhaus and others refuse public or shared resolvers, so point it to your own (for example `127.0.0.1`) |
| `CT_LOOKUP` | `on` | `off` skips the Certificate Transparency search |
| `SPF_PROVIDERS` | *(empty)* | Labels for SPF includes: `text=Label; text=Label` (without labels, includes are shown by name) |

**Precedence:** command-line options › environment › config file › defaults.
For a single run, a setting can be given in the environment:

```bash
RESOLVER=127.0.0.1 ./ndm_domain-health-check.sh example.com
```

`RELATED_DOMAINS` is the exception: it is taken **only** from the config file or from
`--related-domains`, never from the environment, so that a variable left exported in
the shell cannot silently change the results. Commented out or missing means none.

### Choosing the blocklist resolver

Some blocklists, Spamhaus among them, refuse queries that arrive through public or shared
resolvers. When that happens the report shows a warning (`refused the queries: NOT checked`)
and that list is missing from the "not listed" count. `DNSBL_RESOLVER` sends only the
blocklist queries to a resolver the lists accept; everything else keeps using `RESOLVER`.

What to use, in order of preference:

1. **`127.0.0.1`**, if the machine runs its own recursive resolver (Unbound, Knot Resolver,
   BIND). The queries leave from your own address, which is what the lists expect. It does not
   help if `127.0.0.1` only forwards to another resolver (a stub such as `systemd-resolved`
   or `dnsmasq`): the query still leaves through the forwarder's upstream.
2. **Your router or gateway, or your ISP's resolver**, when it resolves on its own or forwards
   to the ISP. The lists see an ordinary, low-volume customer address and accept it. It fails
   when the router forwards to a public resolver.
3. **Avoid public resolvers** (Google, Cloudflare, Quad9...): many clients share them, the
   lists cannot tell them apart and refuse them to limit abuse.

To check whether a resolver is accepted (replace `<resolver-ip>` with its address):

```bash
dig +short 2.0.0.127.zen.spamhaus.org @<resolver-ip>
```

`2.0.0.127` is the Spamhaus test address and is always listed:

| Answer | Meaning |
|--------|---------|
| `127.0.0.2` (often with `127.0.0.4` and `127.0.0.10`) | Accepted: use this resolver |
| `127.255.255.254` (any `127.255.255.x`) | Refused: public or shared resolver |
| nothing, or a timeout | The resolver does not respond or does not resolve |

Then set it in the configuration file, for example `DNSBL_RESOLVER=127.0.0.1`.

## Saving reports

```bash
./ndm_domain-health-check.sh -o example.com
# ...report on screen...
Report saved to: /path/to/NDM_Domain-Health-Check/reports/example.com_20261014-113538.txt
```

- File name: `<domain>_<YYYYMMDD>-<HHMMSS>.txt`, plain text (colors removed). The file is
  private (mode 600: it holds your domain's real data) and an existing file is never overwritten.
- Each saved report ends with `#NDM_FACT` lines, introduced by a few `#NDM_NOTE` lines that
  explain them (both hidden on screen). The next run with `--output` or `--compare` compares
  itself with the latest report of the same domain and prints section 15: nameservers, DS,
  MX, SPF, DMARC, DKIM, CAA and similar changes are marked "to check".
- Default directory: `reports/` next to the script. It ships empty (only a `.gitkeep`
  placeholder is versioned); the reports saved in it are ignored by Git.
- `OUTPUT_DIR` in the config file changes it permanently; `--output-dir DIR` changes it
  for one run (a relative `DIR` starts from the current directory).

## Sample output

> **Note:** this output is only an illustration. Domain names, addresses, keys and
> records are fictitious documentation values (RFC 2606, RFC 5737, RFC 5398): they are
> not the real data of `example.com` and may not match what the script reports today.
> The layout of the report may also change between versions.

An abridged report produced in passive mode, as for any domain that is not yours:

```bash
./ndm_domain-health-check.sh --passive example.com
```

```
══════════════════════════════════════════════════════════════════════
  NDM Domain Health Check (1.1.0)
  Domain: EXAMPLE.COM
  Resolver: 9.9.9.10  ·  2026-10-14 12:23
  ✔ ok  ↑ improvable  ◆ to check  ⚠ warning  ✘ error  ℹ info
  Mode: passive (no AXFR, no obsolete-TLS test, no mail port connections)
══════════════════════════════════════════════════════════════════════

[3] REGISTRY (DELEGATION)
  Source: .com registry nameserver a.gtld-servers.net (direct, no recursion)
  ✔ Nameservers              ns1.provider.example ns2.provider.example
  ℹ DS records               2 (more than one is normal only during a key rollover)
      12345  alg 13 ECDSAP256SHA256  digest-type 2  0123456789ABCDEF…
      12345  alg 8 RSASHA256  digest-type 2  0123456789ABCDEF…

[5] DNSSEC
  Source: registry DS vs. zone DNSKEY, signatures on ns1.provider.example, validation via 9.9.9.10
  ✔ DS 12345 alg 13          matches key 12345 (flags 257)
  ✘ DS 12345 alg 8           matches NO published key (wrong algorithm, tag or digest?)
  ✔ Signature (SOA)          valid until 2026-10-21 12:24 UTC (6 days)
  ✔ Validation (delv)        fully validated

[7] MAIL (DNS)
  Source: resolver 9.9.9.10
  ✔ SPF                      soft fail (~all)
      - ip4:203.0.113.10
      - ip4:198.51.100.25
      - include:_spf.relay.example
         - ip4:192.0.2.0/29
         - include:_spf2.relay.example
            - 4 IPv4 + 1 IPv6 ranges
      - +mx                                          -> example.com (203.0.113.10)
      - ~all                                         softfail for every other server
  ✔ SPF 203.0.113.10         this domain's MX example.com, website
  ◆ SPF 198.51.100.25        matches no host of this domain (A/AAAA, MX, CT names): intended?
      reverse DNS  vps.old-name.example.net (does NOT resolve back to 198.51.100.25: stale or generic PTR?)
                   belongs to another domain: example.net
      owner        AS64500 EXAMPLE-NET · US
  ✔ SPF DNS lookups          3 of 10 (nested includes counted)
  ✔ DMARC                    p=quarantine
  ↑ MTA-STS                  not published: senders cannot be required to use TLS

[14] HOW TO FIX
  Source: practical steps for the findings above, most urgent first
      Values on their own lines are ready to copy. Run the script again after each change.

  1. ✘ DNSSEC: remove the stale DS at the registrar
       These DS records match no key of the zone (an old key or a typo):
         example.com. IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
       The domain still validates through the DS that matches; remove only these.

  2. ⚠ Reverse DNS: vps.old-name.example.net does not resolve back to 198.51.100.25
       Ask the owner of the IP (AS64500 EXAMPLE-NET · US) to set the PTR to a name of yours,
       then add its address:
         PTR of 198.51.100.25  →  mail.example.com
         mail.example.com. IN A 198.51.100.25

  3. ◆ SPF: confirm that 198.51.100.25 may send mail as @example.com
       If it is yours (a VPS, a relay), give it a reverse DNS name in one of your
       domains and add that domain to RELATED_DOMAINS. If you do not recognize it,
       remove it from the SPF record: it can send mail in your name.

  4. ↑ Mail: publish MTA-STS (receive mail only over TLS)
       1. Serve this file at https://mta-sts.example.com/.well-known/mta-sts.txt
       …

══════════════════════════════════════════════════════════════════════
  SUMMARY: example.com   ✔ 25 ok  ↑ 6 improvable  ◆ 1 to check  ⚠ 1 warnings  ✘ 1 errors
  ✘ DS 12345 alg 8: matches NO published key (wrong algorithm, tag or digest?)
  ⚠ PTR 198.51.100.25: vps.old-name.example.net does not resolve back to 198.51.100.25
  To check (cannot be judged automatically):
  ◆ SPF 198.51.100.25: matches no host of this domain (A/AAAA, MX, CT names): intended?
  Improvements:
  ↑ MTA-STS: not published: senders cannot be required to use TLS
  ↑ …
══════════════════════════════════════════════════════════════════════
```

## Delicate operations

Some protections tie the registrar, the DNS provider, the hosting and the mail server
together. Changing one of them in the wrong order can make the domain, or its mail,
unreachable for hours or days. Section 13 of the report lists these steps for the
domain being checked, with its real values (TTLs, `max_age`, selectors); this is the
complete reference.

Before any change, save a report of the current state (`--output`): it is the list of what
must still be in place afterwards. After every step, run the script again.

### Changing registrar

DNS records and DNSSEC keys do not move: only the registration does.

1. Write down the nameservers and the DS records (section 3).
2. Unlock the domain, ask for the transfer code, check that the registrant e-mail works.
3. After the transfer, check that nameservers and DS are unchanged. Some registrars drop
   the DS: the domain keeps working, unsigned. Add the same DS again.

### Changing DNS provider

1. Copy **all** the records to the new provider, then compare them one by one with the
   saved report: A/AAAA, CNAME, MX, SPF, DKIM, DMARC, MTA-STS (`_mta-sts`), TLS-RPT
   (`_smtp._tls`), CAA, SRV and any other.
2. A day before, lower the TTLs.
3. With DNSSEC on: remove the DS at the registrar **first**, then wait for its TTL plus
   margin (24 hours is safe). Never switch nameservers while the old DS is published:
   validating resolvers would stop resolving the domain.
4. Switch the nameservers at the registrar and wait 24–48 hours.
5. Turn DNSSEC on at the new provider and give the **new** DS to the registrar.

### Changing web hosting

1. A day before, lower the TTLs.
2. If the nameservers belong to the hosting, this is also a DNS provider change: follow
   that procedure first.
3. With MTA-STS: copy the policy file to the new hosting, with a valid certificate for
   `mta-sts.<domain>`, **before** moving its address.
4. Update the A/AAAA records and every IP address written in SPF.
5. If the mail lives on the same hosting, follow also the next procedure.

### Changing mail server or provider

1. With MTA-STS in `enforce`: at least `max_age` before the change, add the new mail host
   as an extra `mx:` line of the policy (or set `mode: testing`) and change the `id` in
   `_mta-sts`. Senders accept only the MX listed in the policy they have cached.
2. A day before, lower the TTL of the MX record.
3. Publish the new server's SPF entry and DKIM key **before** switching; keep the old ones
   until the move is over.
4. Change the MX, then the `mx:` lines of the MTA-STS policy and its `id`.
5. Check the new server's certificate for the MX name (section 8) and its reverse DNS.
6. After a few days, remove the old SPF entry and DKIM key; with clean TLS reports, go
   back to `enforce`.

### DNSSEC: turning it on and off

- **On**: turn signing on at the DNS provider, then give the registrar the DS shown in
  section 14. Only the key-signing key (flags 257) is needed.
- **Off**: remove the DS at the registrar, wait for its TTL plus margin, and only then
  turn signing off. The opposite order breaks the domain for validating resolvers.

### MTA-STS: turning it on, enforcing, changing, turning it off

MTA-STS tells the servers that send you mail: "deliver to my MX only over TLS, with a
valid certificate". Two rules apply to every operation below:

- senders keep the policy in memory for `max_age` seconds, so a change reaches all of
  them only after that time;
- every change of the policy file needs a **new `id`** in the `_mta-sts` TXT record,
  otherwise senders do not even download the new file.

**Before you start**

1. The mail server must present, on port 25, a valid certificate that contains the MX
   name: section 8 of the report, or
   `openssl s_client -starttls smtp -connect <mx>:25 -servername <mx> -verify_hostname <mx> -brief </dev/null`
   must answer `Verification: OK`.
2. Create a mailbox (or a forwarder) for the TLS reports, for example `tlsrpt@<domain>`.

**Turning it on (`testing` mode: nothing is ever refused)**

1. DNS: create `mta-sts.<domain>` (A record or CNAME) pointing to the web server that
   will serve the file, **without** proxy or CDN.
2. Web server: create the site `mta-sts.<domain>` and obtain its certificate. If the
   hosting panel also wants `www.mta-sts.<domain>` and cannot exclude it, add in the DNS
   `www.mta-sts.<domain>. CNAME mta-sts.<domain>.`
3. In that site, create the file `.well-known/mta-sts.txt` with one `mx:` line for each
   MX record (section 14 of the report gives it ready, built from your MX):
   ```
   version: STSv1
   mode: testing
   mx: mail.example.com
   max_age: 86400
   ```
4. Check that it answers directly with `200`, without redirects, and shows the file:
   `curl -i https://mta-sts.<domain>/.well-known/mta-sts.txt`
5. DNS: publish the two TXT records (the `id` is free text: the date plus a counter is
   handy):
   ```
   _mta-sts.<domain>.    TXT  "v=STSv1; id=2026101501"
   _smtp._tls.<domain>.  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>"
   ```
6. Run the script: section 7 must show `MTA-STS mode testing` and `TLS-RPT published`.

**Switching to `enforce`**

1. Read the daily TLS reports for 2–4 weeks: `total-failure-session-count` must stay at
   `0`. A failure means that a sender could not get a valid TLS connection: find out why
   before going on.
2. In the file, set `mode: enforce` and `max_age: 604800` (one week).
3. Change the `id` in `_mta-sts` (for example `id=2026111501`).
4. Check with `curl` and with the script: section 7 must show `MTA-STS mode enforce`.

**Changing the policy** (another MX, a new mail host)

1. Edit the file: add or remove the `mx:` lines.
2. Change the `id` in `_mta-sts`.
3. When the mail moves to another server, follow
   [Changing mail server or provider](#changing-mail-server-or-provider): in `enforce`,
   the new host must be in the policy at least `max_age` before the switch.

**Turning it off**

1. In the file, set `mode: none` and change the `id` in `_mta-sts`.
2. Keep file and records online for `max_age` (one week with `604800`): senders replace
   their cached policy with the `none` one.
3. Then remove the `_mta-sts` record, the file, the `mta-sts` site and its DNS records
   (including `www.mta-sts`, if you added it). `_smtp._tls` may stay: it only asks for
   reports.

**What can go wrong**

- In `enforce`, an expired mail server certificate, or one without the MX name: senders
  keep your mail queued and, after a few days, return it to the sender. Watch the
  certificate renewals and the TLS reports.
- A changed file with the same `id`: senders ignore the change until `max_age` expires.
- Records removed without passing through `mode: none`: senders keep the old policy
  until `max_age` expires.

### DMARC: tightening the policy

Move one step at a time, reading the reports (`rua=`) in between: `p=none` (monitoring)
→ `p=quarantine` → `p=reject`. Before each step, every service that sends mail as your
domain must pass SPF or DKIM aligned with it: a forgotten newsletter or invoicing service
would see its mail quarantined or rejected.

### Rotating a DKIM key

Publish the new key under a **new** selector, switch the signing to it, and remove the
old key only a week later: mail already sent is still checked against the old one.

## Responsible use and passive mode

Almost everything the script reads is public by design: DNS records, registration data,
certificates, HTTP headers, blocklists. A few checks go one step further and are
normally run on **your own** domains or on domains you manage with the owner's consent:

- **AXFR**: asks every nameserver for the whole zone (a correctly configured server refuses);
- **obsolete TLS**: tries a TLS 1.0/1.1 handshake;
- **mail ports**: connects to ports 25, 465, 587, 993, 995, 143 and 110 and reads their
  capabilities. No login is ever attempted and no credentials are used;
- **server probes**: weak cipher suites on the web and mail TLS ports, the SMTP banner and
  the `VRFY`/`EXPN` commands, recursion and `version.bind` on the nameservers, TLS on every live
  name found in the CT logs, and a web request to names whose CNAME points to a service where
  sites can be claimed.

For domains that are not yours, use `--passive`: it skips all of them. Avoid repeated or
mass checks of third-party domains. Registration data may include personal data
(GDPR): reading it is legitimate, storing or reusing it is not.

What a scanned domain can make the script do is limited. Every connection (web, TLS, mail
ports, ping) goes only to public addresses: a name of the domain, or a redirect, that resolves
to loopback, the LAN or another private range is not contacted (a hostile domain could
otherwise point the script at your network). The addresses are checked through the configured
resolver and then pinned, so every tool connects to exactly the addresses that were checked.
The web checks follow at most 5 redirects, and only to HTTP(S). Names read from DNS records are
validated before they reach `dig`, the SPF tree is analysed up to 50 records, the answers read
from a server are size-limited, and each mail probe has an overall time limit. The embedded
Python helpers run in isolated mode, so they never import modules from the current directory.

## External services contacted

| Service | Used for |
|---------|----------|
| Validating resolver (`RESOLVER`, default Quad9 `9.9.9.10`) | DNS lookups and DNSSEC validation |
| TLD registry nameservers | NS and DS exactly as published by the registry |
| Domain's authoritative nameservers | SOA, DNSKEY, signatures, AXFR test |
| IANA RDAP bootstrap, registry RDAP / WHOIS servers | Domain registration and IP ownership |
| RIPEstat (RIPE NCC) | Announced prefix and origin ASN of IP addresses |
| crt.sh | Certificate Transparency logs (`CT_LOOKUP=off` skips it) |
| DNSBL operators (via your system resolver, or `DNSBL_RESOLVER`) | Blocklist checks |
| The domain's web and mail servers | HTTP/TLS and mail checks (not in passive mode, except normal web visits) |

The defaults favour non-profit operators and services that are free to use, and every
one of them can be changed in the configuration file:

- **Quad9** is run by a Swiss non-profit foundation and does not keep the clients' IP
  addresses. `9.9.9.10` validates DNSSEC but, unlike `9.9.9.9`, does not block the domains
  it considers malicious, so they are still checked as they really are. Your own
  validating resolver (for example Knot Resolver or Unbound) works too.
- **RIPEstat** is the public data service of the RIPE NCC, the non-profit regional
  registry for Europe; it covers addresses of every region. Requests identify themselves
  with `sourceapp=ndm_domain-health-check`, as RIPEstat asks.
- **Blocklists**: the default ones (PSBL, Spamhaus ZEN) are run by non-profit or
  community projects and are free to query and to leave. Add others in `DNSBLS`.
- **crt.sh** is open-source software and a free public service, the most complete search
  of the CT logs. Set `CT_LOOKUP=off` to skip it.

The practical advice in section 14 refers to open-source software (Apache, BIND,
certbot, Dovecot, Exim, Knot DNS, nginx, OpenDKIM, PowerDNS, Postfix, rspamd) and otherwise
describes the setting to look for, without naming commercial panels or providers. Names
of providers and certificate authorities appear in the report only when they are found
in the data of the domain being checked.

## Exit codes

| Code | Meaning |
|:----:|---------|
| `0` | Check completed, no errors (warnings and tips may be present) |
| `1` | Check completed with at least one error, or it could not run (missing required tool, invalid domain, registry unreachable) |
| `2` | Invalid command-line usage |

This makes the script usable from cron jobs or other scripts.

## Project layout

```
NDM_Domain-Health-Check/
├── ndm_domain-health-check.sh            the script
├── ndm_domain-health-check.conf.example  configuration template (versioned)
├── ndm_domain-health-check.conf          your configuration (personal, ignored by Git)
├── reports/                              saved reports (contents ignored by Git)
│   └── .gitkeep                          keeps the empty directory in the repository
├── .github/workflows/ci.yml              automatic checks (ShellCheck, smoke tests)
├── .github/dependabot.yml                monthly updates of the GitHub Actions used by CI
├── .gitattributes                        keeps Linux line endings (needed on Windows)
├── .gitignore
├── LICENSE                               GNU AGPL v3
├── CHANGELOG.md                          changes in each version
├── CITATION.cff                          how to cite this software (used by GitHub)
├── SECURITY.md                           how to report a vulnerability
├── README.md                             documentation in English
└── README.it.md                          documentation in Italian
```

## Versioning

The project follows [Semantic Versioning](https://semver.org/). Name, description,
author, version and release date are in the **APP INFO** block at the very top of
`ndm_domain-health-check.sh`; `--version` shows them. Every release has a Git tag
`vX.Y.Z`, and the changes of each version are listed in [CHANGELOG.md](CHANGELOG.md).

## License and disclaimer

Copyright (C) 2026 Nicola Davide Mannarelli ([@nidamanx](https://github.com/nidamanx))

This program is free software: you can redistribute it and/or modify it under the
terms of the **GNU Affero General Public License** as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version
(`SPDX-License-Identifier: AGPL-3.0-or-later`). See the [LICENSE](LICENSE) file.

**Credit.** If you use this tool, or parts of its code, in your work or in another
project, please credit *NDM Domain Health Check* by Nicola Davide Mannarelli and link to
this repository. The **Cite this repository** button on GitHub, generated from
[CITATION.cff](CITATION.cff), gives a ready-made citation. The license already requires
redistributed and modified copies to keep the copyright notice.

**Disclaimer.** This software is provided "as is", without warranty of any kind,
express or implied. In no event shall the author be liable for any claim, damages or
other liability, including loss of data, service disruption or blocked IP addresses,
arising from the use or misuse of this software. You alone are responsible for how you
use it, including checks run against domains and servers you do not own or manage, and
for any decision taken on the basis of its results.
