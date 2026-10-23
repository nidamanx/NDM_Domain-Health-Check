#!/usr/bin/env bash
# ---------------------------------------------------------------- APP INFO ----
# Edit these lines to rename the tool or publish a new release.
APP_NAME="NDM Domain Health Check"
APP_DESCRIPTION="Checks a domain's registration, DNS, DNSSEC, web/TLS and mail setup \
(SPF, DKIM, DMARC, mail servers, blocklists, IP ownership) and grades every finding."
APP_AUTHOR="Nicola Davide Mannarelli (@nidamanx)"
APP_VERSION="1.1.0"
APP_RELEASE_DATE="2026-10-21"
APP_COPYRIGHT="Copyright (C) 2026 Nicola Davide Mannarelli (@nidamanx)"
APP_LICENSE="AGPL-3.0-or-later"
# ------------------------------------------------------------------------------
#
# Copyright (C) 2026  Nicola Davide Mannarelli (@nidamanx)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# The full license text is in the LICENSE file distributed with this script.
#
# DISCLAIMER
# This software is provided "as is", without warranty of any kind, express or
# implied. In no event shall the author be liable for any claim, damages or other
# liability, including loss of data, service disruption or blocked IP addresses,
# arising from the use or misuse of this software. You alone are responsible for
# how you use it, including checks run against domains and servers you do not own
# or manage, and for any decision taken on the basis of its results.
# ------------------------------------------------------------------------------

# HELP-BEGIN
# Usage:   ./ndm_domain-health-check.sh [options] [domain]
#          (asks for the domain when it is not given)
#
# Options: -p, --passive         DNS lookups and normal web visits only: no AXFR request,
#                                no obsolete-TLS test, no connections to mail ports
#          -r, --related-domains LIST
#                                other domains of yours, comma or space separated
#                                (e.g. --related-domains=example.org,example.net). A mail-sending IP
#                                whose reverse DNS is a forward-confirmed host of one of them
#                                is accepted. Overrides the RELATED_DOMAINS variable.
#          -o, --output          also save the report as plain text:
#                                reports/<domain>_<YYYYMMDD>-<HHMMSS>.txt
#                                (reports/ is next to this script; see OUTPUT_DIR)
#          --output-dir DIR      save the report in DIR (implies --output; a relative
#                                DIR starts from the current directory)
#          -b, --brief           diagnosis only: skip the practical sections 13
#                                (provider change notes) and 14 (how to fix)
#          -c, --compare         show what changed since the last saved report of the domain
#                                (saving with -o always does it)
#          -a, --all             check the domain given and every domain of RELATED_DOMAINS, and
#                                print one summary table (brief checks, run four at a time)
#          --requirements        show the needed tools and how to install them
#          -v, --version         show name, version, author, license and disclaimer
#          -h, --help            show this help
#
# Settings:
#          RESOLVER=9.9.9.10           validating resolver to use (Quad9, no filtering)
#          DKIM_SELECTORS="default x"  DKIM selectors to probe
#          RELATED_DOMAINS="a.org b.net" your other domains (see --related-domains)
#          NO_COLOR=1                  disable colors
#          OUTPUT_DIR=reports          directory for --output (a relative path starts
#                                      from the script's directory)
#          DNSBL_RESOLVER=127.0.0.1    resolver used only for the blocklists (default: the
#                                      system resolver; see the config template)
#          DOMAIN_DNSBLS="zone:level"  blocklists of domain names (empty = skip them)
#          DNSBLS="zone:level ..."     blocklists to check (level: fail or warn; add :6 to a
#                                      zone that supports IPv6, e.g. zone:fail:6)
#          CT_LOOKUP=off               skip the Certificate Transparency search (crt.sh)
#          SPF_PROVIDERS="text=Label; ..."  extra labels for SPF includes
#
#   Config file: next to this script, same name with the .conf extension
#   (ndm_domain-health-check.conf; start from ndm_domain-health-check.conf.example). One KEY=value
#   per line, only read, never executed. It is personal: keep it out of Git.
#   For one run a setting can also be given in the environment:
#          RESOLVER=127.0.0.1 ./ndm_domain-health-check.sh example.com
#   Precedence: command-line options > environment > config file > defaults
#   (the defaults are in the CONFIGURATION block at the top of this script).
#   RELATED_DOMAINS is the exception: it is taken ONLY from the config file or from
#   --related-domains, never from the environment. Commented out or missing = none.
#
# Examples:
#          ./ndm_domain-health-check.sh example.com         (full check: only YOUR domains)
#          ./ndm_domain-health-check.sh --passive example.org   (a domain that is not yours)
#          ./ndm_domain-health-check.sh --related-domains "example.net example.org" example.com
#          ./ndm_domain-health-check.sh -o example.com      (report also saved in reports/)
#
# Needs:   dig (required); python3, delv, openssl, curl, ping (optional, enable extra checks)
#          Run with --requirements for the install commands of your system.
#
# Result levels:
#   ✔ OK       correct
#   ↑ TIP      works, but could be improved
#   ◆ CHECK    cannot be judged automatically: a person must confirm it is intended
#   ⚠ WARNING  works, but is risky or needs attention soon
#   ✘ ERROR    broken or insecure
#   ℹ INFO     neutral information
# HELP-END

set -u

# --------------------------------------------------------- CONFIGURATION ----
# Defaults. Prefer setting them in the config file next to this script (see --help):
# changes made here are lost when the script is updated.

# Real location of this script (following symlinks): the config file and the reports
# directory live next to it.
SCRIPT_PATH=${BASH_SOURCE[0]}
while [[ -L $SCRIPT_PATH ]]; do
  link_target=$(readlink "$SCRIPT_PATH")
  if [[ $link_target == /* ]]; then SCRIPT_PATH=$link_target
  else SCRIPT_PATH="$(dirname "$SCRIPT_PATH")/$link_target"; fi
done
SCRIPT_DIR=$(cd "$(dirname "$SCRIPT_PATH")" && pwd -P)
CONFIG_FILE="$SCRIPT_DIR/$(basename "$SCRIPT_PATH" .sh).conf"

# Read KEY=value lines from the config file (never executed). A variable already set
# in the environment is left untouched, so the environment wins over the file.
load_config() {
  local key value
  [[ -r $CONFIG_FILE ]] || return 0
  while IFS='=' read -r key value || [[ -n $key ]]; do
    key=$(printf '%s' "$key" | tr -d '[:space:]')
    [[ -z $key || $key == \#* ]] && continue
    value=$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
      -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")
    case $key in
      RESOLVER|DKIM_SELECTORS|RELATED_DOMAINS|NO_COLOR|OUTPUT_DIR|DNSBLS|DOMAIN_DNSBLS|DNSBL_RESOLVER|CT_LOOKUP|SPF_PROVIDERS)
        declare -p "$key" >/dev/null 2>&1 || printf -v "$key" '%s' "$value" ;;
    esac
  done <"$CONFIG_FILE"
}
# RELATED_DOMAINS must come only from the config file or --related-domains: an exported
# variable left in the shell must not silently change the results.
unset RELATED_DOMAINS
load_config

# Quad9 (Swiss non-profit foundation): 9.9.9.10 validates DNSSEC without blocking the
# domains it considers malicious, so a flagged domain is still checked as it really is.
RESOLVER="${RESOLVER:-9.9.9.10}"
# DKIM selectors tried (DNS cannot list them): the ones most mail services use.
DKIM_SELECTORS="${DKIM_SELECTORS:-brevo1 brevo2 ctct1 ctct2 default dkim dkim1 dkim2 fm1 fm2 fm3 google hs1 hs2 k1 k2 k3 km1 km2 mail mandrill mte1 mte2 pdk1 pdk2 protonmail protonmail2 protonmail3 s1 s2 selector1 selector2 sig1 smtp zmail zoho}"
RELATED_DOMAINS="${RELATED_DOMAINS:-}"
# These lists are expanded unquoted: a glob character would match file names of the current directory.
DKIM_SELECTORS=${DKIM_SELECTORS//[*?[]/}
OUTPUT_DIR="${OUTPUT_DIR:-reports}"
NET_TIMEOUT=8
# DNS blocklists checked for mail server IPs ("zone:level[:6]"; ":6" = the list also answers
# for IPv6, Spamhaus ZEN always does). Default: lists
# run by non-profit or community projects, free to query and to leave.
DNSBLS="${DNSBLS:-psbl.surriel.com:warn zen.spamhaus.org:fail:6}"
# Blocklists of domain names ("zone:level"): the reputation of the name itself, not of its IPs.
# Set it empty to skip them.
DOMAIN_DNSBLS="${DOMAIN_DNSBLS-dbl.spamhaus.org:fail}"
DNSBLS=${DNSBLS//[*?[]/}; DOMAIN_DNSBLS=${DOMAIN_DNSBLS//[*?[]/}
# Resolver for the blocklist queries only. Empty = the system resolver. Some lists (Spamhaus
# among them) refuse public or shared resolvers: point this to your own (e.g. 127.0.0.1).
DNSBL_RESOLVER="${DNSBL_RESOLVER:-}"
# Certificate Transparency search through crt.sh: "off" skips it.
CT_LOOKUP="${CT_LOOKUP:-on}"
# Extra labels for SPF includes: "text=Label; text=Label" (text found in the include name).
SPF_PROVIDERS="${SPF_PROVIDERS:-}"

# ---------------------------------------------------------------- colors ----
if [[ ( -t 1 || -n ${_NDM_FORCE_COLOR:-} ) && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'; C_MAGENTA=$'\e[35m'; C_CYAN=$'\e[36m'
else
  C_RESET=; C_BOLD=; C_DIM=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=; C_MAGENTA=; C_CYAN=
fi

OK_COUNT=0; TIP_COUNT=0; CHECK_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0
TIP_LIST=(); CHECK_LIST=(); WARN_LIST=(); FAIL_LIST=()

# ------------------------------------------------------------ output API ----
# Text from third parties (HTTP headers, WHOIS/RDAP, SMTP banners) may carry terminal escape
# sequences: control characters are dropped and newlines become spaces. Result in $SANE.
sane() { local s=${1//$'\n'/ }; SANE=${s//[[:cntrl:]]/}; }
line_out() {
  local label message
  sane "$3"; label=$SANE
  sane "$4"; message=$SANE
  printf '  %s%s%s %-24s %s\n' "$1" "$2" "$C_RESET" "$label" "$message"
}
ok()     { OK_COUNT=$((OK_COUNT + 1)); line_out "$C_GREEN" "✔" "$1" "$2"; }
tip()    { TIP_COUNT=$((TIP_COUNT + 1)); sane "$1: $2"; TIP_LIST+=("$SANE"); line_out "$C_MAGENTA" "↑" "$1" "$2"; }
check()  { CHECK_COUNT=$((CHECK_COUNT + 1)); sane "$1: $2"; CHECK_LIST+=("$SANE"); line_out "$C_CYAN" "◆" "$1" "$2"; }
warn()   { WARN_COUNT=$((WARN_COUNT + 1)); sane "$1: $2"; WARN_LIST+=("$SANE"); line_out "$C_YELLOW" "⚠" "$1" "$2"; }
fail()   { FAIL_COUNT=$((FAIL_COUNT + 1)); sane "$1: $2"; FAIL_LIST+=("$SANE"); line_out "$C_RED" "✘" "$1" "$2"; }
info()   { line_out "$C_BLUE" "ℹ" "$1" "$2"; }
detail() { sane "$1"; printf '      %s%s%s\n' "$C_DIM" "$SANE" "$C_RESET"; }
section() {
  printf '\n%s%s[%s] %s%s\n' "$C_BOLD" "$C_CYAN" "$1" "$2" "$C_RESET"
  printf '  %sSource: %s%s\n' "$C_DIM" "$3" "$C_RESET"
}
have() { command -v "$1" >/dev/null 2>&1; }
# Registrable domain of host names on stdin: the last two labels, three under the common
# second-level suffixes (provider.co.uk). Not a full public suffix list.
reg_domain() {
  awk -F. 'NF >= 3 && length($NF) == 2 && $(NF - 1) ~ /^(co|com|org|net|gov|edu|ac|ltd|plc|me|nom)$/ {
             print $(NF - 2) "." $(NF - 1) "." $NF; next }
           NF >= 2 {print $(NF - 1) "." $NF}'
}

# Practical fixes, printed in section [14]. Usage: fix KEY PRIORITY "Title" "step"...
# PRIORITY: 1 error, 2 warning, 3 to check, 4 improvement. Each KEY is kept once.
# Steps starting with "= " are values to copy (records, settings): printed without the
# prefix and without dimming, so they can be selected and pasted as they are.
FIX_KEYS=" "; FIX_1=(); FIX_2=(); FIX_3=(); FIX_4=()
fix() {
  local key=$1 prio=$2 entry
  shift 2
  [[ $FIX_KEYS == *" $key "* ]] && return 0
  FIX_KEYS+="$key "
  entry=$(printf '%s\n' "$@")
  case $prio in
    1) FIX_1+=("$entry") ;;
    2) FIX_2+=("$entry") ;;
    3) FIX_3+=("$entry") ;;
    *) FIX_4+=("$entry") ;;
  esac
}
fix_n=0
print_fixes() {
  local col=$1 sym=$2 entry step
  shift 2
  for entry in "$@"; do
    fix_n=$((fix_n + 1))
    sane "${entry%%$'\n'*}"
    printf '\n  %s%s%d. %s %s%s\n' "$C_BOLD" "$col" "$fix_n" "$sym" "$SANE" "$C_RESET"
    [[ $entry == *$'\n'* ]] || continue
    while IFS= read -r step; do
      case $step in
        '= '*) sane "${step#= }"; printf '         %s\n' "$SANE" ;;
        '') ;;
        *) sane "$step"; printf '       %s%s%s\n' "$C_DIM" "$SANE" "$C_RESET" ;;
      esac
    done <<<"${entry#*$'\n'}"
  done
}

# Render "level<TAB>label<TAB>message" lines produced by the Python probes.
render() {
  local lvl label msg
  while IFS=$'\t' read -r lvl label msg; do
    case $lvl in
      ok) ok "$label" "$msg" ;;     tip) tip "$label" "$msg" ;;
      check) check "$label" "$msg" ;;
      warn) warn "$label" "$msg" ;; fail) fail "$label" "$msg" ;;
      info) info "$label" "$msg" ;;
    esac
    case $lvl in fail) probe_fix 1 "$msg" ;; warn) probe_fix 2 "$msg" ;; tip) probe_fix 4 "$msg" ;; esac
  done
}

# Fixes for the findings of the TLS and mail probes, recognized by their message.
probe_fix() {
  local prio=$1 msg=$2 host
  host=${msg%%:*}
  case $msg in
    *"certificate NOT valid"*|*"TLS handshake failed"*|*"certificate EXPIRED"*|*"certificate expires in"*)
      fix "cert-$host" "$prio" "TLS: install a valid certificate for $host" \
        "The certificate must be valid, not expired and contain the name $host." \
        "In a hosting control panel: the SSL/TLS section (automatic certificates cover" \
        "mail. and webmail. when they point to the server). Own server, with certbot:" \
        "= certbot certonly -d $host   (then reload the web and mail services)" \
        "On shared hosting, mail clients can use the provider's server name instead." ;;
    *"obsolete"*)
      fix legacy-tls "$prio" "TLS: turn off TLS 1.0 and 1.1" \
        "= Apache:   SSLProtocol -all +TLSv1.2 +TLSv1.3" \
        "= Dovecot:  ssl_min_protocol = TLSv1.2" \
        "= nginx:    ssl_protocols TLSv1.2 TLSv1.3;" \
        "= Postfix:  smtpd_tls_protocols = >=TLSv1.2   (same for smtpd_tls_mandatory_protocols)" \
        "Shared hosting: ask the provider." ;;
    *"no STARTTLS"*|*"WITHOUT STARTTLS"*)
      fix starttls "$prio" "Mail: turn on encryption on the mail server" \
        "Install a certificate for the mail host name and enable TLS:" \
        "= Dovecot:  ssl = required, ssl_cert = <..., ssl_key = <..." \
        "= Postfix:  smtpd_tls_cert_file, smtpd_tls_key_file, smtpd_tls_security_level = may" \
        "Shared hosting: ask the provider." ;;
    *"plaintext login"*|*"BEFORE STARTTLS"*)
      fix plain-auth "$prio" "Mail: allow login only after encryption" \
        "= Dovecot:  disable_plaintext_auth = yes   (Dovecot 2.4: auth_allow_cleartext = no)" \
        "= Exim:     auth_advertise_hosts = \${if eq{\$tls_in_cipher}{}{}{*}}" \
        "= Postfix:  smtpd_tls_auth_only = yes" \
        "Shared hosting: ask the provider to disable plaintext authentication." ;;
    *"no working encrypted port"*)
      fix client-ports "$prio" "Mail: open the encrypted ports for mail clients" \
        "Sending: 465 (SSL/TLS) or 587 (STARTTLS). Reading: 993 (IMAPS) or 995 (POP3S)." \
        "Enable them on the mail server and allow them in the firewall." ;;
    *"banner announces"*|*"banner reveals"*)
      fix smtp-banner "$prio" "Mail: set an honest, plain SMTP banner" \
        "The greeting should name the server as its MX/PTR does, and no software version:" \
        "= Postfix:  myhostname = $host   and   smtpd_banner = \$myhostname ESMTP" \
        "= Exim:     smtp_banner = \"\${primary_hostname} ESMTP\"" ;;
    *"VRFY confirms"*)
      fix smtp-vrfy "$prio" "Mail: turn off VRFY" \
        "= Postfix:  disable_vrfy_command = yes" \
        "= Exim:     leave acl_smtp_vrfy unset (it is off by default)" ;;
    *"EXPN lists"*)
      fix smtp-expn "$prio" "Mail: turn off EXPN" \
        "= Postfix:  EXPN is not implemented, check what answers on this port" \
        "= Exim:     do not set smtp_expn_hosts" \
        "= Sendmail: O PrivacyOptions=noexpn" ;;
    *"accepts 3DES"*|*"accepts RC4"*|*"export, NULL or anonymous"*|*"without forward secrecy"*)
      fix "weak-ciphers-${host//[^A-Za-z0-9]/_}" "$prio" "TLS: remove old cipher suites on $host" \
        "Allow only modern suites (ECDHE/DHE key exchange with AES-GCM or ChaCha20):" \
        "= Apache:   SSLCipherSuite HIGH:!aNULL:!eNULL:!3DES:!RC4:!kRSA   (and SSLProtocol -all +TLSv1.2 +TLSv1.3)" \
        "= nginx:    ssl_ciphers HIGH:!aNULL:!eNULL:!3DES:!RC4:!kRSA;" \
        "= Dovecot:  ssl_cipher_list = HIGH:!aNULL:!eNULL:!3DES:!RC4:!kRSA" \
        "= Postfix:  smtpd_tls_exclude_ciphers = aNULL, eNULL, 3DES, RC4, EXPORT, LOW" ;;
    *"prefer 993"*|*"prefer 995"*)
      fix implicit-tls "$prio" "Mail: configure the clients on 993/995 (and 465)" \
        "Ports with TLS from the first byte (RFC 8314) are safer than STARTTLS on 143/110." \
        "Close 143 and 110 in the firewall when no client uses them any more." ;;
  esac
}

# Run a command with a time limit (portable: GNU timeout, gtimeout or perl).
run_to() {
  local secs=$1; shift
  if have timeout; then timeout "$secs" "$@"
  elif have gtimeout; then gtimeout "$secs" "$@"
  else perl -e 'alarm shift; exec @ARGV' "$secs" "$@"
  fi
}

# Names come from DNS data of the audited domain: one starting with "-" would be read by dig
# as an option (-f FILE sends the lines of a local file as queries). Invalid names give no answer.
valid_name() { [[ $1 =~ ^[A-Za-z0-9_*][A-Za-z0-9_*.-]*$ ]]; }

# Short DNS query through a server (default: public resolver); drops dig error lines.
# Answers are kept in $tmpdir for the rest of the run (the same names are asked by several
# sections); a query that gets no reply at all is not kept and is counted in dns_errors.
q() {
  local type=$1 name=$2 server=${3:-$RESOLVER} key="" out rc
  valid_name "$name" || return 0
  if [[ -n ${tmpdir:-} ]] && have md5sum; then
    key="$tmpdir/q_$(printf '%s' "$type|$name|$server" | md5sum | cut -c1-32)"
    if [[ -e $key ]]; then cat "$key"; return 0; fi
  fi
  out=$(dig +short +time=3 +tries=2 "$type" "$name" @"$server" 2>/dev/null)
  rc=$?
  out=$(grep -v '^;' <<<"$out")
  if ((rc != 0)); then
    [[ -n ${tmpdir:-} ]] && echo "$type $name" >>"$tmpdir/dns_errors"
  elif [[ -n $key ]]; then
    printf '%s\n' "$out" >"$key.$BASHPID" && mv "$key.$BASHPID" "$key"
  fi
  [[ -z $out ]] || printf '%s\n' "$out"
}

# Short DNS query for the blocklists: DNSBL_RESOLVER, or the system resolver when it is empty
# (some blocklists refuse public resolvers).
q_sys() {
  local at=()
  valid_name "$2" || return 0
  [[ -n $DNSBL_RESOLVER ]] && at=("@$DNSBL_RESOLVER")
  dig +short +time=3 +tries=1 "$1" "$2" "${at[@]+"${at[@]}"}" 2>/dev/null | grep -v '^;'
}

# TXT query with split strings joined and surrounding quotes removed.
txt() {
  q TXT "$1" "${2:-$RESOLVER}" | sed -e 's/" "//g' -e 's/^"//' -e 's/"$//'
}

# Addresses of a name, one per line: IPv4 (q4) or IPv6 (q6). CNAME lines are dropped.
q4() { q A "$@" | grep -E '^[0-9.]+$'; }
q6() { q AAAA "$@" | grep -Ei '^[0-9a-f:.]+$' | grep ':'; }
# True when a name has at least one A or AAAA record.
has_addr() { q4 "$1" | grep -q . || q6 "$1" | grep -q .; }
# True when the A/AAAA record of NAME is IP (forward confirmation of a PTR): fwd_confirms NAME IP
fwd_confirms() {
  if [[ $2 == *:* ]]; then q6 "$1" | grep -qix "$2"; else q4 "$1" | grep -qx "$2"; fi
}

alg_name() {
  case $1 in
    1) echo "RSAMD5 (obsolete)" ;;     3) echo "DSA (obsolete)" ;;
    6) echo "DSA-NSEC3-SHA1 (obsolete)" ;;  12) echo "ECC-GOST (obsolete)" ;;
    5) echo "RSASHA1 (deprecated)" ;;  7) echo "RSASHA1-NSEC3 (deprecated)" ;;
    8) echo "RSASHA256" ;;            10) echo "RSASHA512" ;;
    13) echo "ECDSAP256SHA256" ;;     14) echo "ECDSAP384SHA384" ;;
    15) echo "ED25519" ;;             16) echo "ED448" ;;
    *) echo "unknown" ;;
  esac
}

# Python helper: reads "flags proto alg key..." lines, prints "tag flags alg sha256 sha384 sha1".
read -r -d '' PY_DS <<'PY'
import sys, base64, hashlib, struct
owner = sys.argv[1].rstrip('.')
wire = b''.join(bytes([len(l)]) + l.lower().encode() for l in owner.split('.')) + b'\x00'
for line in sys.stdin:
    p = line.split()
    if len(p) < 4:
        continue
    flags, proto, alg = int(p[0]), int(p[1]), int(p[2])
    rdata = struct.pack('!HBB', flags, proto, alg) + base64.b64decode(''.join(p[3:]))
    acc = 0
    for i, b in enumerate(rdata):
        acc += b if i & 1 else b << 8
    acc += (acc >> 16) & 0xFFFF
    print(acc & 0xFFFF, flags, alg,
          hashlib.sha256(wire + rdata).hexdigest().upper(),
          hashlib.sha384(wire + rdata).hexdigest().upper(),
          hashlib.sha1(wire + rdata).hexdigest().upper())
PY

# Python helper (stdlib only): registration data via RDAP, falling back to WHOIS on port 43.
# Prints "key<TAB>value" lines: source, registrar, registrant, created, updated, expires,
# days_left, status.
read -r -d '' PY_REG <<'PY'
import sys, os, json, re, socket, time, datetime, urllib.request

domain = sys.argv[1].lower().rstrip('.')
tld = domain.rsplit('.', 1)[-1]
TIMEOUT = 8
MAX_BYTES = 4 << 20   # no answer is trusted to be small: read at most this much
out = {}

def cached_json(url):
    """JSON from url; kept in NDM_CACHE (when set) so the next run of this helper reuses it."""
    d = os.environ.get('NDM_CACHE')
    path = os.path.join(d, 'cache_' + url.rsplit('/', 1)[-1]) if d else None
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
        data = json.loads(r.read(MAX_BYTES))
    if path:
        with open(path, 'w') as f:
            json.dump(data, f)
    return data

def norm_date(s):
    """Return YYYY-MM-DD when the date can be parsed, else the raw string."""
    s = (s or '').strip()
    m = re.search(r'(\d{4})-(\d{2})-(\d{2})', s)
    if m:
        return '-'.join(m.groups())
    for fmt in ('%d-%b-%Y', '%d.%m.%Y', '%Y.%m.%d', '%d/%m/%Y', '%Y/%m/%d', '%Y%m%d'):
        try:
            return datetime.datetime.strptime(s.split()[0], fmt).strftime('%Y-%m-%d')
        except (ValueError, IndexError):
            pass
    return s

def vcard_name(ent):
    fn = org = ''
    for item in (ent.get('vcardArray') or [None, []])[1]:
        if item[0] == 'fn':
            fn = item[3]
        elif item[0] == 'org':
            org = item[3] if isinstance(item[3], str) else ' '.join(item[3])
    return (org or fn or '').strip()

def walk(entities):
    for e in entities or []:
        yield e
        yield from walk(e.get('entities'))

def rdap():
    boot = cached_json('https://data.iana.org/rdap/dns.json')
    base = next((urls[0] for tlds, urls in boot['services'] if tld in tlds), None)
    if not base:
        return False
    url = base.rstrip('/') + '/domain/' + domain
    req = urllib.request.Request(url, headers={'Accept': 'application/rdap+json'})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = json.loads(r.read(MAX_BYTES))
    events = {'registration': 'created', 'expiration': 'expires', 'last changed': 'updated'}
    for ev in data.get('events', []):
        key = events.get(ev.get('eventAction'))
        if key:
            out[key] = norm_date(ev.get('eventDate'))
    for e in walk(data.get('entities')):
        name = vcard_name(e)
        for role in ('registrar', 'registrant'):
            if role in e.get('roles', []) and name and role not in out:
                out[role] = name
    if data.get('status'):
        out['status'] = ', '.join(data['status'])
    out['source'] = 'RDAP ' + url.split('/')[2]
    return True

def whois_query(server, query):
    with socket.create_connection((server, 43), timeout=TIMEOUT) as s:
        s.sendall((query + '\r\n').encode())
        chunks, size, deadline = [], 0, time.monotonic() + 3 * TIMEOUT
        while size < MAX_BYTES and time.monotonic() < deadline:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
            size += len(b)
    return b''.join(chunks).decode('utf-8', 'replace')

FIELDS = [
    ('created', r'creation date|created(?: on| date)?|registered(?: on)?|registration (?:time|date)'),
    ('expires', r'registry expiry date|registrar registration expiration date|expir(?:y|ation|e)(?: date| time)?|paid-till|renewal date'),
    ('updated', r'updated date|last update(?:d)?(?: on)?|last modified'),
    ('status', r'domain status|status'),
    ('registrar', r'registrar(?: name)?|sponsoring registrar'),
    ('registrant', r'registrant(?: organi[sz]ation| name)?'),
]

def parse_whois(text):
    block = ''
    statuses = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(('%', '#', '>>>')):
            continue
        indented = raw[:1] in (' ', '\t')
        key, sep, val = line.partition(':')
        key, val = key.strip().lower(), val.strip()
        if not indented and (not sep or not val):
            block = key            # block header, e.g. "Registrant" or "Registrar:"
            continue
        if indented and block in ('registrant', 'holder', 'registrar'):
            field = 'registrar' if block == 'registrar' else 'registrant'
            if key in ('organization', 'organisation', 'org') and val:
                out[field] = val   # organization wins over a plain name
            elif (key == 'name' and val or not sep) and field not in out:
                out[field] = val if sep else line
            continue
        if not indented:
            block = ''
        for field, pattern in FIELDS:
            if sep and val and re.fullmatch(pattern, key):
                if field == 'status':
                    statuses.append(val.split()[0])
                elif field not in out:
                    out[field] = norm_date(val) if field in ('created', 'expires', 'updated') else val
                break
    if statuses:
        out['status'] = ', '.join(dict.fromkeys(statuses))

def whois():
    m = re.search(r'^whois:\s*(\S+)', whois_query('whois.iana.org', tld), re.M)
    if not m:
        return False
    server = m.group(1)
    parse_whois(whois_query(server, domain))
    out['source'] = 'WHOIS ' + server
    return True

try:
    found = rdap() and any(k in out for k in ('created', 'expires', 'registrar'))
except Exception:
    found = False
if not found:
    out.clear()
    try:
        whois()
    except Exception as exc:
        out['error'] = str(exc)

if re.fullmatch(r'\d{4}-\d{2}-\d{2}', out.get('expires', '')):
    left = datetime.date.fromisoformat(out['expires']) - datetime.date.today()
    out['days_left'] = str(left.days)

for k, v in out.items():
    print(f'{k}\t{" ".join(str(v).split())}')
PY

# Python helper: converts an openssl date ("Dec 13 08:50:58 2026 GMT") to "YYYY-MM-DD days_left".
read -r -d '' PY_DAYS <<'PY'
import sys, datetime
d = datetime.datetime.strptime(' '.join(sys.argv[1].split()), '%b %d %H:%M:%S %Y %Z')
now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
print(d.strftime('%Y-%m-%d'), (d - now).days)
PY

# Python helper (stdlib only): names seen in Certificate Transparency logs (crt.sh).
# Prints "summary<TAB>total<TAB>current" then "row<TAB>name<TAB>last_expiry<TAB>current<TAB>ip"
# lines (current first), or "error<TAB>message".
read -r -d '' PY_CT <<'PY'
import sys, json, socket, datetime, urllib.parse, urllib.request
import concurrent.futures as cf

domain = sys.argv[1].lower().rstrip('.')
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 40
url = 'https://crt.sh/?' + urllib.parse.urlencode({'q': '%.' + domain, 'output': 'json'})
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'ndm_domain-health-check'})
    with urllib.request.urlopen(req, timeout=45) as r:
        certs = json.loads(r.read(64 << 20))
except Exception as e:
    print(f'error\t{e}')
    sys.exit()

# Keep, for each name, the latest expiry date among its certificates.
names = {}
for c in certs:
    expiry = (c.get('not_after') or '')[:10]
    for n in (c.get('name_value') or '').lower().split('\n'):
        n = n.strip().rstrip('.')
        if n and (n == domain or n.endswith('.' + domain)) and expiry > names.get(n, ''):
            names[n] = expiry

today = datetime.date.today().isoformat()
current = {n for n, exp in names.items() if exp >= today}
ordered = sorted(names, key=lambda n: (n not in current, n.lstrip('*.'), n))[:limit]

def resolve(name):
    if name.startswith('*.'):
        return '*'
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.getaddrinfo(name, None, family)[0][4][0]
        except OSError:
            continue
    return '-'

with cf.ThreadPoolExecutor(max_workers=16) as ex:
    ips = list(ex.map(resolve, ordered))

print(f'summary\t{len(names)}\t{len(current)}')
for n, ip in zip(ordered, ips):
    print(f'row\t{n}\t{names[n]}\t{int(n in current)}\t{ip}')
PY

# IP owner data (PY_IPINFO output), looked up once per IP and reused by several sections.
ipinfo_cache=""
ipinfo_fetch() {
  local need=() ip
  for ip in "$@"; do
    awk -F'\t' -v ip="$ip" '$1 == ip {f = 1} END {exit !f}' <<<"$ipinfo_cache" || need+=("$ip")
  done
  if ((${#need[@]})) && have python3; then
    ipinfo_cache+=$'\n'$(NDM_CACHE=${tmpdir:-} python3 -I -c "$PY_IPINFO" "${need[@]}" </dev/null 2>/dev/null)
  fi
}
# One-line owner summary: "org (netname) · ASn name · country".
ip_owner_summary() {
  local _ip network bgp netname org country rir asn asname abuse out=""
  IFS=$'\t' read -r _ip network bgp netname org country rir asn asname abuse \
    < <(awk -F'\t' -v ip="$1" '$1 == ip {print; exit}' <<<"$ipinfo_cache")
  [[ -n ${org:-} && $org != - ]] && out=$org
  [[ -n ${netname:-} && $netname != - ]] && out+="${out:+ }($netname)"
  [[ -n ${asn:-} && $asn != - ]] && out+="${out:+ · }AS$asn${asname:+ ${asname#-}}"
  [[ -n ${country:-} && $country != - ]] && out+="${out:+ · }$country"
  printf '%s' "$out"
}

# Value of a key from the PY_REG output stored in $reg.
regval() { printf '%s\n' "${reg:-}" | awk -F'\t' -v k="$1" '$1 == k {print $2; exit}'; }

# Python helper (stdlib only): TLS and mail-port probes, run in parallel.
# Args: optional "--mail" (adds a summary for mail client ports), then specs
# "kind|host|port|label" with kind in: tls, smtp, submission, imap, pop, legacy.
# Prints "level<TAB>label<TAB>message" lines.
read -r -d '' PY_PROBE <<'PY'
import sys, os, re, ssl, socket, smtplib, imaplib, poplib, ipaddress, datetime, time, warnings
import concurrent.futures as cf

warnings.filterwarnings('ignore', category=DeprecationWarning)  # TLS 1.0/1.1 test is intentional

TIMEOUT = 6
socket.setdefaulttimeout(TIMEOUT)
# Name -> addresses checked by the shell (NDM_PIN="host=ip,ip ..."): connections go only there.
PINS = {}
for _item in os.environ.get('NDM_PIN', '').split():
    _h, _, _ips = _item.partition('=')
    PINS[_h.lower()] = _ips.split(',')
_resolve = socket.getaddrinfo

def _pinned(host, port, *args, **kw):
    ips = PINS.get(str(host).lower())
    if ips is None:
        raise socket.gaierror(socket.EAI_NONAME, 'not verified as public')
    return [r for ip in ips for r in _resolve(ip, port, *args, **kw)]

if PINS:
    socket.getaddrinfo = _pinned
NOW = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
_paths = ssl.get_default_verify_paths()
HAS_CA = bool(os.environ.get('SSL_CERT_FILE') or _paths.cafile
              or (_paths.capath and os.path.isdir(_paths.capath) and os.listdir(_paths.capath)))
RANK = {'ok': 0, 'info': 1, 'tip': 1, 'warn': 2, 'fail': 3}

def worst(a, b):
    return a if RANK[a] >= RANK[b] else b

def loose_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

def strict_ctx():
    return ssl.create_default_context() if HAS_CA else loose_ctx()

def cert_error(e):
    return getattr(e, 'verify_message', None) or getattr(e, 'reason', None) or str(e)

def tls_summary(sock, host, port, mode=''):
    """Grade the negotiated protocol and certificate lifetime."""
    ver = sock.version() or 'TLS'
    lvl, msg = 'ok', f'{host}:{port} {mode}{ver}'
    if ver in ('SSLv3', 'TLSv1', 'TLSv1.1'):
        lvl, msg = 'fail', msg + ' (obsolete protocol)'
    cert = sock.getpeercert() if HAS_CA else {}
    if cert and cert.get('notAfter'):
        exp = datetime.datetime.strptime(' '.join(cert['notAfter'].split()), '%b %d %H:%M:%S %Y %Z')
        days = (exp - NOW).days
        if days < 0:
            lvl, msg = 'fail', msg + ', certificate EXPIRED'
        elif days < 14:
            lvl, msg = worst(lvl, 'warn'), msg + f', certificate expires in {days} days'
        else:
            msg += f', valid certificate ({days} days left)'
    elif not HAS_CA:
        msg += ', certificate not verified (Python has no CA store)'
    return lvl, msg

# Each probe returns a list of (level, label, message, reachable).

def p_tls(host, port, label):
    try:
        with socket.create_connection((host, port)) as raw, \
             strict_ctx().wrap_socket(raw, server_hostname=host) as s:
            lvl, msg = tls_summary(s, host, port)
            return [(lvl, label, msg, True)]
    except ssl.SSLCertVerificationError as e:
        return [('fail', label, f'{host}:{port} certificate NOT valid: {cert_error(e)}', True)]
    except ssl.SSLError as e:
        return [('fail', label, f'{host}:{port} TLS handshake failed: {cert_error(e)}', True)]
    except OSError:
        return [('info', label, f'{host}:{port} closed or unreachable', False)]

# Mail servers may delay their greeting on purpose (anti-spam): wait longer than for TLS.
SMTP_TIMEOUT = 20

def smtp_extras(s, banner, host, port, label):
    """Banner name against the server's names, software version, VRFY/EXPN, size limit."""
    rows = []
    welcome = banner.decode('utf-8', 'replace') if isinstance(banner, bytes) else str(banner)
    first = ' '.join(welcome.split())
    name = (first.split() or [''])[0].lower().rstrip('.')
    ptr = ''
    try:
        ptr = socket.gethostbyaddr(s.sock.getpeername()[0])[0].lower().rstrip('.')
    except OSError:
        pass
    known = {host.lower().rstrip('.'), ptr} - {''}
    if '.' in name and name not in known:
        rows.append(('tip', label, f'{host}:{port} the banner announces "{name}", the server is {host}'
                     + (f' (PTR {ptr})' if ptr else '') + ': receivers compare these names', True))
    m = re.search(r'(Exim|Sendmail|Postfix|qmail|Courier|MailEnable|Dovecot|Microsoft ESMTP MAIL Service)'
                  r'[ ,/-]+(?:Version:? )?v?(\d+\.\d+[\d.]*)', first, re.I)
    if m:
        rows.append(('tip', label, f'{host}:{port} the banner reveals the software version ({m.group(1)} {m.group(2)})', True))
    size = s.esmtp_features.get('size', '')
    if size.isdigit() and int(size) > 0:
        rows.append(('info', label, f'{host}:{port} accepts messages up to {int(size) // 1048576} MB', True))
    try:
        code, _ = s.docmd('VRFY', 'postmaster')
        if code in (250, 251):
            rows.append(('tip', label, f'{host}:{port} VRFY confirms mailboxes: spammers use it to collect addresses', True))
        code, _ = s.docmd('EXPN', 'postmaster')
        if code in (250, 251):
            rows.append(('warn', label, f'{host}:{port} EXPN lists the members of mailing lists to anyone', True))
    except (OSError, smtplib.SMTPException):
        pass
    return rows

def p_weakc(host, port, label):
    """Does a server accept old or non-forward-secret cipher suites (TLS 1.2 and below)?"""
    tests = [('3DES', '3DES:!aNULL:!eNULL', 'warn', 'accepts 3DES (Sweet32)'),
             ('RC4', 'RC4:!aNULL:!eNULL', 'warn', 'accepts RC4'),
             ('export/NULL/anonymous', 'EXPORT:eNULL:aNULL:LOW', 'warn', 'accepts export, NULL or anonymous suites'),
             ('no forward secrecy', 'kRSA:!aNULL:!eNULL', 'tip', 'accepts suites without forward secrecy (plain RSA key exchange)')]
    rows, untested, tested = [], [], 0
    for name, spec, lvl, text in tests:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(spec + ':@SECLEVEL=0')
        except (ValueError, ssl.SSLError):
            untested.append(name)
            continue
        try:
            with socket.create_connection((host, port)) as raw, ctx.wrap_socket(raw, server_hostname=host):
                tested += 1
                rows.append((lvl, label, f'{host}:{port} {text}', False))
        except ssl.SSLError:
            tested += 1
        except OSError:
            return []
    if not rows and tested:
        rows.append(('ok', label, f'{host}:{port} refuses 3DES, RC4, export/NULL/anonymous suites'
                     + (f' (not testable here: {", ".join(untested)})' if untested else ''), False))
    elif not tested:
        rows.append(('info', label, 'cannot test: the local OpenSSL has these cipher suites disabled', False))
    return rows

class BannerSMTP(smtplib.SMTP):
    """SMTP that keeps the greeting text (the standard class drops it)."""
    banner = b''

    def connect(self, host='localhost', port=0, source_address=None):
        code, msg = super().connect(host, port, source_address)
        self.banner = msg
        return code, msg

def p_smtp(host, port, label, submission):
    note = ' (port 25 is often blocked by ISPs)' if port == 25 else ''
    try:
        s = BannerSMTP(host, port, local_hostname='domain-health-check.invalid', timeout=SMTP_TIMEOUT)
    except smtplib.SMTPConnectError as e:
        text = e.smtp_error.decode('utf-8', 'replace') if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        return [('info', label, f'{host}:{port} server refused the connection: {e.smtp_code} '
                 f'{" ".join(text.split())[:80]} (your IP may be on a blocklist it uses)', False)]
    except ConnectionRefusedError:
        return [('info', label, f'{host}:{port} closed (connection refused){note}', False)]
    except (socket.timeout, TimeoutError):
        return [('info', label, f'{host}:{port} no greeting within {SMTP_TIMEOUT} s{note}', False)]
    except (OSError, smtplib.SMTPException) as e:
        return [('info', label, f'{host}:{port} not reachable: {e}{note}', False)]
    res = []
    try:
        s.ehlo()
        auth_before_tls = s.has_extn('auth')
        if not submission and port == 25:
            res.extend(smtp_extras(s, s.banner, host, port, label))
        if not s.has_extn('starttls'):
            return [('fail', label, f'{host}:{port} no STARTTLS: traffic is NOT encrypted', True)]
        try:
            s.starttls(context=strict_ctx())
            lvl, msg = tls_summary(s.sock, host, port, 'STARTTLS ')
            res.append((lvl, label, msg, True))
        except ssl.SSLCertVerificationError as e:
            # Between mail servers TLS is opportunistic: a bad certificate is a warning there.
            lvl = 'fail' if submission else 'warn'
            res.append((lvl, label, f'{host}:{port} STARTTLS, but certificate NOT valid: {cert_error(e)}', True))
        if submission and auth_before_tls:
            res.append(('warn', label, 'login offered BEFORE STARTTLS: passwords could travel in clear', True))
    except (OSError, smtplib.SMTPException) as e:
        res.append(('warn', label, f'{host}:{port} SMTP error: {e}', True))
    finally:
        try:
            s.quit()
        except Exception:
            s.close()
    return res

def p_imap(host, port, label):
    try:
        m = imaplib.IMAP4(host, port)
    except (OSError, imaplib.IMAP4.error):
        return [('ok', label, f'{host}:{port} closed (plain IMAP not exposed)', False)]
    caps = {c.upper() for c in m.capabilities}
    try:
        m.logout()
    except Exception:
        pass
    if 'STARTTLS' not in caps:
        return [('fail', label, f'{host}:{port} open WITHOUT STARTTLS: passwords travel in clear', True)]
    if 'LOGINDISABLED' in caps:
        return [('tip', label, f'{host}:{port} open, login only after STARTTLS (prefer 993)', True)]
    return [('warn', label, f'{host}:{port} STARTTLS available, but plaintext login is allowed', True)]

def p_pop(host, port, label):
    try:
        p = poplib.POP3(host, port)
    except (OSError, poplib.error_proto):
        return [('ok', label, f'{host}:{port} closed (plain POP3 not exposed)', False)]
    try:
        caps = {k.upper(): [v.upper() for v in vals] for k, vals in p.capa().items()}
    except poplib.error_proto:
        caps = None
    try:
        p.quit()
    except Exception:
        pass
    if caps is None:
        return [('warn', label, f'{host}:{port} open, capabilities unknown (cannot verify encryption)', True)]
    if 'STLS' not in caps:
        return [('fail', label, f'{host}:{port} open WITHOUT STARTTLS: passwords travel in clear', True)]
    if 'USER' in caps or {'PLAIN', 'LOGIN'} & set(caps.get('SASL', [])):
        return [('warn', label, f'{host}:{port} STARTTLS available, but plaintext login is allowed', True)]
    return [('tip', label, f'{host}:{port} open, login only after STARTTLS (prefer 995)', True)]

def p_legacy(host, port, label):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except (ValueError, ssl.SSLError):
        return [('info', label, 'cannot test: local OpenSSL has TLS 1.0/1.1 disabled', False)]
    try:
        with socket.create_connection((host, port)) as raw, \
             ctx.wrap_socket(raw, server_hostname=host) as s:
            return [('warn', label, f'{host}:{port} still accepts {s.version()} (obsolete)', True)]
    except ssl.SSLError as e:
        if 'NO_PROTOCOLS_AVAILABLE' in str(getattr(e, 'reason', '')).upper():
            return [('info', label, 'cannot test: local OpenSSL has TLS 1.0/1.1 disabled', False)]
        return [('ok', label, f'{host}:{port} TLS 1.0/1.1 refused', True)]
    except OSError:
        return []

PROBES = {
    'tls': p_tls,
    'smtp': lambda h, p, l: p_smtp(h, p, l, False),
    'submission': lambda h, p, l: p_smtp(h, p, l, True),
    'imap': p_imap,
    'pop': p_pop,
    'legacy': p_legacy,
    'weakc': p_weakc,
}

def run(spec):
    kind, host, port, label = spec.split('|', 3)
    if PINS and host.lower() not in PINS:
        return [('info', label, f'{host}:{port} not contacted: it does not resolve to public addresses only', False)]
    try:
        # The names under test come from the audited domain's DNS: never probe a private address.
        if not all(ipaddress.ip_address(a[4][0].split('%')[0]).is_global
                   for a in socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)):
            return [('info', label, f'{host}:{port} not contacted: it resolves to a non-public address', False)]
    except OSError:
        pass
    try:
        return PROBES[kind](host, int(port), label)
    except Exception as e:  # never let one probe break the report
        return [('warn', label, f'{host}:{port} probe error: {e}', False)]

args = sys.argv[1:]
mail_mode = bool(args) and args[0] == '--mail'
specs = args[1:] if mail_mode else args
# Socket timeouts apply to each read: a server that sends a byte every few seconds would keep
# a probe alive forever. One overall deadline for all probes; stuck threads are abandoned.
DEADLINE = time.time() + 60
ex = cf.ThreadPoolExecutor(max_workers=8)
futures = [ex.submit(run, spec) for spec in specs]
results = []
for spec, fut in zip(specs, futures):
    try:
        results.append(fut.result(timeout=max(0.1, DEADLINE - time.time())))
    except cf.TimeoutError:
        _, t_host, t_port, t_label = spec.split('|', 3)
        results.append([('warn', t_label, f'{t_host}:{t_port} no complete answer within 60 s '
                         '(slow or unresponsive server)', False)])

rows = [r for res in results for r in res]
client_rows = [r for spec, res in zip(specs, results) if spec.split('|')[2] != '25' for r in res]
if mail_mode and client_rows and not any(r[3] for r in client_rows):
    host = specs[-1].split('|')[1]
    rows = [r for r in rows if r not in client_rows]
    rows.append(('info', 'Mail client ports', f'{host}: no port reachable from here', False))
elif mail_mode and client_rows:
    def secure(label):
        return any(r[1] == label and r[3] and r[0] in ('ok', 'warn') for r in client_rows)
    if not (secure('SMTPS 465') or secure('Submission 587')):
        rows.append(('fail', 'Sending (clients)', 'no working encrypted port (465 or 587)', True))
    if not (secure('IMAPS 993') or secure('POP3S 995')):
        rows.append(('fail', 'Reading (clients)', 'no working encrypted port (993 or 995)', True))

for lvl, label, msg, _ in rows:
    print(f'{lvl}\t{label}\t{msg}')
sys.stdout.flush()
os._exit(0)  # do not wait for probes that are still stuck
PY

# Python helper: recursive SPF analysis through dig.
# Args: domain resolver [ip=label ...] (the domain's own web/mail IPs).
# Prints "row<TAB>depth<TAB>term<TAB>description" (tree), "sender<TAB>kind<TAB>name<TAB>provider",
# "direct<TAB>network<TAB>matching labels<TAB>ptr", "covered<TAB>ip<TAB>label<TAB>0|1" and a final
# "total<TAB>dns_lookups<TAB>void_lookups" line (RFC 7208 limits: 10 lookups, 2 void lookups).
read -r -d '' PY_SPF <<'PY'
import sys, os, re, subprocess, ipaddress

domain, resolver = sys.argv[1].lower().rstrip('.'), sys.argv[2]
known = {}
for item in sys.argv[3:]:
    ip, _, label = item.partition('=')
    known.setdefault(ip, set()).add(label)
all_nets, direct, senders = [], [], []

def add_net(text):
    try:
        all_nets.append(ipaddress.ip_network(text, strict=False))
    except ValueError:
        pass
# Labels for SPF includes come only from the user (SPF_PROVIDERS, "text=Label; ...").
KNOWN = [tuple(x.strip() for x in item.split('=', 1))
         for item in os.environ.get('NDM_SPF_PROVIDERS', '').split(';') if '=' in item]
QUAL = {'+': 'pass', '-': 'fail (hard)', '~': 'softfail', '?': 'neutral'}
MAX_NETS = 4
# A hostile or oversized tree must not run forever: stop after this many records.
MAX_NODES = 50
MAX_MX = 10
lookups = voids = loops = nodes = 0
rows = []

_cache = {}

def dig(rtype, name):
    # Names come from the audited domain's DNS: "-f FILE" would be read by dig as an option.
    if not re.fullmatch(r'[A-Za-z0-9_*][A-Za-z0-9_*.-]*', name):
        return []
    key = (rtype, name.lower())
    if key not in _cache:
        try:
            out = subprocess.run(['dig', '+short', '+time=3', '+tries=2', rtype, name, '@' + resolver],
                                 capture_output=True, text=True, timeout=20).stdout
        except Exception:
            out = ''
        _cache[key] = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(';')]
    return _cache[key]

def spf_records(name):
    recs = []
    for line in dig('TXT', name):
        value = re.sub(r'"\s*"', '', line).strip('"')
        if value.lower().startswith('v=spf1'):
            recs.append(value)
    return recs

def provider(name):
    return next((label for key, label in KNOWN if key in name.lower()), '')

def ipv4s(name):
    return [x for x in dig('A', name) if re.fullmatch(r'[\d.]+', x)]

def ipv6s(name):
    return [x for x in dig('AAAA', name) if ':' in x]

def split_cidr(text):
    """'host/24//64' -> ('host', 24, 64); the lengths default to the whole address."""
    m = re.fullmatch(r'([^/]*)(?:/(\d+))?(?://(\d+))?', text)
    if not m:
        return text, 32, 128
    return m.group(1), int(m.group(2) or 32), int(m.group(3) or 128)

def add_hosts(name, c4, c6):
    """Authorize the addresses of a host; returns them (IPv4 first)."""
    v4, v6 = ipv4s(name), ipv6s(name)
    for ip in v4:
        add_net(f'{ip}/{c4}')
    for ip in v6:
        add_net(f'{ip}/{c6}')
    return v4 + v6

def emit(depth, term, desc=''):
    rows.append((depth, term, desc))

def walk(name, depth, seen):
    global lookups, voids, loops, nodes
    nodes += 1
    if nodes > MAX_NODES:
        if nodes == MAX_NODES + 1:
            emit(depth, '(analysis stopped)', f'more than {MAX_NODES} records: tree too large')
        return
    recs = spf_records(name)
    if not recs:
        voids += 1
        emit(depth, '(no SPF record)', 'void lookup')
        return
    if len(recs) > 1:
        emit(depth, f'({len(recs)} SPF records)', 'permerror: only one is allowed')
    terms = recs[0].split()[1:]
    nets = [t for t in terms if re.match(r'^[+?~-]?ip[46]:', t, re.I)]
    collapse, nets_shown = len(nets) > MAX_NETS, False
    for t in terms:
        m = re.match(r'^([+?~-]?)([a-z0-9]+)(.*)$', t, re.I)
        if not m:
            emit(depth, t, 'unrecognized term')
            continue
        qual, mech, rest = m.group(1) or '+', m.group(2).lower(), m.group(3)
        arg = rest[1:] if rest[:1] in (':', '=') else ''
        host, c4, c6 = split_cidr(arg + (rest if rest[:1] == '/' else ''))
        target = (host or name).rstrip('.').lower()
        if mech in ('ip4', 'ip6'):
            add_net(arg)
            if depth == 0:
                direct.append(arg)
            if not collapse:
                emit(depth, t)
            elif not nets_shown:
                n4 = sum(1 for x in nets if x.lstrip('+?~-').lower().startswith('ip4'))
                emit(depth, f'{n4} IPv4 + {len(nets) - n4} IPv6 ranges')
                nets_shown = True
        elif mech in ('include', 'redirect'):
            lookups += 1
            emit(depth, t, provider(target))
            if depth == 0:
                senders.append((mech, target, provider(target)))
            if target in seen:
                loops += 1
                emit(depth + 1, '(loop)', 'permerror')
            elif depth < 10:
                walk(target, depth + 1, seen | {target})
        elif mech == 'a':
            lookups += 1
            ips = add_hosts(target, c4, c6)
            if depth == 0:
                senders.append(('a', target, ''))
            if not ips:
                voids += 1
            emit(depth, t, '-> ' + ', '.join(ips[:3]) if ips else 'no address (void lookup)')
        elif mech == 'mx':
            lookups += 1
            hosts = [h.split()[-1].rstrip('.') for h in dig('MX', target)][:MAX_MX]
            if not hosts:
                voids += 1
                emit(depth, t, 'no MX (void lookup)')
            else:
                if depth == 0:
                    senders.append(('mx', target, ''))
                parts = []
                for h in hosts:
                    ips = add_hosts(h, c4, c6)
                    if len(parts) < 3:
                        parts.append(f'{h} ({ips[0]})' if ips else h)
                emit(depth, t, '-> ' + ', '.join(parts))
        elif mech == 'ptr':
            lookups += 1
            emit(depth, t, 'deprecated by RFC 7208: remove it')
        elif mech == 'exists':
            lookups += 1
            emit(depth, t)
        elif mech == 'all' and depth == 0:
            emit(depth, t, f'{QUAL.get(qual, "")} for every other server')
        elif mech in ('all', 'exp'):
            continue
        else:
            emit(depth, t, 'unknown mechanism')

walk(domain, 0, {domain})
for depth, term, desc in rows:
    print(f'row\t{depth}\t{term}\t{desc}')
for kind, name, label in senders:
    print(f'sender\t{kind}\t{name}\t{label}')

# Direct networks: which of the domain's own IPs they contain, and the PTR of single hosts.
for net_text in direct:
    try:
        net = ipaddress.ip_network(net_text, strict=False)
    except ValueError:
        continue
    labels = sorted({lab for ip, labs in known.items() for lab in labs
                     if ipaddress.ip_address(ip).version == net.version and ipaddress.ip_address(ip) in net})
    ptr = ''
    if net.num_addresses == 1:
        out = subprocess.run(['dig', '+short', '+time=3', '+tries=1', '-x', str(net.network_address),
                              '@' + resolver], capture_output=True, text=True, timeout=15).stdout.split()
        ptr = out[0].rstrip('.') if out and not out[0].startswith(';') else ''
    shown = str(net) if net.version == 6 else net_text
    print(f'direct\t{shown}\t{", ".join(labels) or "-"}\t{ptr or "-"}')

# Coverage: is each of the domain's own IPs authorized anywhere in the tree?
for ip, labs in known.items():
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        continue
    covered = any(n.version == addr.version and addr in n for n in all_nets)
    print(f'covered\t{ip}\t{", ".join(sorted(labs))}\t{int(covered)}')
print(f'total\t{lookups}\t{voids}')
print(f'loops\t{loops}')
PY

# Python helper (stdlib only): IP ownership via RDAP (IANA bootstrap) and the origin ASN
# via RIPEstat (RIPE NCC).
# Args: resolver ip ... ; prints one line per IP, tab separated, '-' for unknown fields:
# ip, network, bgp_prefix, netname, org, country, rir, asn, as_name, abuse
read -r -d '' PY_IPINFO <<'PY'
import sys, os, json, ipaddress, urllib.request
import concurrent.futures as cf

ips = list(dict.fromkeys(sys.argv[1:]))
TIMEOUT = 10
MAX_BYTES = 4 << 20
# Registry of each RDAP server, for the "rir" field.
RIRS = {'arin': 'ARIN', 'ripe': 'RIPE NCC', 'apnic': 'APNIC', 'lacnic': 'LACNIC', 'afrinic': 'AFRINIC'}

def fetch(url, accept='application/rdap+json'):
    req = urllib.request.Request(url, headers={'Accept': accept,
                                               'User-Agent': 'ndm_domain-health-check'})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read(MAX_BYTES))

def bootstrap(version):
    """IANA bootstrap file, shared between runs through NDM_CACHE (when set)."""
    d = os.environ.get('NDM_CACHE')
    path = os.path.join(d, f'cache_ipv{version}.json') if d else None
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    data = fetch(f'https://data.iana.org/rdap/ipv{version}.json')
    if path:
        with open(path, 'w') as f:
            json.dump(data, f)
    return data

boots = {}
for version in (4, 6):
    try:
        boots[version] = bootstrap(version)
    except Exception:
        boots[version] = None

def rdap_base(addr):
    """Most specific RDAP service for the address, from the IANA bootstrap file."""
    boot, best = boots.get(addr.version), None
    for prefixes, urls in (boot or {}).get('services', []):
        for prefix in prefixes:
            net = ipaddress.ip_network(prefix)
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, urls)
    if not best:
        return None
    return next((u for u in best[1] if u.startswith('https')), best[1][0])

def vcard(ent, field):
    for item in (ent.get('vcardArray') or [None, []])[1]:
        if item[0] == field:
            v = item[3]
            return v if isinstance(v, str) else ' '.join(map(str, v))
    return ''

def walk(entities):
    for e in entities or []:
        yield e
        yield from walk(e.get('entities'))

def lookup(ip):
    r = dict.fromkeys(['network', 'bgp', 'netname', 'org', 'country', 'rir', 'asn', 'asname', 'abuse'], '')
    addr = ipaddress.ip_address(ip)
    # RIPEstat (RIPE NCC, a non-profit): announced BGP prefix and origin ASN, any region.
    try:
        d = fetch('https://stat.ripe.net/data/prefix-overview/data.json'
                  f'?resource={ip}&sourceapp=ndm_domain-health-check', 'application/json').get('data') or {}
        if d.get('announced'):
            r['bgp'] = d.get('resource') or ''
            asns = d.get('asns') or []
            if asns:
                r['asn'] = str(asns[0].get('asn', ''))
                r['asname'] = asns[0].get('holder') or ''
    except Exception:
        pass
    try:
        base = rdap_base(addr)
        if base:
            d = fetch(base.rstrip('/') + '/ip/' + ip)
            cidrs = d.get('cidr0_cidrs') or []
            if cidrs:
                c = cidrs[0]
                r['network'] = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
            elif d.get('startAddress'):
                r['network'] = f"{d['startAddress']} - {d.get('endAddress', '')}"
            r['netname'] = d.get('name') or ''
            r['country'] = d.get('country') or r['country']
            for e in walk(d.get('entities')):
                roles = e.get('roles', [])
                if 'abuse' in roles and not r['abuse']:
                    r['abuse'] = vcard(e, 'email')
                elif 'registrant' in roles and not r['org']:
                    r['org'] = vcard(e, 'fn')
            if not r['org']:  # some registries only list other roles
                r['org'] = next((vcard(e, 'fn') for e in walk(d.get('entities'))
                                 if 'abuse' not in e.get('roles', []) and vcard(e, 'fn')), '')
            host = base.split('/')[2]
            r['rir'] = next((v for k, v in RIRS.items() if k in host), host)
    except Exception:
        pass
    return r

with cf.ThreadPoolExecutor(max_workers=6) as ex:
    results = list(ex.map(lookup, ips))
for ip, r in zip(ips, results):
    fields = [r[k] or '-' for k in ('network', 'bgp', 'netname', 'org', 'country', 'rir', 'asn', 'asname', 'abuse')]
    print('\t'.join([ip] + [' '.join(f.split()) for f in fields]))
PY

# Python helper: hours left until a DNSSEC signature expiration (YYYYMMDDHHMMSS, UTC).
read -r -d '' PY_SIGLEFT <<'PY'
import sys, datetime
exp = datetime.datetime.strptime(sys.argv[1], '%Y%m%d%H%M%S')
now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
print(exp.strftime('%Y-%m-%d %H:%M UTC'), int((exp - now).total_seconds() // 3600))
PY

# Python helper (stdlib only): does a TLSA record match the certificate that a mail server shows
# on port 25 after STARTTLS? Args: host. Reads "usage selector matching hex" lines from stdin and
# prints "level<TAB>label<TAB>message" lines.
read -r -d '' PY_DANE <<'PY'
import sys, os, ssl, socket, smtplib, hashlib

# Name -> addresses checked by the shell (NDM_PIN="host=ip,ip ..."): connections go only there.
PINS = {}
for _item in os.environ.get('NDM_PIN', '').split():
    _h, _, _ips = _item.partition('=')
    PINS[_h.lower()] = _ips.split(',')
_resolve = socket.getaddrinfo

def _pinned(host, port, *args, **kw):
    ips = PINS.get(str(host).lower())
    if ips is None:
        raise socket.gaierror(socket.EAI_NONAME, 'not verified as public')
    return [r for ip in ips for r in _resolve(ip, port, *args, **kw)]

if PINS:
    socket.getaddrinfo = _pinned

def tlv(b, i):
    tag, n = b[i], b[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[j:j + k], 'big')
        j += k
    return tag, j, n

def children(b, start, end):
    i = start
    while i < end:
        tag, v, n = tlv(b, i)
        yield tag, i, v, v + n
        i = v + n

def spki(der):
    """SubjectPublicKeyInfo of an X.509 certificate, as DER."""
    _, v, n = tlv(der, 0)
    _, tbs_v, tbs_n = tlv(der, v)
    kids = list(children(der, tbs_v, tbs_v + tbs_n))
    skip = 1 if kids[0][0] == 0xA0 else 0         # optional explicit version
    _, start, _, end = kids[skip + 5]             # serial, signature, issuer, validity, subject, SPKI
    return der[start:end]

host = sys.argv[1]
label = f'DANE {host}'
records = [l.split() for l in sys.stdin if len(l.split()) == 4]
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = smtplib.SMTP(host, 25, local_hostname='domain-health-check.invalid', timeout=20)
    s.ehlo()
    s.starttls(context=ctx)
    der = s.sock.getpeercert(binary_form=True)
    s.close()
    data = {'0': der, '1': spki(der)}
except Exception as e:
    print(f'info\t{label}\tcannot check the TLSA records against the certificate: {e}')
    sys.exit()
hashes = {'0': lambda x: x, '1': lambda x: hashlib.sha256(x).digest(), '2': lambda x: hashlib.sha512(x).digest()}
matched = unchecked = 0
for usage, selector, mtype, hexdata in records:
    if usage not in ('1', '3'):
        unchecked += 1                            # CA-type records need the whole chain
        continue
    if selector in data and mtype in hashes and hashes[mtype](data[selector]).hex() == hexdata.lower():
        matched += 1
if matched:
    print(f'ok\t{label}\ta TLSA record matches the certificate shown on port 25')
elif unchecked == len(records):
    print(f'info\t{label}\tthe TLSA records are of the trust-anchor type (usage 0/2): not checked here')
else:
    print(f'fail\t{label}\tNO TLSA record matches the certificate shown on port 25: senders that use DANE will refuse to deliver')
PY

# Python helper (stdlib only): size of DKIM public keys. Reads "selector<TAB>type<TAB>base64"
# lines, prints "selector<TAB>type<TAB>bits" (type: rsa, ed25519 or unknown).
read -r -d '' PY_DKIM <<'PY'
import sys, base64

def tlv(b, i):
    """DER element at i: (tag, start of the value, length of the value)."""
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], 'big')
        i += k
    return tag, i, n

for line in sys.stdin:
    sel, kind, b64 = line.rstrip('\n').split('\t')
    try:
        raw = base64.b64decode(b64 + '=' * (-len(b64) % 4))
        if kind.lower() == 'ed25519':
            print(f'{sel}\ted25519\t{len(raw) * 8}')
            continue
        _, i, _ = tlv(raw, 0)           # SubjectPublicKeyInfo
        _, j, n = tlv(raw, i)           # AlgorithmIdentifier
        _, k, _ = tlv(raw, j + n)       # BIT STRING (first byte: unused bits)
        _, m, _ = tlv(raw, k + 1)       # RSAPublicKey
        _, v, n = tlv(raw, m)           # modulus
        mod = raw[v:v + n].lstrip(b'\0')
        print(f'{sel}\trsa\t{(len(mod) - 1) * 8 + mod[0].bit_length()}')
    except Exception:
        print(f'{sel}\tunknown\t0')
PY

# ----------------------------------------------------------------- setup ----
REQUIRED_TOOLS="dig"
OPTIONAL_TOOLS="python3 delv openssl curl ping"

# Package that provides a tool, for a given package manager.
pkg_for() {
  local pm=$1 tool=$2
  case $tool in
    dig|delv)
      case $pm in
        apt) echo dnsutils ;; dnf|yum|zypper) echo bind-utils ;; pacman|brew) echo bind ;;
        apk) echo bind-tools ;;
      esac ;;
    python3) case $pm in pacman|brew) echo python ;; *) echo python3 ;; esac ;;
    ping)
      case $pm in
        apt) echo iputils-ping ;; dnf|yum|zypper|pacman) echo iputils ;; apk) echo iputils ;;
        brew) echo "" ;;  # macOS ships ping
      esac ;;
    *) echo "$tool" ;;
  esac
}

# Install command for a package manager and a list of tools (deduplicated packages).
install_cmd() {
  local pm=$1; shift
  local pkgs="" t p
  for t in "$@"; do
    p=$(pkg_for "$pm" "$t")
    [[ -n $p && " $pkgs " != *" $p "* ]] && pkgs+="${pkgs:+ }$p"
  done
  [[ -z $pkgs ]] && return
  case $pm in
    apt) echo "sudo apt install $pkgs" ;;      dnf) echo "sudo dnf install $pkgs" ;;
    yum) echo "sudo yum install $pkgs" ;;      zypper) echo "sudo zypper install $pkgs" ;;
    pacman) echo "sudo pacman -S $pkgs" ;;     apk) echo "sudo apk add $pkgs" ;;
    brew) echo "brew install $pkgs" ;;
  esac
}

detect_pm() {
  local pm
  for pm in apt-get dnf yum zypper pacman apk brew; do
    if have "$pm"; then echo "${pm%-get}"; return; fi
  done
}

# Explain what is missing and how to install it, for this system and the common others.
requirements_help() {
  local miss_req=() miss_opt=() t pm all
  for t in $REQUIRED_TOOLS; do have "$t" || miss_req+=("$t"); done
  for t in $OPTIONAL_TOOLS; do have "$t" || miss_opt+=("$t"); done
  echo "Requirements"
  echo "  required:  $REQUIRED_TOOLS (DNS queries)"
  echo "  optional:  $OPTIONAL_TOOLS"
  echo "             (python3: registration, TLS, mail, SPF and IP checks; delv: DNSSEC validation;"
  echo "              openssl: certificate details; curl: web checks; ping: availability)"
  echo
  if ((${#miss_req[@]} + ${#miss_opt[@]} == 0)); then
    echo "Everything is installed."
    return
  fi
  ((${#miss_req[@]})) && echo "  MISSING (required): ${miss_req[*]}"
  ((${#miss_opt[@]})) && echo "  missing (optional): ${miss_opt[*]}"
  echo
  pm=$(detect_pm)
  if [[ -n $pm ]]; then
    echo "Install on this system ($pm):"
    echo "  $(install_cmd "$pm" "${miss_req[@]+"${miss_req[@]}"}" "${miss_opt[@]+"${miss_opt[@]}"}")"
    echo
  fi
  all="$REQUIRED_TOOLS $OPTIONAL_TOOLS"
  echo "All tools, other systems:"
  # shellcheck disable=SC2086  # word splitting of the tool list is intended
  {
    printf '  %-16s %s\n' "Debian/Ubuntu" "$(install_cmd apt $all)"
    printf '  %-16s %s\n' "Fedora/RHEL 8+" "$(install_cmd dnf $all)"
    printf '  %-16s %s\n' "CentOS/RHEL 7" "$(install_cmd yum $all)"
    printf '  %-16s %s\n' "openSUSE" "$(install_cmd zypper $all)"
    printf '  %-16s %s\n' "Arch/Manjaro" "$(install_cmd pacman $all)"
    printf '  %-16s %s\n' "Alpine" "$(install_cmd apk $all)"
    printf '  %-16s %s\n' "macOS (Homebrew)" "$(install_cmd brew $all)"
  }
}

# Name, version, release date, description and author (used by --version and --help).
version_info() {
  printf '%s %s (released %s)\n' "$APP_NAME" "$APP_VERSION" "$APP_RELEASE_DATE"
  printf '%s\n' "$APP_DESCRIPTION" | fold -s -w 88 | sed 's/ *$//'
  printf 'Author: %s\n' "$APP_AUTHOR"
  echo
  printf '%s\n' "$APP_COPYRIGHT"
  printf 'License %s: GNU AGPL version 3 or later <https://www.gnu.org/licenses/agpl-3.0.html>\n' \
    "$APP_LICENSE"
  echo 'This is free software: you are free to change and redistribute it.'
  echo 'Provided "as is", WITHOUT ANY WARRANTY: the author is not liable for any damage'
  echo 'arising from its use. See the LICENSE file and the header of this script.'
}

usage() {
  version_info
  echo
  # The help text is the comment block between the HELP-BEGIN and HELP-END markers.
  awk '/^# HELP-BEGIN/ {f = 1; next} /^# HELP-END/ {exit} f {sub(/^# ?/, ""); print}' "$0"
}

PASSIVE=""
BRIEF=""
COMPARE=""
ALL=""
OUTPUT=""
OUTPUT_DIR_CLI=""
domain=""
while (($#)); do
  case $1 in
    -p|--passive) PASSIVE=1 ;;
    -b|--brief) BRIEF=1 ;;
    -c|--compare) COMPARE=1 ;;
    -a|--all) ALL=1 ;;
    -o|--output) OUTPUT=1 ;;
    --output-dir)
      if (($# < 2)) || [[ $2 == -* ]]; then
        echo "Option $1 needs a directory (see --help)" >&2; exit 2
      fi
      OUTPUT=1; OUTPUT_DIR_CLI=$2; shift ;;
    --output-dir=*) OUTPUT=1; OUTPUT_DIR_CLI=${1#*=} ;;
    -r|--related-domains)
      if (($# < 2)) || [[ $2 == -* ]]; then
        echo "Option $1 needs a list of domains (see --help)" >&2; exit 2
      fi
      RELATED_DOMAINS=$2; shift ;;
    --related-domains=*) RELATED_DOMAINS=${1#*=} ;;
    --requirements) requirements_help; exit 0 ;;
    -v|--version) version_info; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    *)
      if [[ -n $domain ]]; then
        echo "Only one domain at a time ('$domain' and '$1' given)" >&2; exit 2
      fi
      domain=$1 ;;
  esac
  shift
done
# Report directory: --output-dir is taken as given (relative to the current directory);
# OUTPUT_DIR from the environment, config file or default is relative to the script directory.
if [[ -n $OUTPUT_DIR_CLI ]]; then
  OUTPUT_DIR=$OUTPUT_DIR_CLI
elif [[ $OUTPUT_DIR != /* ]]; then
  OUTPUT_DIR="$SCRIPT_DIR/$OUTPUT_DIR"
fi
# The child process works with the folder its parent resolved (including --output-dir).
[[ -n ${_NDM_OUTDIR:-} ]] && OUTPUT_DIR=$_NDM_OUTDIR
# Normalize the related domains: commas to spaces, lowercase, no trailing dots.
RELATED_DOMAINS=$(printf '%s' "${RELATED_DOMAINS//[*?[]/}" | tr ',' ' ' | tr '[:upper:]' '[:lower:]' \
  | tr -s ' ' '\n' | sed -e 's/\.$//' -e '/^$/d' | paste -sd ' ' -)
for t in $REQUIRED_TOOLS; do
  if ! have "$t"; then
    { echo "Error: '$t' is required but not installed."; echo; requirements_help; } >&2
    exit 1
  fi
done

# Portfolio: one brief check per domain, a table at the end.
portfolio() {
  local list="" d i=0 args facts rc f name err warn chk tip
  [[ -n $domain ]] && list=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')
  for d in $RELATED_DOMAINS; do
    [[ $d == -* ]] && continue
    [[ " $list " == *" $d "* ]] || list+="${list:+ }$d"
  done
  if [[ -z $list ]]; then
    echo "Error: --all needs domains: give one, or set RELATED_DOMAINS (see --help)." >&2
    return 2
  fi
  PF_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t ndm_all)
  # Background children of a script ignore SIGINT: on Ctrl-C they are stopped with SIGTERM, which
  # makes each of them remove its own temporary directory.
  PF_PIDS=()
  trap 'kill "${PF_PIDS[@]}" 2>/dev/null; wait; rm -rf "${PF_DIR:?}"; exit 130' INT TERM
  for d in $list; do
    i=$((i + 1))
    args=(--brief)
    [[ -n $PASSIVE ]] && args+=(--passive)
    [[ -n $OUTPUT ]] && args+=(-o)
    [[ -n $OUTPUT_DIR_CLI ]] && args+=(--output-dir "$OUTPUT_DIR_CLI")
    [[ -n $RELATED_DOMAINS ]] && args+=(--related-domains "$RELATED_DOMAINS")
    _NDM_FACTS_FILE="$PF_DIR/facts_$i" NO_COLOR=1 "${BASH:-bash}" "$0" "${args[@]}" "$d" >"$PF_DIR/out_$i" 2>&1 &
    PF_PIDS+=("$!")
    ((i % 4 == 0)) && wait
  done
  wait
  pf() { awk -F= -v k="$1" '$1 == k {print substr($0, index($0, "=") + 1); exit}' "$2"; }
  printf '\n%s  %-30s %3s %3s %3s %3s  %-7s %-6s %-11s %-9s %-9s %s%s\n' "$C_BOLD" "Domain" "✘" "⚠" "◆" "↑" \
    "DNSSEC" "SPF" "DMARC" "MTA-STS" "Domain" "Certificate" "$C_RESET"
  i=0; rc=0
  for d in $list; do
    i=$((i + 1)); facts="$PF_DIR/facts_$i"
    if [[ ! -s $facts ]]; then
      printf '  %-30s %s(not checked: %s)%s\n' "$d" "$C_RED" "$(grep -a -m1 -E 'Error|✘' "$PF_DIR/out_$i" | sed 's/^ *//' | cut -c1-70)" "$C_RESET"
      rc=1; continue
    fi
    err=$(pf '~err' "$facts"); warn=$(pf '~warn' "$facts"); chk=$(pf '~check' "$facts"); tip=$(pf '~tip' "$facts")
    ((${err:-0} > 0)) && rc=1
    f=$(pf '~mail' "$facts")
    printf '  %-30s %s%3s%s %s%3s%s %3s %3s  %-7s %-6s %-11s %-9s %-9s %s\n' "$d" \
      "$([[ ${err:-0} -gt 0 ]] && echo "$C_RED")" "$err" "$C_RESET" "$([[ ${warn:-0} -gt 0 ]] && echo "$C_YELLOW")" "$warn" "$C_RESET" \
      "$chk" "$tip" "$(pf '~dnssec' "$facts")" "$(pf '~spf_all' "$facts")" "$(pf '~dmarc_policy' "$facts")" \
      "$(pf '~mta_sts' "$facts")" "$(d=$(pf '~reg_days' "$facts"); [[ -n $d ]] && echo "${d} d" || echo -)" \
      "$(d=$(pf '~cert_days' "$facts"); [[ -n $d ]] && echo "${d} d" || echo -)$([[ $f == no ]] && echo '  (no mail)')"
  done
  printf '  %s✘ errors  ⚠ warnings  ◆ to check  ↑ improvements.  Domain / Certificate: days left.%s\n\n' "$C_DIM" "$C_RESET"
  rm -rf "${PF_DIR:?}"
  return "$rc"
}
if [[ -n $ALL ]]; then portfolio; exit $?; fi

if [[ -z $domain ]]; then
  read -r -p "Domain to check: " domain
fi
# Normalize: lowercase, strip scheme, path and trailing dot.
domain=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]' \
  | sed -e 's#^[a-z]*://##' -e 's#/.*$##' -e 's/\.$//' -e 's/^ *//' -e 's/ *$//')
dns_label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
if [[ ! $domain =~ ^(${dns_label}\.)+${dns_label}$ || ${#domain} -gt 253 ]]; then
  echo "Error: '$domain' is not a valid domain name." >&2
  exit 1
fi
parent="${domain#*.}"

if [[ -n $OUTPUT && -z ${_NDM_CHILD:-} ]]; then
  if [[ ! -d $OUTPUT_DIR ]]; then (umask 077; mkdir -p "$OUTPUT_DIR" 2>/dev/null); fi
  if [[ ! -d $OUTPUT_DIR || ! -w $OUTPUT_DIR ]]; then
    echo "Error: cannot write to the output directory '$OUTPUT_DIR'." >&2
    exit 1
  fi
  report_file="$OUTPUT_DIR/${domain}_$(date '+%Y%m%d-%H%M%S').txt"
  if [[ -e $report_file || -L $report_file ]]; then
    echo "Error: '$report_file' already exists; not overwriting it." >&2
    exit 1
  fi
  child_args=()
  [[ -n $PASSIVE ]] && child_args+=(--passive)
  [[ -n $BRIEF ]] && child_args+=(--brief)
  [[ -n $RELATED_DOMAINS ]] && child_args+=(--related-domains "$RELATED_DOMAINS")
  raw=$(mktemp 2>/dev/null || mktemp -t ndm_report)
  report_tmp=""
  trap 'rm -f "$raw" "$report_tmp"' EXIT
  color=""
  [[ -t 1 ]] && color=1
  _NDM_SAVE=1 _NDM_OUTDIR=$OUTPUT_DIR _NDM_CHILD=1 _NDM_FORCE_COLOR=$color \
    "${BASH:-bash}" "$0" "${child_args[@]+"${child_args[@]}"}" "$domain" \
    | tee "$raw" | grep -a --line-buffered -Ev '^#NDM_(FACT|NOTE) '
  # The #NDM_FACT lines (and the #NDM_NOTE lines explaining them) stay in the saved file:
  # the next run compares itself with them.
  status=${PIPESTATUS[0]}
  # Plain-text copy: drop the color escape sequences.
  # The report holds the domain's real data: private file, written aside and then renamed.
  report_tmp=$(mktemp "$OUTPUT_DIR/.report.XXXXXX")
  sed $'s/\x1b\\[[0-9;]*m//g' "$raw" >"$report_tmp"
  chmod 600 "$report_tmp"
  mv "$report_tmp" "$report_file"
  report_tmp=""
  rm -f "$raw"
  printf 'Report saved to: %s\n' "$report_file"
  exit "$status"
fi

missing=()
for t in $OPTIONAL_TOOLS; do have "$t" || missing+=("$t"); done

tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t ndm_domain-health-check)
trap 'rm -rf "$tmpdir"' EXIT
# Without these, a signal would end the script without running the EXIT trap.
trap 'exit 130' INT
trap 'exit 143' TERM

rule() { printf '%s%s══════════════════════════════════════════════════════════════════════%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"; }
printf '\n'; rule
printf '%s  %s (%s)%s\n' "$C_BOLD" "$APP_NAME" "$APP_VERSION" "$C_RESET"
printf '%s  Domain: %s%s\n' "$C_BOLD" "$(printf '%s' "$domain" | tr '[:lower:]' '[:upper:]')" "$C_RESET"
printf '  %sResolver: %s  ·  %s%s\n' "$C_DIM" "$RESOLVER" "$(date '+%Y-%m-%d %H:%M')" "$C_RESET"
printf '  %s%s✔%s ok  %s↑%s improvable  %s◆%s to check  %s⚠%s warning  %s✘%s error  %sℹ%s info%s\n' "$C_DIM" \
  "$C_GREEN" "$C_DIM" "$C_MAGENTA" "$C_DIM" "$C_CYAN" "$C_DIM" "$C_YELLOW" "$C_DIM" "$C_RED" "$C_DIM" \
  "$C_BLUE" "$C_DIM" "$C_RESET"
if [[ -n $RELATED_DOMAINS ]]; then
  printf '  %sRelated domains: %s%s\n' "$C_DIM" "$RELATED_DOMAINS" "$C_RESET"
fi
if [[ ! -e $CONFIG_FILE && -e $CONFIG_FILE.example ]]; then
  printf '  %sNo config file: copy %s to %s to customize%s\n' "$C_DIM" \
    "$(basename "$CONFIG_FILE").example" "$(basename "$CONFIG_FILE")" "$C_RESET"
fi
if [[ -n $PASSIVE ]]; then
  printf '  %sMode: passive (no AXFR, no obsolete-TLS test, no mail port connections)%s\n' "$C_YELLOW" "$C_RESET"
fi
if ((${#missing[@]})); then
  printf '  %sOptional tools missing (some checks skipped): %s  ·  see --requirements%s\n' \
    "$C_YELLOW" "${missing[*]}" "$C_RESET"
fi
rule

# ---------------------------------------------------------- [1] registration ----
registrar_name=""
if have python3; then
  reg=$(NDM_CACHE=${tmpdir:-} python3 -I -c "$PY_REG" "$domain" 2>/dev/null)
  src=$(regval source)
  section 1 "REGISTRATION" "${src:-RDAP / WHOIS (no answer)}"
  if [[ -z $src ]]; then
    err=$(regval error)
    info "Registration data" "not available: RDAP/WHOIS unreachable or port 43 blocked${err:+ ($err)}"
  else
    r=$(regval registrar);  info "Registrar"  "${r:-not published}"; registrar_name=$r
    r=$(regval registrant); info "Registrant" "${r:-not published (privacy / GDPR)}"
    r=$(regval created);    info "Created"    "${r:-not published by this registry}"
    r=$(regval updated);    [[ -n $r ]] && info "Last updated" "$r"
    exp=$(regval expires); left=$(regval days_left)
    reg_expires=$exp; reg_days=$left
    if [[ -z $exp ]]; then
      info "Expires" "not published by this registry"
    elif [[ -z $left ]]; then
      info "Expires" "$exp"
    elif ((left < 0)); then
      fail "Expires" "$exp (EXPIRED ${left#-} days ago)"
      fix renew 1 "Registration: renew the domain now" \
        "It expired ${left#-} days ago: renew it at ${registrar_name:-the registrar} before it is" \
        "deleted and can be registered by anyone. Then turn on automatic renewal."
    elif ((left < 30)); then
      warn "Expires" "$exp (only $left days left: renew!)"
      fix renew 2 "Registration: renew before $exp" \
        "Renew at ${registrar_name:-the registrar} or turn on automatic renewal, and check that the" \
        "payment method and the registrant e-mail address are still valid."
    else
      ok "Expires" "$exp ($left days left)"
    fi
    st=$(regval status)
    if [[ -n $st ]]; then
      if [[ $st =~ [Hh]old|[Rr]edemption|pendingDelete|inactive ]]; then
        fail "Status" "$st"
        fix status 1 "Registration: the domain is suspended or being deleted" \
          "Contact ${registrar_name:-the registrar}. clientHold often means an unpaid renewal or an" \
          "unverified registrant e-mail; redemptionPeriod can still be recovered, for a fee."
      else
        info "Status" "$st"
        st_norm=$(printf '%s' "$st" | tr '[:upper:]' '[:lower:]' | tr -d ' _-')
        if [[ $st_norm != *transferprohibited* && ( $st_norm == *ok* || $st_norm == *active* || $st_norm == *prohibited* ) ]]; then
          tip "Transfer lock" "no transfer lock in the registry status (clientTransferProhibited)"
          fix transfer-lock 4 "Registration: lock the domain against transfers" \
            "Turn on the transfer lock (\"registrar lock\", status clientTransferProhibited) at" \
            "${registrar_name:-the registrar}: nobody can move the domain away without you unlocking it first." \
            "Registries that do not publish this status are not covered by this check."
        fi
      fi
    fi
  fi
else
  section 1 "REGISTRATION" "RDAP / WHOIS"
  info "Registration data" "skipped (python3 not available)"
fi

# ---------------------------------------------------------- [2] availability ----
avail_src="resolver $RESOLVER, ping, HTTPS request"
[[ -z $PASSIVE ]] && avail_src+=", TCP connection to the mail server"
section 2 "AVAILABILITY" "$avail_src"

# TCP connect test (bash /dev/tcp, no data sent).
# shellcheck disable=SC2016  # $1 and $2 are expanded by the inner bash, not by this shell
tcp_open() { run_to 4 bash -c ': >"/dev/tcp/$1/$2"' _ "$1" "$2" >/dev/null 2>&1; }

# True when an address is on the public Internet: not loopback, private, link-local,
# documentation, multicast... Anything that is not a plain address is "not public".
ip_is_public() {
  local ip a b c
  ip=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  if [[ $ip == *:* ]]; then
    case $ip in
      2001:db8:*|2001:0db8:*|2001::*|2001:0:*|2001:0000:*|2001:2:*|2001:10:*|2002:*) return 1 ;;
      [23]*) return 0 ;;
    esac
    return 1
  fi
  # No leading zeros: curl would read 010.0.0.1 as octal.
  [[ $ip =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
  IFS=. read -r a b c _ <<<"$ip"
  ((a == 0 || a == 10 || a == 127 || a >= 224)) && return 1
  ((a == 100 && b >= 64 && b <= 127)) && return 1
  ((a == 169 && b == 254)) && return 1
  ((a == 172 && b >= 16 && b <= 31)) && return 1
  ((a == 192 && (b == 168 || b == 0))) && return 1
  ((a == 198 && (b == 18 || b == 19))) && return 1
  ((a == 198 && b == 51 && c == 100)) && return 1
  ((a == 203 && b == 0 && c == 113)) && return 1
  return 0
}

# True when every address of a host is public (and there is at least one). It also sets PIN to
# curl's --resolve option with those addresses: curl then connects to exactly what was checked,
# even if its own resolver would answer differently. Usage: pin_host HOST PORT && curl "${PIN[@]}" ...
# Other tools: PIN_IPS (comma separated), PIN_IP (first address, for /dev/tcp) and PIN_ADDR (first
# address, IPv6 in brackets, for "openssl s_client -connect $PIN_ADDR:port").
PIN=(); PIN_IPS=""; PIN_ADDR=""; PIN_IP=""
pin_host() {
  local ip list="" raw=""
  PIN=(); PIN_IPS=""; PIN_ADDR=""; PIN_IP=""
  for ip in $(q4 "$1") $(q6 "$1"); do
    ip_is_public "$ip" || return 1
    raw+="${raw:+,}$ip"
    [[ -n $PIN_IP ]] || { PIN_IP=$ip; PIN_ADDR=$ip; [[ $ip == *:* ]] && PIN_ADDR="[$ip]"; }
    [[ $ip == *:* ]] && ip="[$ip]"
    list+="${list:+,}$ip"
  done
  [[ -n $list ]] || return 1
  PIN_IPS=$raw
  PIN=(--resolve "$1:$2:$list")
}

# "host=ip,ip ..." for the hosts of PY_PROBE specs ("kind|host|port|label") that resolve only to
# public addresses: the Python helpers connect to these and refuse every other name (NDM_PIN).
probe_pins() {
  local spec host out="_=" seen=" "
  for spec in "$@"; do
    host=${spec#*|}; host=${host%%|*}
    [[ $seen == *" $host "* ]] && continue
    seen+="$host "
    pin_host "$host" 0 && out+=" $host=$PIN_IPS"
  done
  printf '%s' "$out"
}

# GET a URL following redirects by hand (at most 5). A hostile site could redirect to
# loopback, the LAN or ftp://, and the audited domain itself could point to a private
# address: only hosts that resolve to public addresses (pinned with --resolve) are contacted.
# Sets FETCH_CODE, FETCH_TIME, FETCH_URL, FETCH_ERR, FETCH_BLOCKED; the headers of the last
# response are in $tmpdir/headers. Returns 1 on a curl error or a blocked redirect.
fetch_follow() {
  local url=$1 hop=0 hostport host port rest ip first bad out rc code redirect secs total=0 pin
  FETCH_CODE=000; FETCH_TIME=0; FETCH_URL=$url; FETCH_ERR=""; FETCH_BLOCKED=""; FETCH_HTTP=""
  : >"$tmpdir/headers"
  while ((hop <= 5)); do
    FETCH_URL=$url
    case $url in
      https://*) port=443 ;;
      http://*) port=80 ;;
      *) FETCH_BLOCKED=1; FETCH_ERR="redirect to a non-web address not followed"; return 1 ;;
    esac
    hostport=${url#*://}; hostport=${hostport%%[/?#]*}; hostport=${hostport##*@}
    if [[ $hostport == \[* ]]; then
      host=${hostport#\[}; host=${host%%\]*}; rest=${hostport#*\]}
      [[ $rest == :* ]] && port=${rest#:}
    else
      host=${hostport%%:*}
      [[ $hostport == *:* ]] && port=${hostport##*:}
    fi
    pin=()
    if [[ ! $port =~ ^[0-9]{1,5}$ ]]; then
      FETCH_BLOCKED=1; FETCH_ERR="redirect with an invalid port not followed"; return 1
    fi
    first=""; bad=""
    if [[ $host == *:* || $host =~ ^[0-9.]+$ ]]; then
      if ip_is_public "$host"; then first=$host; else bad=$host; fi
    else
      for ip in $(q4 "$host") $(q6 "$host"); do
        if ip_is_public "$ip"; then first=${first:-$ip}; else bad=$ip; fi
      done
      if [[ -n $first && -z $bad ]]; then
        [[ $first == *:* ]] && first="[$first]"
        pin=(--resolve "$host:$port:$first")
      fi
    fi
    if [[ -n $bad || -z $first ]]; then
      FETCH_BLOCKED=1
      if [[ -n $bad ]]; then FETCH_ERR="$host not contacted: it resolves to a non-public address ($bad)"
      else FETCH_ERR="$host not contacted: no public address found"; fi
      return 1
    fi
    out=$(curl -sS -m "$NET_TIMEOUT" -o /dev/null -D "$tmpdir/headers.hop" --proto '=http,https' \
      "${pin[@]+"${pin[@]}"}" -w '%{http_code}|%{redirect_url}|%{time_total}|%{http_version}' "$url" 2>"$tmpdir/curl_err")
    rc=$?
    if ((rc != 0)); then
      FETCH_ERR=$(sed 's/^curl: //' "$tmpdir/curl_err" | head -1)
      [[ -n $FETCH_ERR ]] || FETCH_ERR="no response from $url"
      return 1
    fi
    IFS='|' read -r code redirect secs FETCH_HTTP <<<"$out"
    total=$(awk -v a="$total" -v b="${secs:-0}" 'BEGIN {printf "%.6f", a + b}')
    cp "$tmpdir/headers.hop" "$tmpdir/headers"
    FETCH_CODE=$code; FETCH_TIME=$total
    if [[ $code =~ ^30[12378]$ && -n $redirect ]]; then url=$redirect; hop=$((hop + 1)); continue; fi
    return 0
  done
  FETCH_ERR="too many redirects (more than 5)"
  return 1
}

# Average round-trip time (ms) of two pings, empty when there is no reply.
ping_avg() {
  if [[ $1 == *:* ]]; then
    if have ping6; then run_to 6 ping6 -c 2 "$1"; else run_to 6 ping -6 -c 2 "$1"; fi
  else
    run_to 6 ping -c 2 "$1"
  fi 2>/dev/null | awk -F/ '/min\/avg/ {print $5}'
}

web_ip=$(q4 "$domain" | head -1)
web_ip6=$(q6 "$domain" | head -1)
if [[ -z $web_ip && -z $web_ip6 ]]; then
  warn "Website" "no address (A or AAAA) for $domain"
else
  if have ping; then
    for web_addr in $web_ip $web_ip6; do
      if ! ip_is_public "$web_addr"; then info "Ping $web_addr" "not sent: non-public address"; continue; fi
      avg=$(ping_avg "$web_addr")
      if [[ -n $avg ]]; then ok "Ping $web_addr" "replies (avg ${avg} ms)"
      else info "Ping $web_addr" "no reply (ICMP is often blocked: not an error)"; fi
    done
  fi
  if have curl; then
    fetch_follow "https://$domain/" || true
    code=$FETCH_CODE; secs=$FETCH_TIME
    case $code in
      2??|3??) ok "Website" "online (HTTP $code, ${secs} s)" ;;
      4??)     warn "Website" "responds with HTTP $code (${secs} s)" ;;
      5??)     fail "Website" "server error HTTP $code (${secs} s)" ;;
      *)       if [[ -n $FETCH_BLOCKED ]]; then warn "Website" "$FETCH_ERR"
               else fail "Website" "not responding on https://$domain/"; fi ;;
    esac
    case $code in
      2??|3??) ;;
      4??) fix website 2 "Web: the home page answers HTTP $code" \
             "Check that the site is published in the right folder (document root) and that no" \
             "rule (.htaccess, firewall, maintenance mode) blocks it." ;;
      *)   [[ -n $FETCH_BLOCKED ]] || fix website 1 "Web: the site does not work" \
             "Check that the web server is running and look at its error log. On shared" \
             "hosting, open a ticket with the provider." ;;
    esac
  fi
fi

avail_mx=$(q MX "$domain" | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
if [[ -z $avail_mx || $avail_mx == "." ]]; then
  info "Mail service" "no MX published"
elif [[ -n $PASSIVE ]]; then
  info "Mail service" "MX $avail_mx published (not contacted in passive mode)"
else
  avail_host="mail.$domain"
  has_addr "$avail_host" || avail_host=$avail_mx
  open_port=""
  if pin_host "$avail_host" 0; then
    for port in 993 465 587 995 25; do
      if tcp_open "$PIN_IP" "$port"; then open_port=$port; break; fi
    done
  else
    open_port=skip
  fi
  if [[ $open_port == skip ]]; then info "Mail service" "$avail_host resolves to a non-public address: not contacted"
  elif [[ -n $open_port ]]; then ok "Mail service" "online ($avail_host answers on port $open_port)"
  else
    warn "Mail service" "$avail_host does not answer on 993/465/587/995/25"
    fix mail-down 2 "Mail: the mail server does not answer" \
      "Check that the mail service is running on $avail_host and that its firewall allows" \
      "ports 25, 465, 587 and 993. Some networks block outgoing port 25: test from another one."
  fi
fi

# ------------------------------------------------- [3] registry delegation ----
parent_ns=$(q NS "$parent." | head -1 | sed 's/\.$//')
if [[ -z $parent_ns ]]; then
  echo "Error: cannot find the nameservers of '.$parent'. Check your network." >&2
  exit 1
fi

section 3 "REGISTRY (DELEGATION)" ".$parent registry nameserver $parent_ns (direct, no recursion)"

deleg_ns=$(dig +norec +noall +authority +answer NS "$domain" @"$parent_ns" 2>/dev/null \
  | awk '$4 == "NS" {print $5}' | sed 's/\.$//' | sort -u)
if [[ -z $deleg_ns ]]; then
  fail "Nameservers" "none delegated (domain not registered, suspended, or a subdomain?)"
  exit 1
fi
ok "Nameservers" "$(echo "$deleg_ns" | paste -sd ' ' -)"
deleg_l=$(printf '%s\n' "$deleg_ns" | tr '[:upper:]' '[:lower:]' | sort -u)
if (($(printf '%s\n' "$deleg_l" | wc -l) < 2)); then
  warn "Nameservers" "only one: if it goes down the whole domain is offline"
  fix ns-single 2 "DNS: add a second nameserver" \
    "Keep at least two nameservers, on different networks, so that one outage does not take" \
    "the domain (and its mail) offline. Add it at ${registrar_name:-the registrar} and in the zone."
fi
# A nameserver inside the zone itself can only be found if the registry hands out its address (glue).
deleg_glue=$(dig +norec +noall +additional NS "$domain" @"$parent_ns" 2>/dev/null \
  | awk '$4 == "A" || $4 == "AAAA" {print tolower($1)}' | sed 's/\.$//' | sort -u)
for ns in $deleg_l; do
  [[ $ns == "$domain" || $ns == *".$domain" ]] || continue
  if ! grep -qx "$ns" <<<"$deleg_glue"; then
    warn "Glue $ns" "no address at the registry: resolvers cannot find a nameserver that lives inside its own zone"
    fix "glue-$ns" 2 "DNS: register the address of $ns at the registrar" \
      "A nameserver named inside $domain needs a glue record (its IP address) at the registry:" \
      "in the registrar's panel, the section for nameservers or \"glue records\" / \"host records\"."
  fi
done

# A nameserver whose own domain expires can be taken over: look at the domains (other than this
# one) that host the nameservers.
if have python3; then
  ns_doms=$(for ns in $deleg_l; do reg_domain <<<"$ns"; done \
    | sort -u | grep -vx "$domain" | head -3)
  ns_dom_n=0; ns_dom_bad=0
  for nd in $ns_doms; do
    nd_left=$(NDM_CACHE=$tmpdir python3 -I -c "$PY_REG" "$nd" 2>/dev/null | awk -F'\t' '$1 == "days_left" {print $2}')
    [[ $nd_left =~ ^-?[0-9]+$ ]] || continue
    ns_dom_n=$((ns_dom_n + 1))
    if ((nd_left < 0)); then
      ns_dom_bad=1
      fail "Nameserver domain" "$nd EXPIRED $((-nd_left)) days ago: the nameservers living in it can be taken over"
      fix "nsdom-$nd" 1 "DNS: the domain $nd, that hosts your nameservers, has expired" \
        "Renew it now (or move the nameservers elsewhere): whoever registers it can answer for $domain."
    elif ((nd_left < 30)); then
      ns_dom_bad=1
      warn "Nameserver domain" "$nd expires in $nd_left days: it hosts nameservers of this domain"
      fix "nsdom-$nd" 2 "DNS: renew $nd, that hosts your nameservers" \
        "If it expires, the nameservers living in it stop answering and can be taken over."
    fi
  done
  ((ns_dom_n > 0 && ns_dom_bad == 0)) && ok "Nameserver domains" "$ns_dom_n checked, none expiring soon"
fi

# DS digests may be printed in chunks by dig: join fields 8..NF.
reg_ds=$(dig +norec +noall +answer DS "$domain" @"$parent_ns" 2>/dev/null \
  | awk '$4 == "DS" {d = ""; for (i = 8; i <= NF; i++) d = d $i; print $5, $6, $7, toupper(d)}')
if [[ -z $reg_ds ]]; then
  info "DS records" "none (DNSSEC not enabled at the registry)"
else
  ds_count=$(echo "$reg_ds" | wc -l | tr -d ' ')
  if ((ds_count == 1)); then ok "DS records" "1"
  else info "DS records" "$ds_count (more than one is normal only during a key rollover)"; fi
  while read -r tag alg dtype digest; do
    detail "$tag  alg $alg $(alg_name "$alg")  digest-type $dtype  ${digest:0:16}…"
  done <<<"$reg_ds"
fi

# --------------------------------------------------- [4] authoritative DNS ----
first_ns=$(echo "$deleg_ns" | head -1)
section 4 "AUTHORITATIVE DNS" "each delegated nameserver (direct, no recursion)"

serials=""
answering_ns=""
for ns in $deleg_ns; do
  s=$(dig +norec +short +time=3 +tries=1 SOA "$domain" @"$ns" 2>/dev/null | grep -v '^;' | awk '{print $3}')
  if [[ -z $s ]]; then
    fail "SOA on $ns" "no answer (lame or unreachable nameserver)"
    fix "lame-$ns" 1 "DNS: nameserver $ns does not answer" \
      "Repair it, or remove it from the nameservers at ${registrar_name:-the registrar}: resolvers" \
      "waste time on it and answers become slow or fail. Keep at least two working nameservers."
  else
    serials+="$s"$'\n'
    answering_ns+=" $ns"
  fi
done
uniq_serials=$(printf '%s' "$serials" | sort -u | sed '/^$/d')
if [[ $(printf '%s\n' "$uniq_serials" | sed '/^$/d' | wc -l | tr -d ' ') == 1 ]]; then
  ok "SOA serial" "$uniq_serials (same on all nameservers)"
elif [[ -n $uniq_serials ]]; then
  warn "SOA serial" "differs between nameservers: $(echo "$uniq_serials" | paste -sd ' ' -)"
  fix soa-sync 2 "DNS: the nameservers serve different versions of the zone" \
    "Normal for a few minutes after a change. If it lasts, the secondaries are not updated:" \
    "check that the primary sends NOTIFY and allows the zone transfer to the secondaries."
fi

# Every nameserver must list the same nameservers as the registry (parent/child consistency).
ns_only_parent=""; ns_only_child=""; ns_answered=0
for ns in $answering_ns; do
  child=$(dig +norec +short +time=3 +tries=1 NS "$domain" @"$ns" 2>/dev/null | grep -v '^;' \
    | sed 's/\.$//' | tr '[:upper:]' '[:lower:]' | sort -u)
  [[ -n $child ]] || continue
  ns_answered=$((ns_answered + 1))
  ns_only_parent+=$'\n'$(comm -23 <(printf '%s\n' "$deleg_l") <(printf '%s\n' "$child"))
  ns_only_child+=$'\n'$(comm -13 <(printf '%s\n' "$deleg_l") <(printf '%s\n' "$child"))
done
ns_only_parent=$(printf '%s\n' "$ns_only_parent" | sed '/^$/d' | sort -u | paste -sd ' ' -)
ns_only_child=$(printf '%s\n' "$ns_only_child" | sed '/^$/d' | sort -u | paste -sd ' ' -)
if ((ns_answered == 0)); then :
elif [[ -n $ns_only_parent || -n $ns_only_child ]]; then
  warn "NS consistency" "the zone and the registry disagree${ns_only_parent:+; only at the registry: $ns_only_parent}${ns_only_child:+; only in the zone: $ns_only_child}"
  fix ns-mismatch 2 "DNS: make the nameservers of the zone and of the registry the same" \
    "The NS records inside the zone must match the nameservers set at ${registrar_name:-the registrar}." \
    "A mismatch makes some resolvers use servers the other side does not know (stale or missing" \
    "answers). Update the NS records in the zone or the nameservers at the registrar, then wait for the TTLs."
else
  ok "NS consistency" "the zone lists the same nameservers as the registry"
fi

# DNS must also work over TCP (large and DNSSEC answers need it).
tcp_bad=()
for ns in $answering_ns; do
  dig +tcp +norec +short +time=3 +tries=1 SOA "$domain" @"$ns" 2>/dev/null | grep -v '^;' | grep -q . \
    || tcp_bad+=("$ns")
done
if [[ -z $answering_ns ]]; then :
elif ((${#tcp_bad[@]})); then
  warn "DNS over TCP" "no answer over TCP from: ${tcp_bad[*]}"
  fix tcp53 2 "DNS: open TCP port 53 on ${tcp_bad[*]}" \
    "UDP works but TCP does not: answers that do not fit one packet (DNSSEC, many records) fail." \
    "Allow TCP and UDP on port 53 in the firewall of the nameserver (managed DNS: tell the provider)."
else
  ok "DNS over TCP" "answered by all nameservers"
fi

# Active checks of the nameservers themselves: open recursion and software version.
if [[ -z $PASSIVE ]]; then
  open_ns=(); ver_ns=()
  for ns in $answering_ns; do
    rr=$(dig +time=3 +tries=1 +recurse +comments +answer A a.root-servers.net @"$ns" 2>/dev/null)
    if grep -m1 '^;; flags:' <<<"$rr" | grep -q ' ra' && [[ -n $(awk '$4 == "A"' <<<"$rr") ]]; then
      open_ns+=("$ns")
    fi
    vb=$(dig +short +time=3 +tries=1 CH TXT version.bind @"$ns" 2>/dev/null | grep -v '^;' | head -1 | tr -d '"')
    [[ $vb =~ [0-9]+\.[0-9]+ ]] && ver_ns+=("$ns ($vb)")
  done
  if ((${#open_ns[@]})); then
    warn "Open resolver" "${open_ns[*]} answers recursive queries from this machine: if it does so for everyone, it can be abused for DDoS amplification"
    fix open-resolver 2 "DNS: stop the authoritative server from recursing" \
      "An authoritative nameserver should answer only for its own zones:" \
      "= BIND:      recursion no;   (or allow-recursion { <your networks>; };)" \
      "= Knot DNS:  it never recurses (check that another resolver is not listening on the same address)" \
      "= PowerDNS:  allow-recursion=127.0.0.1 (authoritative server), recursor on another address"
  elif [[ -n $answering_ns ]]; then
    ok "Recursion" "refused by all nameservers"
  fi
  if ((${#ver_ns[@]})); then
    tip "DNS software version" "the nameservers announce it: ${ver_ns[*]}"
    fix dns-version 4 "DNS: do not announce the software version" \
      "= BIND:      options { version \"not disclosed\"; };" \
      "= Knot DNS:  server: identity: \"\"  and  version: \"\"" \
      "= PowerDNS:  version-string=anonymous"
  fi
fi

# Nameservers that all sit in the same /24 share the same fate.
ns_addr=$(for ns in $deleg_ns; do q4 "$ns"; done | sort -u)
if (($(sed '/^$/d' <<<"$ns_addr" | wc -l) >= 2)) && (($(sed -e '/^$/d' -e 's/\.[0-9]*$//' <<<"$ns_addr" | sort -u | wc -l) == 1)); then
  tip "Nameserver diversity" "all nameserver addresses are in the same /24 network: one outage takes them all"
  fix ns-diversity 4 "DNS: put a nameserver on a different network" \
    "Use at least one secondary nameserver on another network or provider (secondary DNS service" \
    "or a second site), so that a routing or datacenter problem does not take all of them down."
fi

# SOA timers: refresh/retry/expire/negative TTL (RFC 1912, RFC 2308).
soa_full=$(dig +norec +short +time=3 +tries=1 SOA "$domain" @"$first_ns" 2>/dev/null | grep -v '^;' | head -1)
read -r _ _ _ soa_refresh soa_retry soa_expire soa_min <<<"$soa_full"
if [[ ${soa_min:-} =~ ^[0-9]+$ && ${soa_expire:-} =~ ^[0-9]+$ && ${soa_retry:-} =~ ^[0-9]+$ && ${soa_refresh:-} =~ ^[0-9]+$ ]]; then
  info "SOA timers" "refresh $soa_refresh s · retry $soa_retry s · expire $soa_expire s · negative TTL $soa_min s"
  soa_notes=()
  ((soa_expire < 604800)) && soa_notes+=("expire under 1 week")
  ((soa_retry >= soa_refresh)) && soa_notes+=("retry not shorter than refresh")
  ((soa_min > 86400)) && soa_notes+=("negative TTL over 1 day")
  if ((${#soa_notes[@]})); then
    tip "SOA timers" "unusual: $(printf '%s, ' "${soa_notes[@]}" | sed 's/, $//')"
    fix soa-timers 4 "DNS: bring the SOA timers to usual values" \
      "Typical values: refresh 7200-86400, retry 3600 (shorter than refresh), expire 1209600-2419200" \
      "(2-4 weeks), negative TTL 300-3600: a mistaken \"does not exist\" answer stays cached that long." \
      "Managed DNS usually fixes them itself; on your own server they are in the SOA record."
  fi
fi

# A wildcard answers for every name, including typos and forgotten subdomains.
wild=$(dig +norec +noall +answer A "nx-$RANDOM$RANDOM.$domain" @"$first_ns" 2>/dev/null \
  | awk '$4 == "A" || $4 == "CNAME" {print $NF; exit}')
[[ -n $wild ]] && info "Wildcard DNS" "any unknown name resolves (to ${wild%.}): typos and forgotten subdomains look valid"
# TTLs: very low ones add load and hide little; very high ones make every change slow.
ttl_a=$(dig +norec +noall +answer A "$domain" @"$first_ns" 2>/dev/null | awk '$4 == "A" {print $2; exit}')
ttl_mx=$(dig +norec +noall +answer MX "$domain" @"$first_ns" 2>/dev/null | awk '$4 == "MX" {print $2; exit}')
if [[ ${ttl_a:-} =~ ^[0-9]+$ || ${ttl_mx:-} =~ ^[0-9]+$ ]]; then
  info "TTL" "A ${ttl_a:--} s · MX ${ttl_mx:--} s"
  if [[ ${ttl_a:-0} =~ ^[0-9]+$ ]] && ((ttl_a > 0 && ttl_a < 60)); then
    tip "TTL" "A record TTL of $ttl_a s: very short, every visitor causes a new DNS query"
  elif [[ ${ttl_a:-0} =~ ^[0-9]+$ ]] && ((ttl_a > 86400)); then
    tip "TTL" "A record TTL of $ttl_a s: a change takes more than a day to reach everybody"
  fi
fi

# A zone transfer must be refused to anonymous clients.
axfr_open=()
[[ -n $PASSIVE ]] && deleg_ns_axfr="" || deleg_ns_axfr=$deleg_ns
for ns in $deleg_ns_axfr; do
  n=$(dig +time=3 +tries=1 AXFR "$domain" @"$ns" 2>/dev/null | grep -v '^;' | grep -c 'IN')
  ((n > 2)) && axfr_open+=("$ns ($n records)")
done
if [[ -n $PASSIVE ]]; then
  info "Zone transfer (AXFR)" "not tested (passive mode)"
elif ((${#axfr_open[@]})); then
  fail "Zone transfer (AXFR)" "ALLOWED on: ${axfr_open[*]}"
  fix axfr 1 "DNS: anyone can download the whole zone (AXFR)" \
    "Allow zone transfers only to the IP addresses of your secondary nameservers:" \
    "= BIND:      allow-transfer { <secondary IPs>; };   (no secondaries: { none; })" \
    "= Knot DNS:  an acl with \"action: transfer\" for the secondaries only" \
    "= PowerDNS:  allow-axfr-ips=<secondary IPs>" \
    "Managed DNS or shared hosting: report it to the provider."
else
  ok "Zone transfer (AXFR)" "refused by all nameservers"
fi

dnskeys=$(dig +norec +noall +answer DNSKEY "$domain" @"$first_ns" 2>/dev/null \
  | awk '$4 == "DNSKEY" {k = ""; for (i = 8; i <= NF; i++) k = k $i; print $5, $6, $7, k}')
if [[ -z $dnskeys ]]; then
  info "DNSKEY" "none (zone not signed)"
else
  info "DNSKEY" "$(echo "$dnskeys" | wc -l | tr -d ' ') key(s) published"
  while read -r flags _ alg _; do
    role="ZSK"; [[ $flags == 257 ]] && role="KSK"
    detail "flags $flags ($role)  alg $alg $(alg_name "$alg")"
  done <<<"$dnskeys"
fi

# --------------------------------------------------------------- [5] DNSSEC ----
# Fills ds_lines with the steps that give the registrar the DS of the zone's key-signing
# keys (flags 257; every key when none has that flag), plus the DNSKEY alternative.
ds_steps() {
  local computed ksk tag flags alg sha256 _s384 _s1 kflags kproto kalg key
  ds_lines=()
  if ! have python3; then
    ds_lines+=("Copy the DS record shown by your DNS provider (python3 computes it here).")
    return
  fi
  computed=$(paste -d ' ' <(printf '%s\n' "$dnskeys" | python3 -I -c "$PY_DS" "$domain") \
    <(printf '%s\n' "$dnskeys"))
  ksk=257
  awk '$2 == 257 {f = 1} END {exit !f}' <<<"$computed" || ksk=""
  ds_lines+=("In the DNSSEC section of the ${registrar_name:-registrar}'s panel, add:")
  while read -r tag flags alg sha256 _s384 _s1 kflags kproto kalg key; do
    [[ -z $ksk || $flags == "$ksk" ]] || continue
    ds_lines+=("= Key tag      $tag" "= Algorithm    $alg ($(alg_name "$alg"))"
      "= Digest type  2 (SHA-256)" "= Digest       $sha256"
      "As a single record (some panels want this form):"
      "= $domain. IN DS $tag $alg 2 $sha256"
      "If the panel asks for the public key (DNSKEY) instead:"
      "= Flags $kflags · Protocol $kproto · Algorithm $kalg"
      "= Public key   $key")
  done <<<"$computed"
  [[ -n $ksk ]] && awk '$2 == 256 {f = 1} END {exit !f}' <<<"$computed" &&
    ds_lines+=("Give only this key (flags 257): the zone-signing keys (flags 256) are not needed.")
  ds_lines+=("The registry publishes it within minutes to a few hours: then run this script again.")
}
# The DS records currently at the registry, as zone-file lines.
reg_ds_lines() {
  local tag alg dtype digest
  while read -r tag alg dtype digest; do
    [[ -n $tag ]] && printf '= %s. IN DS %s %s %s %s\n' "$domain" "$tag" "$alg" "$dtype" "$digest"
  done <<<"$reg_ds"
}
dnssec_broken_hint="If it cannot be fixed soon, remove the DS at the registrar: unsigned works, broken does not."

section 5 "DNSSEC" "registry DS vs. zone DNSKEY, signatures on $first_ns, validation via $RESOLVER"

if [[ -z $reg_ds && -z $dnskeys ]]; then
  tip "DNSSEC" "not enabled: protects DNS answers (MX, SPF, DKIM) from forgery"
  fix dnssec 4 "DNSSEC: enable it" \
    "1. Turn on signing where the zone is hosted (nameservers: $(echo "$deleg_ns" | paste -sd ' ' -))." \
    "   In a DNS provider or hosting panel: the DNSSEC option of the zone. Own server:" \
    "= BIND 9.16+:  dnssec-policy default;   (in the zone statement)" \
    "= Knot DNS:    dnssec-signing: on       (in the zone section)" \
    "= PowerDNS:    pdnsutil secure-zone $domain" \
    "2. Run this script again: it will then show the DS to give to the registrar."
elif [[ -z $reg_ds ]]; then
  warn "Status" "zone is signed but no DS at the registry (not validated yet)"
  ds_steps
  fix dnssec 2 "DNSSEC: give the DS record to the registrar" \
    "The zone is already signed by its nameservers: only the link at the .$parent registry" \
    "is missing." "${ds_lines[@]}"
elif [[ -z $dnskeys ]]; then
  fail "Status" "DS at the registry but zone NOT signed: domain broken for validating resolvers"
  fix dnssec 1 "DNSSEC: remove the DS at the registrar now (or sign the zone again)" \
    "Validating resolvers (public ones and most providers') cannot resolve the domain." \
    "Either turn signing back on at the DNS provider, or remove at ${registrar_name:-the registrar}:" \
    "$(reg_ds_lines)" \
    "Resolvers recover after the DS TTL (usually 1-24 hours)."
else
  if have python3; then
    computed=$(printf '%s\n' "$dnskeys" | python3 -I -c "$PY_DS" "$domain")
    ds_good=0; ds_bad=(); ds_sha1=()
    while read -r tag alg dtype digest; do
      if [[ $dtype != [124] ]]; then
        info "DS $tag alg $alg" "digest type $dtype cannot be verified here"
        continue
      fi
      match=""
      while read -r ktag kflags kalg sha256 sha384 sha1; do
        [[ $ktag == "$tag" && $kalg == "$alg" ]] || continue
        if [[ $dtype == 2 && $digest == "$sha256" ]] || [[ $dtype == 4 && $digest == "$sha384" ]]; then
          match="key $ktag (flags $kflags)"
        elif [[ $dtype == 1 && $digest == "$sha1" ]]; then
          match="key $ktag (flags $kflags)"
          ds_sha1+=("= $domain. IN DS $ktag $kalg 2 $sha256")
        fi
      done <<<"$computed"
      if [[ -n $match ]]; then
        ok "DS $tag alg $alg" "matches $match"
        ds_good=$((ds_good + 1))
        [[ $dtype == 1 ]] && tip "DS $tag alg $alg" "digest type 1 (SHA-1) is deprecated: use SHA-256 (type 2)"
      else
        fail "DS $tag alg $alg" "matches NO published key (wrong algorithm, tag or digest?)"
        ds_bad+=("= $domain. IN DS $tag $alg $dtype $digest")
      fi
    done <<<"$reg_ds"
    ((${#ds_sha1[@]})) && fix ds-sha1 4 "DNSSEC: replace the SHA-1 DS with a SHA-256 one" \
      "Digest type 1 (SHA-1) is deprecated. Add this DS at the registrar, then remove the SHA-1 one:" \
      "${ds_sha1[@]}"
    if ((${#ds_bad[@]} && ds_good)); then
      fix ds-stale 1 "DNSSEC: remove the stale DS at the registrar" \
        "These DS records match no key of the zone (an old key or a typo):" "${ds_bad[@]}" \
        "The domain still validates through the DS that matches; remove only these."
    elif ((${#ds_bad[@]})); then
      ds_steps
      fix ds-stale 1 "DNSSEC: replace the DS at the registrar (the domain does not validate)" \
        "No DS matches the zone's keys. Remove:" "${ds_bad[@]}" "${ds_lines[@]}" \
        "$dnssec_broken_hint"
    fi
  else
    info "DS vs DNSKEY" "skipped (python3 not available)"
  fi
fi

# Algorithms in use, and whether the DS can be kept in sync automatically (CDS/CDNSKEY, RFC 8078).
if [[ -n $dnskeys ]]; then
  algs_ok=""
  dnskey_algs=$(awk '{print $3}' <<<"$dnskeys" | sort -un | paste -sd ' ' -)
  for alg in $dnskey_algs; do
    case $alg in
      1|3|6|12)
        warn "DNSSEC algorithm $alg" "$(alg_name "$alg"): no longer accepted by many validating resolvers"
        fix "alg-$alg" 2 "DNSSEC: move the zone to a modern algorithm" \
          "Algorithm $alg is obsolete. Roll the keys over to 13 (ECDSAP256SHA256) or 15 (ED25519);" \
          "do it with the algorithm rollover procedure of your DNS software, never by just swapping keys." ;;
      5|7)
        tip "DNSSEC algorithm $alg" "$(alg_name "$alg"): SHA-1 based, move to 13 (ECDSAP256SHA256) or 15 (ED25519)"
        fix "alg-$alg" 4 "DNSSEC: move the zone away from SHA-1 signatures" \
          "Algorithm $alg is deprecated. Plan an algorithm rollover to 13 (ECDSAP256SHA256) or 15" \
          "(ED25519) with your DNS software or provider; the DS at the registrar changes too." ;;
      *) algs_ok+="${algs_ok:+, }$alg ($(alg_name "$alg"))" ;;
    esac
  done
  [[ -n $algs_ok ]] && ok "DNSSEC algorithms" "$algs_ok"
  cds_any=$({ dig +norec +short +time=3 +tries=1 CDS "$domain" @"$first_ns"
              dig +norec +short +time=3 +tries=1 CDNSKEY "$domain" @"$first_ns"; } 2>/dev/null | grep -v '^;')
  if [[ -n $cds_any ]]; then
    ok "CDS/CDNSKEY" "published: the registry can keep the DS up to date by itself"
  else
    info "CDS/CDNSKEY" "not published: the DS must be changed by hand at every key change"
  fi
fi

# Denial of existence: plain NSEC lets anyone list every name in the zone (zone walking).
if [[ -n $dnskeys ]]; then
  denial=$(dig +norec +dnssec +noall +authority +answer A "nx-$RANDOM$RANDOM.$domain" @"$first_ns" 2>/dev/null)
  nsec_next=$(awk '$4 == "NSEC" {print $5; exit}' <<<"$denial")
  if [[ -n $(awk '$4 == "NSEC3"' <<<"$denial") ]]; then
    ok "Denial of existence" "NSEC3 (names hashed: the zone cannot be listed)"
    read -r n3_iter n3_salt < <(awk '$4 == "NSEC3" {print $7, $8; exit}' <<<"$denial")
    if [[ ${n3_iter:-} =~ ^[0-9]+$ ]] && { ((n3_iter > 0)) || [[ ${n3_salt:--} != - ]]; }; then
      tip "NSEC3 parameters" "iterations $n3_iter, salt ${n3_salt:--}: RFC 9276 asks for 0 iterations and no salt"
      fix nsec3-params 4 "DNSSEC: use the recommended NSEC3 parameters" \
        "Extra iterations and a salt only slow resolvers down. In the zone's DNSSEC policy:" \
        "= BIND 9.16+:  nsec3param iterations 0 optout no salt-length 0;" \
        "= PowerDNS:    pdnsutil set-nsec3 $domain '1 0 0 -' && pdnsutil rectify-zone $domain" \
        "Managed DNS: ask the provider."
    fi
  elif [[ -z $nsec_next ]]; then
    info "Denial of existence" "no NSEC/NSEC3 record returned"
  elif [[ $nsec_next == '\000.'* ]]; then
    ok "Denial of existence" "NSEC with minimal answers (the zone cannot be listed)"
  else
    tip "Denial of existence" "plain NSEC: every name in the zone can be listed (zone walking); consider NSEC3"
    fix nsec3 4 "DNSSEC: switch to NSEC3 so the zone cannot be listed" \
      "= BIND 9.16+:  nsec3param iterations 0 optout no salt-length 0;  (in the dnssec-policy)" \
      "= PowerDNS:    pdnsutil set-nsec3 $domain '1 0 0 -' && pdnsutil rectify-zone $domain" \
      "Managed DNS: ask the provider whether NSEC3 is available."
  fi
fi

# Signature lifetime: signatures that expire make the whole zone fail validation.
if [[ -n $dnskeys ]]; then
  for rtype in SOA DNSKEY; do
    sig_exp=$(dig +norec +dnssec +noall +answer "$rtype" "$domain" @"$first_ns" 2>/dev/null \
      | awk -v t="$rtype" '$4 == "RRSIG" && $5 == t {print $9; exit}')
    if [[ -z $sig_exp ]]; then
      fail "Signature ($rtype)" "no RRSIG returned by $first_ns"
      fix rrsig 1 "DNSSEC: $first_ns serves the zone without signatures" \
        "Check that DNSSEC signing is still enabled for the zone on every nameserver." \
        "$dnssec_broken_hint"
    elif have python3 && sl=$(python3 -I -c "$PY_SIGLEFT" "$sig_exp" 2>/dev/null); then
      hours=${sl##* }; when=${sl% *}
      if ((hours < 0)); then fail "Signature ($rtype)" "EXPIRED on $when"
      elif ((hours < 24)); then warn "Signature ($rtype)" "expires in $hours h ($when)"
      else ok "Signature ($rtype)" "valid until $when ($((hours / 24)) days)"; fi
      if ((hours < 24)); then
        fix rrsig $((hours < 0 ? 1 : 2)) "DNSSEC: the signatures are not being renewed" \
          "The DNS server must re-sign the zone automatically: check that signing is still" \
          "enabled and look at its logs (BIND: rndc signing -list $domain; PowerDNS:" \
          "pdnsutil check-zone $domain; managed DNS: ask the provider)." \
          "$dnssec_broken_hint"
      fi
    else
      info "Signature ($rtype)" "expires $sig_exp"
    fi
  done
fi

if [[ -n $reg_ds ]]; then
  if have delv; then
    v=$(delv @"$RESOLVER" "$domain" SOA 2>&1 | head -1)
    case $v in
      *"fully validated"*) ok "Validation (delv)" "fully validated" ;;
      *"unsigned answer"*) warn "Validation (delv)" "unsigned answer" ;;
      *) fail "Validation (delv)" "${v:-no output}" ;;
    esac
    [[ $v == *"fully validated"* ]] || dnssec_invalid=1
  else
    flags=$(dig +dnssec +noall +comments SOA "$domain" @"$RESOLVER" 2>/dev/null | grep -m1 'flags:')
    if [[ $flags == *" ad"* ]]; then ok "Validation (AD flag)" "authenticated by $RESOLVER"
    else fail "Validation (AD flag)" "not authenticated by $RESOLVER"; dnssec_invalid=1; fi
  fi
fi

if [[ -n ${dnssec_invalid:-} ]]; then
  fix dnssec-invalid 1 "DNSSEC: the domain does not validate" \
    "Fix the DNSSEC errors listed in section 5. Detailed diagnosis, with the broken link:" \
    "= https://dnsviz.net/d/$domain/dnssec/" \
    "$dnssec_broken_hint"
fi

# ---------------------------------------------------------- [6] web / TLS ----
section 6 "WEB & TLS" "resolver $RESOLVER + direct connections to the web server"

has_ipv6=""
for host in "$domain" "www.$domain"; do
  cname=$(q CNAME "$host" | head -1 | sed 's/\.$//')
  a=$(q A "$host" | grep -E '^[0-9.]+$' | paste -sd ' ' -)
  aaaa=$(q AAAA "$host" | grep ':' | paste -sd ' ' -)
  [[ -n $aaaa ]] && has_ipv6=1
  label="apex"; [[ $host == "www.$domain" ]] && label="www"
  if [[ -z $a && -z $aaaa ]]; then
    warn "Address ($label)" "no A/AAAA record"
    if [[ $label == www && ( -n ${web_ip:-} || -n ${web_ip6:-} ) ]]; then
      fix addr-www 2 "Web: www.$domain does not exist" "Add it as an alias of the domain:" \
        "= www.$domain. IN CNAME $domain."
    else
      fix "addr-$label" 2 "Web: $host has no address" \
        "Add an A record (and AAAA with IPv6) pointing to the web server:" \
        "= $host. IN A <web server IPv4>"
    fi
  else
    ok "Address ($label)" "${a}${a:+${aaaa:+ }}${aaaa}${cname:+ (CNAME → $cname)}"
  fi
done
[[ -z $has_ipv6 ]] && tip "IPv6" "no AAAA record (site reachable over IPv4 only)"

if have curl; then
  http="000 "
  pin_host "$domain" 80 &&
    http=$(curl -s -o /dev/null -m "$NET_TIMEOUT" "${PIN[@]}" -w '%{http_code} %{redirect_url}' "http://$domain/" 2>/dev/null)
  code=${http%% *}; loc=${http#* }
  if [[ $code =~ ^30[1278]$ && $loc == https://* ]]; then
    ok "HTTP to HTTPS" "$code redirect to $loc"
  elif [[ $code == 000 ]]; then
    warn "HTTP (port 80)" "no response"
  else
    warn "HTTP to HTTPS" "HTTP $code, no redirect to HTTPS"
  fi
  if [[ ! ( $code =~ ^30[1278]$ && $loc == https://* ) ]]; then
    # shellcheck disable=SC2016  # nginx and Apache variables, not shell ones
    fix https-redirect 2 "Web: redirect http:// to https://" \
      "Port 80 should answer with a permanent redirect (301) to the HTTPS address." \
      "In a hosting panel look for a \"force HTTPS\" option. Apache (.htaccess):" \
      "= RewriteEngine On" \
      "= RewriteCond %{HTTPS} off" \
      '= RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' \
      "nginx (server block on port 80):" \
      '= return 301 https://$host$request_uri;'
  fi

  # Follow redirects (never into private addresses) and keep the headers of the final response.
  fetch_follow "https://$domain/" || true
  final_url=$FETCH_URL
  if [[ -n $FETCH_BLOCKED ]]; then
    warn "HTTPS" "$FETCH_ERR"
  elif [[ -n $FETCH_ERR ]]; then
    fail "HTTPS" "$FETCH_ERR"
    fix "cert-$domain" 1 "Web: HTTPS does not work for $domain" \
      "Usually a missing, expired or wrong-name certificate. In a hosting panel: the" \
      "SSL/TLS section (automatic certificates). Own server, with certbot:" \
      "= certbot --apache -d $domain -d www.$domain   (or --nginx)"
  elif [[ ! -s $tmpdir/headers ]]; then
    fail "HTTPS" "no response from https://$domain/"
    fix "website" 1 "Web: the site does not answer on HTTPS" \
      "Check that the web server listens on port 443 and that the firewall allows it."
  else
    headers=$(tr -d '\r' <"$tmpdir/headers" | awk '/^HTTP\//{buf = ""} {buf = buf $0 "\n"} END {printf "%s", buf}')
    status=$(printf '%s\n' "$headers" | head -1)
    ok "HTTPS" "$status (certificate trusted, hostname valid)"
    [[ $final_url != "https://$domain/" ]] && detail "final URL: $final_url"
    hdr() { printf '%s\n' "$headers" | grep -i "^$1:" | head -1 | cut -d: -f2- | sed 's/^ *//'; }
    hsts=$(hdr strict-transport-security)
    if [[ -z $hsts ]]; then
      tip "HSTS" "not set: browsers may still try plain HTTP first"
    elif [[ $hsts =~ max-age=([0-9]+) ]] && ((BASH_REMATCH[1] < 15768000)); then
      tip "HSTS" "$hsts (max-age below 6 months)"
    else
      ok "HSTS" "$hsts"
    fi
    if [[ -z $hsts || $hsts =~ max-age=([0-9]+) && ${BASH_REMATCH[1]} -lt 15768000 ]]; then
      fix hsts 4 "Web: send HSTS (one year)" \
        "Only when HTTPS works on the site; add includeSubDomains only if it works on every" \
        "subdomain too. Apache (.htaccess):" \
        '= Header always set Strict-Transport-Security "max-age=31536000"' \
        "nginx:" \
        '= add_header Strict-Transport-Security "max-age=31536000" always;'
    fi
    sec_missing=()
    csp=$(hdr content-security-policy)
    [[ -z $csp ]] && sec_missing+=("Content-Security-Policy")
    [[ -z $(hdr x-frame-options) && $csp != *frame-ancestors* ]] && sec_missing+=("X-Frame-Options")
    [[ -z $(hdr x-content-type-options) ]] && sec_missing+=("X-Content-Type-Options")
    [[ -z $(hdr referrer-policy) ]] && sec_missing+=("Referrer-Policy")
    [[ -z $(hdr permissions-policy) ]] && sec_missing+=("Permissions-Policy")
    if ((${#sec_missing[@]})); then
      tip "Security headers" "missing: ${sec_missing[*]}"
      hdr_lines=()
      for h in "${sec_missing[@]}"; do
        case $h in
          X-Content-Type-Options) v="nosniff" ;;
          X-Frame-Options) v="SAMEORIGIN" ;;
          Referrer-Policy) v="strict-origin-when-cross-origin" ;;
          Permissions-Policy) v="camera=(), microphone=(), geolocation=()" ;;
          Content-Security-Policy) h="Content-Security-Policy-Report-Only"; v="default-src 'self'" ;;
        esac
        hdr_lines+=("= Header always set $h \"$v\"")
      done
      [[ " ${sec_missing[*]} " == *" Content-Security-Policy "* ]] && hdr_lines+=(
        "Content-Security-Policy: start in Report-Only mode, fix what the browser console"
        "reports, then rename the header to Content-Security-Policy.")
      fix sec-headers 4 "Web: add the missing security headers" \
        "Starting values for Apache (.htaccess); nginx: add_header Name \"value\" always;" \
        "${hdr_lines[@]}"
    else
      ok "Security headers" "all common headers present"
    fi

    # HTTP version, and HTTP/3 announced through Alt-Svc.
    case $FETCH_HTTP in
      3) ok "HTTP version" "HTTP/3" ;;
      2) if [[ $(hdr alt-svc) == *h3* ]]; then ok "HTTP version" "HTTP/2 (HTTP/3 announced)"
         else ok "HTTP version" "HTTP/2"; fi ;;
      1*)
        tip "HTTP version" "HTTP/$FETCH_HTTP only: HTTP/2 loads pages faster over one connection"
        fix http2 4 "Web: enable HTTP/2" \
          "= Apache:  Protocols h2 http/1.1   (with mod_http2, and an MPM event or worker)" \
          "= nginx:   listen 443 ssl;  http2 on;" \
          "Shared hosting: look for the HTTP/2 option in the panel." ;;
    esac

    # Software and version in the headers help attackers pick the right exploit.
    ver_hdr=()
    for h in server x-powered-by; do
      hv=$(hdr "$h")
      [[ $hv =~ [0-9]+\.[0-9]+ ]] && ver_hdr+=("$h: $hv")
    done
    if ((${#ver_hdr[@]})); then
      tip "Version in headers" "${ver_hdr[*]}"
      fix version-headers 4 "Web: stop announcing software versions" \
        "= Apache:  ServerTokens Prod   and   ServerSignature Off" \
        "= nginx:   server_tokens off;" \
        "= PHP:     expose_php = Off   (php.ini)" \
        "Shared hosting: ask the provider."
    fi

    # Cookies set by the home page: Secure, HttpOnly and SameSite.
    cookie_issues=()
    while IFS= read -r c; do
      [[ -n $c ]] || continue
      cname=${c#*: }; cname=${cname%%=*}
      miss=""
      grep -qi ';[[:space:]]*secure' <<<"$c" || miss+="Secure "
      grep -qi ';[[:space:]]*httponly' <<<"$c" || miss+="HttpOnly "
      grep -qi ';[[:space:]]*samesite' <<<"$c" || miss+="SameSite "
      [[ -n $miss ]] && cookie_issues+=("$cname lacks ${miss% }")
    done < <(printf '%s\n' "$headers" | grep -i '^set-cookie:')
    if ((${#cookie_issues[@]})); then
      tip "Cookies" "$(printf '%s; ' "${cookie_issues[@]}" | sed 's/; $//')"
      fix cookies 4 "Web: set the cookie flags" \
        "Secure keeps the cookie off plain HTTP, HttpOnly hides it from scripts, SameSite limits" \
        "cross-site requests. In the application or the web server, for example:" \
        "= Apache:  Header always edit Set-Cookie ^(.*)\$ \"\$1; Secure; HttpOnly; SameSite=Lax\"" \
        "= PHP:     session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax"
    fi

    # HSTS preload: the directive is a promise that is hard to take back.
    if [[ $hsts == *[Pp]reload* ]]; then
      hsts_age=0; [[ $hsts =~ max-age=([0-9]+) ]] && hsts_age=${BASH_REMATCH[1]}
      if ((hsts_age < 31536000)) || [[ $hsts != *[Ii]ncludeSubDomains* ]]; then
        warn "HSTS preload" "'preload' without max-age of at least 1 year and includeSubDomains: not eligible"
      else
        info "HSTS preload" "eligible for the preload list (hstspreload.org); removal later takes months"
      fi
    fi

    # security.txt (RFC 9116): where researchers can report a problem. Same site only, no redirects.
    sec_body=""
    for sh in "$domain" "www.$domain"; do
      pin_host "$sh" 443 || continue
      sec_body=$(curl -sS -m "$NET_TIMEOUT" "${PIN[@]}" --proto '=https' --max-filesize 65536 \
        "https://$sh/.well-known/security.txt" 2>/dev/null | head -c 65536)
      [[ $sec_body == *[Cc]ontact:* ]] && break
      sec_body=""
    done
    if [[ -z $sec_body ]]; then
      tip "security.txt" "not published: researchers cannot tell where to report a problem"
      fix security-txt 4 "Web: publish /.well-known/security.txt" \
        "A small text file (RFC 9116). Serve it over HTTPS at /.well-known/security.txt:" \
        "= Contact: mailto:security@$domain" \
        "= Expires: $(date -u -d '+1 year' '+%Y-%m-%dT00:00:00Z' 2>/dev/null || echo 2027-12-31T00:00:00Z)" \
        "Expires is required and must be renewed at least once a year."
    else
      sec_exp=$(printf '%s\n' "$sec_body" | tr -d '\r' | awk 'tolower($1) == "expires:" {print $2; exit}')
      sec_days=""
      if [[ -n $sec_exp ]] && have python3; then
        sec_days=$(python3 -I -c 'import sys, datetime as d
e = d.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
print((e - d.datetime.now(d.timezone.utc)).days)' "$sec_exp" 2>/dev/null)
      fi
      if [[ -z $sec_exp ]]; then
        tip "security.txt" "published, but without the required Expires field"
      elif [[ $sec_days =~ ^-[0-9]+$ ]]; then
        warn "security.txt" "expired on $sec_exp: researchers are told to ignore it"
        fix security-txt-exp 2 "Web: renew security.txt" "Change the Expires field of /.well-known/security.txt to a date within a year."
      else
        ok "security.txt" "published${sec_days:+, valid for $sec_days more days}"
      fi
    fi
  fi
else
  info "HTTP/HTTPS" "skipped (curl not available)"
fi

# Renewal advice for the website certificate (priority 1 expired, 2 expiring).
cert_renew_fix() {
  fix "cert-$domain" "$1" "Web: renew the certificate of $domain (${enddate:-expiry unknown})" \
    "Automatic renewal is not working. In a hosting panel: the SSL/TLS section and its" \
    "log. Own server with certbot, to see the error:" \
    "= certbot renew --dry-run"
}
if have openssl && ! pin_host "$domain" 443; then
  info "TLS (port 443)" "not contacted: $domain has no public address"
elif have openssl; then
  tls=$(run_to "$NET_TIMEOUT" openssl s_client -connect "$PIN_ADDR:443" -servername "$domain" -status </dev/null 2>/dev/null)
  cert=$(printf '%s\n' "$tls" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p')
  if [[ -n $cert ]]; then
    proto=$(printf '%s\n' "$tls" | grep -m1 -E '^ *Protocol *:' | awk -F: '{gsub(/ /, "", $2); print $2}')
    issuer=$(printf '%s\n' "$cert" | openssl x509 -noout -issuer 2>/dev/null | sed -e 's/^issuer= *//' -e 's/.*O *= *\([^,\/]*\).*/\1/')
    startdate=$(printf '%s\n' "$cert" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
    enddate=$(printf '%s\n' "$cert" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    sans=$(printf '%s\n' "$cert" | openssl x509 -noout -text 2>/dev/null \
      | grep -A1 'Subject Alternative Name' | tail -1 | sed -e 's/DNS://g' -e 's/^ *//')
    # Prefer ISO dates and a day count when python3 is available.
    end_left=""
    if have python3; then
      s=$(python3 -I -c "$PY_DAYS" "$startdate" 2>/dev/null) && { start_days=${s##* }; startdate=${s%% *}; }
      e=$(python3 -I -c "$PY_DAYS" "$enddate" 2>/dev/null) && { enddate=${e%% *}; end_left=${e##* }; }
    fi
    if [[ $proto == TLSv1.3 ]]; then ok "TLS protocol" "$proto"
    elif [[ $proto == TLSv1.2 ]]; then
      tip "TLS protocol" "$proto (TLS 1.3 not offered)"
      fix tls13 4 "Web: enable TLS 1.3" \
        "= Apache:  SSLProtocol -all +TLSv1.2 +TLSv1.3" \
        "= nginx:   ssl_protocols TLSv1.2 TLSv1.3;" \
        "Shared hosting: ask the provider."
    else info "TLS protocol" "${proto:-unknown}"; fi
    info "Certificate issuer" "${issuer:-unknown}"
    info "Certificate names" "${sans:-unknown}"
    info "Certificate issued" "${startdate:-unknown}"
    ctext=$(printf '%s\n' "$cert" | openssl x509 -noout -text 2>/dev/null)
    key_alg=$(grep -m1 'Public Key Algorithm:' <<<"$ctext" | sed 's/.*: *//')
    key_bits=$(grep -m1 -oE 'Public-Key: \([0-9]+ bit' <<<"$ctext" | grep -oE '[0-9]+')
    sig_alg=$(grep -m1 'Signature Algorithm:' <<<"$ctext" | sed 's/.*: *//')
    case $key_alg in
      rsaEncryption) key_name="RSA" ;;
      id-ecPublicKey) key_name="EC" ;;
      *) key_name=${key_alg:-unknown} ;;
    esac
    info "Certificate key" "$key_name${key_bits:+ $key_bits bit}, signed with ${sig_alg:-unknown}"
    if [[ $key_name == RSA && ${key_bits:-4096} =~ ^[0-9]+$ ]] && ((${key_bits:-4096} < 2048)); then
      fail "Certificate key" "RSA $key_bits bit is too short (browsers reject it): use 2048 or more"
      fix "certkey-$domain" 1 "Web: replace the certificate with a stronger key" \
        "Issue a new certificate with an RSA key of 2048 bits or more (or an ECDSA P-256 key)."
    fi
    if [[ $sig_alg == *[Ss][Hh][Aa]1* || $sig_alg == *md5* ]]; then
      fail "Certificate signature" "$sig_alg is broken: browsers reject it"
      fix "certsig-$domain" 1 "Web: replace the certificate (weak signature)" \
        "The CA signed it with $sig_alg. Reissue it: current CAs use SHA-256 or better."
    fi
    if [[ ${start_days:-} =~ ^-?[0-9]+$ && ${end_left:-} =~ ^-?[0-9]+$ ]] && ((end_left - start_days > 398)); then
      tip "Certificate lifetime" "valid for $((end_left - start_days)) days: browsers distrust public certificates valid over 398 days"
    fi
    # The server must send the intermediate certificates too: browsers may hide the error, other clients do not.
    if grep -qE 'unable to get local issuer|unable to verify the first certificate|Verify return code: (20|21)' <<<"$tls"; then
      warn "Certificate chain" "incomplete: the server does not send the intermediate certificate (some clients will reject it)"
      fix "chain-$domain" 2 "Web: serve the full certificate chain" \
        "Install the certificate bundle (certificate + intermediates), not the certificate alone:" \
        "= Apache:  SSLCertificateFile fullchain.pem   (certbot gives fullchain.pem)" \
        "= nginx:   ssl_certificate fullchain.pem;"
    fi
    # OCSP stapling matters only when the certificate still names an OCSP responder.
    if grep -q 'OCSP - URI:' <<<"$ctext"; then
      if grep -q 'OCSP Response Status: successful' <<<"$tls"; then ok "OCSP stapling" "enabled"
      else info "OCSP stapling" "not enabled (the certificate names an OCSP responder)"; fi
    fi
    if ! printf '%s\n' "$cert" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
      fail "Certificate expiry" "$enddate (EXPIRED)"
      cert_renew_fix 1
    elif ! printf '%s\n' "$cert" | openssl x509 -noout -checkend 1209600 >/dev/null 2>&1; then
      warn "Certificate expiry" "$enddate (less than 14 days left)"
      cert_renew_fix 2
    else
      ok "Certificate expiry" "$enddate${end_left:+ ($end_left days left)}"
    fi
  else
    fail "TLS (port 443)" "no certificate received"
    fix "cert-$domain" 1 "Web: no certificate on port 443" \
      "Install a certificate for $domain and www.$domain (hosting panel: the SSL/TLS" \
      "section; own server: certbot --apache -d $domain -d www.$domain, or --nginx)."
  fi
fi

# Certificate coverage of the other web names, plus obsolete protocol test.
if have python3; then
  specs=()
  for sub in www mail webmail; do
    has_addr "$sub.$domain" && specs+=("tls|$sub.$domain|443|HTTPS $sub")
  done
  [[ -z $PASSIVE ]] && specs+=("legacy|$domain|443|Legacy TLS 443" "weakc|$domain|443|Weak ciphers 443")
  ((${#specs[@]})) && render <<<"$(NDM_PIN=$(probe_pins "${specs[@]}") python3 -I -c "$PY_PROBE" "${specs[@]}" 2>/dev/null)"
fi

# Certificate Transparency data is fetched once here (slow) and shown in its own section later.
CT_LIMIT=40
ct=""
[[ $CT_LOOKUP != off ]] && have python3 && ct=$(python3 -I -c "$PY_CT" "$domain" "$CT_LIMIT" 2>/dev/null)

# ----------------------------------------------------------------- [7] mail ----
# Sets (or adds) a tag in a DMARC record: dmarc_set RECORD TAG VALUE.
dmarc_set() {
  local out="" part t found="" parts=()
  IFS=';' read -r -a parts <<<"$1"
  for part in "${parts[@]+"${parts[@]}"}"; do
    part=$(printf '%s' "$part" | sed -e 's/^ *//' -e 's/ *$//')
    [[ -z $part ]] && continue
    t=$(printf '%s' "${part%%=*}" | tr '[:upper:]' '[:lower:]')
    if [[ $t == "$2" ]]; then part="$2=$3"; found=1; fi
    out+="${out:+; }$part"
  done
  [[ -n $found ]] || out+="; $2=$3"
  printf '%s' "$out"
}

# Value of a tag in a "tag=value; tag=value" record (DMARC, DKIM): kv_tag RECORD TAG
kv_tag() {
  printf '%s' "$1" | tr ';' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | awk -F= -v t="$2" 'tolower($1) == t {print substr($0, index($0, "=") + 1); exit}'
}

section 7 "MAIL (DNS)" "resolver $RESOLVER"

mx=$(q MX "$domain" | sort -n)
first_mx=""
mail_ips=()
if [[ -z $mx ]]; then
  warn "MX" "none (mail falls back to the A record)"
  fix mx 2 "Mail: publish an MX record" \
    "If the domain receives mail:" \
    "= $domain. IN MX 10 mail.$domain." \
    "If it must not receive mail, say so explicitly (null MX, RFC 7505) and block senders:" \
    "= $domain. IN MX 0 ." \
    "= $domain. IN TXT \"v=spf1 -all\""
elif [[ $mx == "0 ." ]]; then
  info "MX" "null MX: this domain accepts no mail"
else
  while read -r pref host; do
    host=${host%.}
    [[ -z $first_mx ]] && first_mx=$host
    if [[ -n $(q CNAME "$host") ]]; then
      fail "MX $pref $host" "target is a CNAME (not allowed by RFC 2181)"
      fix "mx-$host" 1 "Mail: the MX must point to a host name, not to an alias" \
        "$host is a CNAME. Point the MX to its target, or make $host an A record:" \
        "= $domain. IN MX $pref $(q CNAME "$host" | head -1)"
      continue
    fi
    host_addrs=$({ q4 "$host"; q6 "$host"; } | paste -sd ' ' -)
    if [[ -z $host_addrs ]]; then
      fail "MX $pref $host" "target has no A or AAAA record"
      fix "mx-$host" 1 "Mail: the MX host $host does not exist" \
        "Add its address, or change the MX to an existing mail host:" \
        "= $host. IN A <mail server IPv4>" \
        "= $host. IN AAAA <mail server IPv6>   (if it has one)"
      continue
    fi
    ok "MX $pref $host" "$host_addrs"
    for ip in $host_addrs; do
      [[ " ${mail_ips[*]-} " == *" $ip "* ]] || mail_ips+=("$ip")
    done
  done <<<"$mx"
fi

# Redundancy: one MX host, or MX hosts that share one address or one /24, fail together.
if [[ -n $mx && $mx != "0 ." ]]; then
  mx_n=$(sed '/^$/d' <<<"$mx" | wc -l | tr -d ' ')
  mx4=$(printf '%s\n' "${mail_ips[@]+"${mail_ips[@]}"}" | grep -E '^[0-9.]+$' | sort -u)
  mx4_n=$(sed '/^$/d' <<<"$mx4" | wc -l | tr -d ' ')
  mx4_nets=$(sed -e '/^$/d' -e 's/\.[0-9]*$//' <<<"$mx4" | sort -u | wc -l | tr -d ' ')
  if ((mx_n == 1)); then
    tip "MX redundancy" "a single MX host: while it is down, senders keep the mail queued and may give up after days"
  elif ((mx4_n >= 1 && mx4_nets == 1)); then
    tip "MX redundancy" "all the MX hosts are in the same network ($mx4_n address(es)): one outage takes them all"
  fi
fi

spf=$(txt "$domain" | grep -i '^v=spf1')
spf_count=$(printf '%s' "$spf" | grep -c .)
if ((spf_count == 0)); then
  warn "SPF" "missing"
  if [[ -n $mx && $mx != "0 ." ]]; then
    fix spf 2 "Mail: publish an SPF record" \
      "A starting point that authorizes the MX servers to send:" \
      "= $domain. IN TXT \"v=spf1 mx ~all\"" \
      "Add include:... for every service that sends mail as @$domain (hosting, newsletter," \
      "CRM, invoicing). Once sure that nothing is missing, change ~all to -all."
  else
    fix spf 2 "Mail: publish an SPF record" \
      "The domain receives no mail: if it also sends none, block every sender:" \
      "= $domain. IN TXT \"v=spf1 -all\""
  fi
elif ((spf_count > 1)); then
  fail "SPF" "$spf_count SPF records: only one is allowed (permerror)"
  spf_vals=()
  while IFS= read -r l; do spf_vals+=("= $l"); done <<<"$spf"
  fix spf 1 "Mail: merge the SPF records into one" \
    "With more than one SPF record receivers ignore all of them. Current records:" \
    "${spf_vals[@]}" \
    "Keep a single TXT record: v=spf1, all the mechanisms, one final ~all or -all."
else
  spf_l=$(printf '%s' "$spf" | tr '[:upper:]' '[:lower:]')
  case $spf_l in
    *" -all"*) ok "SPF" "hard fail (-all)" ;;
    *" ~all"*) ok "SPF" "soft fail (~all)" ;;
    *" ?all"*) warn "SPF" "neutral (?all): offers no protection" ;;
    *"+all"*|*" all"|*" all "*) fail "SPF" "+all: ANY server may send as this domain" ;;
    *redirect=*) ok "SPF" "delegated with redirect=" ;;
    *)         warn "SPF" "no 'all' mechanism" ;;
  esac
  case $spf_l in
    *" -all"*|*" ~all"*|*redirect=*) ;;
    *)
      spf_new=$(printf '%s' "$spf_l" | sed -E 's/ [+?]?all( |$)/ ~all\1/')
      [[ $spf_new == *" ~all"* ]] || spf_new+=" ~all"
      [[ $spf_l == *"+all"* || $spf_l == *" all" || $spf_l == *" all "* ]] && spf_prio=1 || spf_prio=2
      fix spf "$spf_prio" "Mail: end the SPF record with ~all" \
        "Without ~all or -all the record does not protect the domain. Suggested record:" \
        "= $domain. IN TXT \"$spf_new\"" \
        "Once sure that every sender is listed, use -all."
      ;;
  esac
  detail "$spf"
  if have python3; then
    # Full tree: every include expanded down to the authorized networks.
    # The domain's own servers: MX hosts and mail.<domain> send mail; the website only for matching.
    own_ips=()
    while read -r _ mxh; do
      mxh=${mxh%.}
      for ip in $(q4 "$mxh") $(q6 "$mxh"); do own_ips+=("$ip=MX $mxh"); done
    done <<<"${mx:-}"
    for ip in $(q4 "mail.$domain") $(q6 "mail.$domain"); do own_ips+=("$ip=mail.$domain"); done
    for ip in $(q4 "$domain") $(q6 "$domain"); do own_ips+=("$ip=website"); done
    for sub in www webmail; do
      for ip in $(q4 "$sub.$domain") $(q6 "$sub.$domain"); do own_ips+=("$ip=$sub.$domain"); done
    done
    while IFS=$'\t' read -r kind name _ _ ip; do
      [[ $kind == row && ( $ip =~ ^[0-9.]+$ || $ip == *:* ) && $name != "$domain" ]] && own_ips+=("$ip=$name")
    done <<<"${ct:-}"
    spf_tree=$(NDM_SPF_PROVIDERS=$SPF_PROVIDERS python3 -I -c "$PY_SPF" "$domain" "$RESOLVER" "${own_ips[@]+"${own_ips[@]}"}" 2>/dev/null)
    while IFS=$'\t' read -r kind depth term desc; do
      [[ $kind == row ]] || continue
      line="$(printf '%*s' $((depth * 3)) '')- $term"
      if [[ -n $desc ]]; then detail "$(printf '%-46s %s' "$line" "$desc")"; else detail "$line"; fi
    done <<<"$spf_tree"
    # Who may send: providers / mechanisms at the top level plus direct IPs.
    sender_list=$(awk -F'\t' '$1 == "sender" {
        if ($4 != "") s = $4 " (" $3 ")"; else if ($2 == "a" || $2 == "mx") s = $2 " of " $3; else s = $3
        out = out (out == "" ? "" : ", ") s } END {print out}' <<<"$spf_tree")
    direct_count=$(grep -c '^direct' <<<"$spf_tree")
    senders_txt=${sender_list:-none}
    ((direct_count)) && senders_txt+=" + $direct_count direct IP range(s)"
    info "SPF senders" "$senders_txt"
    while IFS=$'\t' read -r kind net labels ptr; do
      [[ $kind == direct ]] || continue
      [[ $labels == - ]] && labels=""
      [[ $ptr == - ]] && ptr=""
      if [[ -n $labels ]]; then
        ok "SPF $net" "this domain's ${labels}${ptr:+ (PTR $ptr)}"
      elif [[ -n $ptr && ( $ptr == "$domain" || $ptr == *".$domain" ) ]]; then
        ok "SPF $net" "PTR $ptr (a host of this domain)"
      else
        host_ip=${net%/32}; host_ip=${host_ip%/128}
        fwd=""
        [[ -n $ptr ]] && fwd_confirms "$ptr" "$host_ip" </dev/null && fwd=1
        related=""
        for rd in $RELATED_DOMAINS; do
          [[ -n $ptr && ( $ptr == "$rd" || $ptr == *".$rd" ) ]] && related=$rd
        done
        if [[ -n $related && -n $fwd ]]; then
          ok "SPF $net" "PTR $ptr (forward-confirmed host of related domain $related)"
        else
          check "SPF $net" "matches no host of this domain (A/AAAA, MX, CT names): intended?"
          fix "spf-$net" 3 "SPF: confirm that $net may send mail as @$domain" \
            "If it is yours (a VPS, a relay), give it a reverse DNS name in one of your" \
            "domains and add that domain to RELATED_DOMAINS. If you do not recognize it," \
            "remove it from the SPF record: it can send mail in your name."
          if [[ -z $ptr ]]; then
            detail "reverse DNS  none"
          elif [[ -n $fwd ]]; then
            detail "reverse DNS  $ptr (forward-confirmed)"
          else
            detail "reverse DNS  $ptr (does NOT resolve back to $host_ip: stale or generic PTR?)"
          fi
          if [[ -n $ptr ]]; then
            ptr_dom=$(reg_domain <<<"$ptr")
            [[ $ptr != "$domain" && $ptr != *".$domain" ]] && \
              detail "             belongs to another domain: $ptr_dom${related:+ (related)}"
          fi
          ipinfo_fetch "${host_ip%/*}"
          owner=$(ip_owner_summary "${host_ip%/*}")
          detail "owner        ${owner:-not available (RDAP/ASN lookup failed)}"
        fi
      fi
    done <<<"$spf_tree"
    while IFS=$'\t' read -r kind ip label covered; do
      # Only mail-sending hosts must be covered (MX, mail.<domain>).
      [[ $kind == covered && $label =~ (^|, )(MX |mail\.) ]] || continue
      if ((covered)); then ok "SPF covers $ip" "$label is authorized"
      else
        check "SPF covers $ip" "$label is NOT authorized: fine only if all its mail leaves via a relay"
        fix "spf-cover-$ip" 3 "SPF: authorize $label if it sends mail directly" \
          "If its mail does not leave through a relay, add it before the final all:" \
          "= ip$([[ $ip == *:* ]] && echo 6 || echo 4):$ip   (or: mx)"
      fi
    done <<<"$spf_tree"
    read -r _ spf_total spf_voids < <(awk -F'\t' '$1 == "total" {print $1, $2, $3}' <<<"$spf_tree")
    if [[ -z ${spf_total:-} ]]; then
      info "SPF DNS lookups" "could not be computed"
    elif ((spf_total > 10)); then
      fail "SPF DNS lookups" "$spf_total of 10 (permerror: receivers ignore this SPF)"
    elif ((spf_total >= 9)); then
      warn "SPF DNS lookups" "$spf_total of 10 (close to the limit)"
    else
      ok "SPF DNS lookups" "$spf_total of 10 (nested includes counted)"
    fi
    if ((${spf_total:-0} >= 9)); then
      fix spf-lookups $((spf_total > 10 ? 1 : 2)) "SPF: reduce the DNS lookups ($spf_total of 10)" \
        "Each include, a, mx, ptr, exists and redirect costs a lookup, nested ones too." \
        "Remove services you no longer use, replace a/mx with ip4:/ip6: of your own servers," \
        "never use ptr. Some providers offer a lighter (flattened) include."
    fi
    spf_loops=$(awk -F'\t' '$1 == "loops" {print $2; exit}' <<<"$spf_tree")
    if ((${spf_loops:-0} > 0)); then
      fail "SPF include loop" "an include leads back to itself (permerror): receivers ignore this SPF"
      fix spf-loop 1 "SPF: remove the include loop" \
        "An include refers (directly or through others) to a record that includes it again." \
        "See the tree above, marked (loop), and remove the include that closes the circle."
    fi
    if ((${spf_voids:-0} > 0)); then
      fix spf-void $((spf_voids > 2 ? 1 : 4)) "SPF: remove the mechanisms that find nothing" \
        "$spf_voids lookup(s) return no record: usually an include or a:/mx: name that no" \
        "longer exists (see the tree above). More than 2 make the whole SPF invalid."
    fi
    if ((${spf_voids:-0} > 2)); then
      fail "SPF void lookups" "$spf_voids of 2 (permerror)"
    elif ((${spf_voids:-0} > 0)); then
      tip "SPF void lookups" "$spf_voids of 2 (mechanisms that find nothing: remove them)"
    fi
  else
    lookups=$(printf '%s\n' "$spf" | tr ' ' '\n' \
      | grep -cEi '^[-+~?]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:|redirect=)')
    info "SPF DNS lookups" "$lookups top-level (nested includes not counted without python3)"
  fi
fi

dmarc=$(txt "_dmarc.$domain" | grep -i '^v=DMARC1')
if [[ -z $dmarc ]]; then
  warn "DMARC" "missing"
  fix dmarc 2 "Mail: publish a DMARC record" \
    "Start in monitoring mode, with an address that receives the daily reports:" \
    "= _dmarc.$domain. IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@$domain\"" \
    "The mailbox must exist. After 2-4 weeks of clean reports move to p=quarantine," \
    "then to p=reject."
else
  p=$(printf '%s' "$dmarc" | grep -oiE '(^|;) *p=[a-z]+' | sed 's/.*=//' | tr '[:upper:]' '[:lower:]')
  rua=$(printf '%s' "$dmarc" | grep -oiE 'rua=[^;]+' | sed 's/rua=//')
  case $p in
    reject|quarantine) ok "DMARC" "p=$p${rua:+, reports to $rua}" ;;
    none)              warn "DMARC" "p=none (monitoring only, no protection)" ;;
    *)                 fail "DMARC" "invalid or missing policy" ;;
  esac
  # The stricter record suggested after monitoring: p (and sp, if it was none) = quarantine.
  dmarc_strict() {
    local r
    r=$(dmarc_set "$1" p quarantine)
    [[ $r == *"sp=none"* ]] && r=$(dmarc_set "$r" sp quarantine)
    printf '%s' "$r"
  }
  case $p in
    none)
      if [[ -z $rua ]]; then
        dmarc_rua=$(dmarc_set "$dmarc" rua "mailto:dmarc@$domain")
        fix dmarc 2 "Mail: make DMARC protect the domain" \
          "1. First receive the daily reports (the mailbox must exist):" \
          "= _dmarc.$domain. IN TXT \"$dmarc_rua\"" \
          "2. When they show that all your own mail passes SPF or DKIM (2-4 weeks):" \
          "= _dmarc.$domain. IN TXT \"$(dmarc_strict "$dmarc_rua")\"" \
          "3. Later, with clean reports, use p=reject."
      else
        fix dmarc 2 "Mail: make DMARC protect the domain" \
          "When the reports show that all your own mail passes SPF or DKIM, switch to:" \
          "= _dmarc.$domain. IN TXT \"$(dmarc_strict "$dmarc")\"" \
          "Later, with clean reports, use p=reject."
      fi ;;
    reject|quarantine) ;;
    *)
      fix dmarc 1 "Mail: fix the DMARC record (the p= policy is missing or invalid)" \
        "= _dmarc.$domain. IN TXT \"$(dmarc_set "$dmarc" p none)\"" \
        "Valid policies: none (monitoring), quarantine, reject." ;;
  esac
  detail "$dmarc"
  if [[ -z $rua ]]; then
    tip "DMARC reports" "no rua= address: you receive no aggregate reports"
    # With p=none the DMARC fix above already includes the report address.
    [[ $p == none ]] || fix dmarc-rua 4 "Mail: receive the DMARC reports" \
      "= _dmarc.$domain. IN TXT \"$(dmarc_set "$dmarc" rua "mailto:dmarc@$domain")\"" \
      "The mailbox must exist. Reports sent to another domain need, in that domain:" \
      "= $domain._report._dmarc.<other domain>. IN TXT \"v=DMARC1\""
  fi
  # Details of the policy: subdomains, percentage, alignment, report addresses at other domains.
  sp=$(kv_tag "$dmarc" sp | tr '[:upper:]' '[:lower:]')
  pct=$(kv_tag "$dmarc" pct | tr -d ' ')
  if [[ $p == reject || $p == quarantine ]]; then
    if [[ $sp == none ]]; then
      warn "DMARC subdomains" "sp=none: the subdomains of this domain are not protected"
      fix dmarc-sp 2 "Mail: protect the subdomains too (sp=)" \
        "= _dmarc.$domain. IN TXT \"$(dmarc_set "$dmarc" sp "$p")\"" \
        "Subdomains that send mail themselves must pass SPF or DKIM aligned with their own name."
    fi
    if [[ $pct =~ ^[0-9]+$ ]] && ((pct < 100)); then
      tip "DMARC pct" "pct=$pct: the policy applies to only $pct% of the mail that fails"
      fix dmarc-pct 4 "Mail: apply the DMARC policy to all failing mail" \
        "pct is meant for a gradual roll-out. Once the reports are clean, remove it or set 100:" \
        "= _dmarc.$domain. IN TXT \"$(dmarc_set "$dmarc" pct 100)\""
    fi
  fi
  adkim=$(kv_tag "$dmarc" adkim | tr -d ' '); aspf=$(kv_tag "$dmarc" aspf | tr -d ' ')
  [[ -n $adkim$aspf ]] && info "DMARC alignment" "DKIM ${adkim:-r}, SPF ${aspf:-r} (r = relaxed, s = strict: exact domain match)"
  # Reports sent to another domain are delivered only if that domain agrees (RFC 7489, 7.1).
  ext_seen=" "
  for tag in rua ruf; do
    for addr in $(kv_tag "$dmarc" "$tag" | tr ',' ' '); do
      [[ $addr == *@* ]] || continue
      rd=${addr#*@}; rd=${rd%%[!A-Za-z0-9.-]*}; rd=$(printf '%s' "$rd" | tr '[:upper:]' '[:lower:]')
      [[ -n $rd && $rd != "$domain" && $rd != *".$domain" && $ext_seen != *" $rd "* ]] || continue
      ext_seen+="$rd "
      if txt "$domain._report._dmarc.$rd" | grep -qi '^v=DMARC1'; then
        ok "DMARC $tag" "$rd accepts the reports of this domain"
      else
        warn "DMARC $tag" "$rd does not authorize reports for $domain: they will not be delivered"
        fix "dmarc-ext-$rd" 2 "Mail: authorize the DMARC reports sent to $rd" \
          "Receivers send reports to another domain only if that domain agrees. In the DNS of $rd:" \
          "= $domain._report._dmarc.$rd. IN TXT \"v=DMARC1\"" \
          "Or use a report address inside $domain."
      fi
    done
  done
fi

# DNS cannot list the selectors in use: the ones in DKIM_SELECTORS are tried, in parallel.
dkim_found=(); dkim_revoked=(); dkim_tried=0
for sel in $DKIM_SELECTORS; do
  [[ $sel =~ ^[A-Za-z0-9._-]+$ ]] || continue
  dkim_tried=$((dkim_tried + 1))
  ((dkim_tried % 10 == 0)) && wait
  ( rec=$(txt "$sel._domainkey.$domain" | grep -i 'p=' | head -1)
    [[ -n $rec ]] && printf '%s\n' "$rec" >"$tmpdir/dkim_$sel" ) &
done
wait
dkim_keys=""
for sel in $DKIM_SELECTORS; do
  [[ -e $tmpdir/dkim_$sel ]] || continue
  rec=$(<"$tmpdir/dkim_$sel")
  key=$(kv_tag "$rec" p | tr -d ' ')
  if [[ -z $key ]]; then dkim_revoked+=("$sel"); continue; fi     # empty p= : revoked key
  dkim_found+=("$sel")
  kind=$(kv_tag "$rec" k | tr -d ' ')
  dkim_keys+="$sel"$'\t'"${kind:-rsa}"$'\t'"$key"$'\n'
done
dkim_key_fix() {
  fix "dkim-key-$1" "$2" "Mail: replace the DKIM key of $1 with a 2048-bit one" \
    "Publish a new 2048-bit key under a NEW selector, switch the signing to it, and remove the" \
    "old key only a week later (mail already sent is still checked against it):" \
    "= opendkim-genkey -b 2048 -s <new selector> -d $domain   (rspamd: rspamadm dkim_keygen -b 2048)" \
    "Hosting panels and mail services: look for the DKIM key size option."
}
if ((${#dkim_found[@]})); then
  ok "DKIM" "selector(s): ${dkim_found[*]}"
  dkim_sizes=""
  have python3 && dkim_sizes=$(printf '%s' "$dkim_keys" | python3 -I -c "$PY_DKIM" 2>/dev/null)
  for sel in "${dkim_found[@]}"; do
    ktype=""; kbits=""
    IFS=$'\t' read -r _ ktype kbits < <(awk -F'\t' -v s="$sel" '$1 == s' <<<"$dkim_sizes") || true
    detail "$sel: ${ktype:-key size not checked}${kbits:+, $kbits bit}"
    if [[ $ktype == rsa && $kbits =~ ^[0-9]+$ ]]; then
      if ((kbits < 1024)); then
        fail "DKIM $sel" "RSA $kbits bit key: can be broken, use 2048"; dkim_key_fix "$sel" 1
      elif ((kbits == 1024)); then
        tip "DKIM $sel" "RSA 1024 bit key: still accepted but weak, use 2048"; dkim_key_fix "$sel" 4
      fi
    fi
    if [[ $(kv_tag "$(<"$tmpdir/dkim_$sel")" t | tr -d ' ') == *y* ]]; then
      warn "DKIM $sel" "test mode (t=y): receivers may ignore failed signatures"
      fix "dkim-test-$sel" 2 "Mail: turn off the DKIM test mode of $sel" \
        "Once the signatures verify at the receivers, remove t=y from the TXT record of" \
        "$sel._domainkey.$domain: with it, DKIM failures are not enforced."
    fi
  done
else
  if ((${#dkim_revoked[@]})); then
    check "DKIM" "only revoked keys (empty p=) found, on ${dkim_revoked[*]}: active with another selector?"
  else
    check "DKIM" "not found with the $dkim_tried common selectors tried: active with another one?"
  fi
  fix dkim 3 "Mail: DKIM not found: add its selector, or turn it on" \
    "If DKIM is active, its selector is in the DKIM-Signature header of a message you sent" \
    "(s=...): add it to DKIM_SELECTORS in the config file, then run the script again." \
    "If it is not active, turn it on where the mail is sent (hosting panel or mail service;" \
    "own server: OpenDKIM or the DKIM module of rspamd) and publish the TXT record it gives."
fi
((${#dkim_revoked[@]})) && ((${#dkim_found[@]})) && info "DKIM revoked" "empty key (p=) on: ${dkim_revoked[*]}"

# MTA-STS state, also used by the notes of section 13 ("" when not published).
sts_mode=""; sts_max_age=""
if txt "_mta-sts.$domain" | grep -qi '^v=STSv1'; then
  policy=""
  # A policy file is a few lines: read at most 64 KiB, whatever the server sends.
  have curl && pin_host "mta-sts.$domain" 443 && policy=$(curl -sS -m "$NET_TIMEOUT" "${PIN[@]}" --proto '=https' --max-filesize 65536 \
    "https://mta-sts.$domain/.well-known/mta-sts.txt" 2>/dev/null | head -c 65536)
  mode=$(printf '%s\n' "$policy" | tr -d '\r' | awk -F': *' 'tolower($1) == "mode" {print $2; exit}')
  sts_mode=${mode:-unreadable}
  sts_max_age=$(printf '%s\n' "$policy" | tr -d '\r' | awk -F': *' 'tolower($1) == "max_age" {print $2; exit}')
  case $mode in
    enforce) ok "MTA-STS" "mode enforce" ;;
    testing) tip "MTA-STS" "mode testing (switch to enforce when reports are clean)" ;;
    none)    warn "MTA-STS" "mode none (policy disabled)" ;;
    *)       fail "MTA-STS" "TXT published but policy file not reachable or invalid" ;;
  esac
  case $mode in
    enforce) ;;
    testing|none)
      fix mta-sts "$([[ $mode == none ]] && echo 2 || echo 4)" "Mail: switch MTA-STS to enforce" \
        "When the TLS reports show no errors, set in the policy file mode: enforce and" \
        "max_age: 604800, then change the id in the _mta-sts TXT record:" \
        "= _mta-sts.$domain. IN TXT \"v=STSv1; id=$(date '+%Y%m%d')01\"" ;;
    *)
      fix mta-sts 1 "Mail: repair the MTA-STS policy file" \
        "It must be reachable over HTTPS with a valid certificate for mta-sts.$domain:" \
        "= https://mta-sts.$domain/.well-known/mta-sts.txt" \
        "and contain the lines version, mode, mx and max_age. If MTA-STS is not wanted," \
        "remove the _mta-sts TXT record." ;;
  esac
else
  tip "MTA-STS" "not published: senders cannot be required to use TLS"
  if [[ -n $mx && $mx != "0 ." ]]; then
    sts_mx=()
    while read -r _ h; do [[ -n $h ]] && sts_mx+=("= mx: ${h%.}"); done <<<"$mx"
    fix mta-sts 4 "Mail: publish MTA-STS (receive mail only over TLS)" \
      "1. Serve this file at https://mta-sts.$domain/.well-known/mta-sts.txt, answered" \
      "   directly with 200 (no redirects). mta-sts.$domain needs a DNS record pointing to" \
      "   that server (not through a proxy) and a valid certificate. If the hosting panel" \
      "   also wants www.mta-sts.$domain for the certificate, add it as an alias:" \
      "= www.mta-sts.$domain. IN CNAME mta-sts.$domain." \
      "   The file:" \
      "= version: STSv1" "= mode: testing" "${sts_mx[@]}" "= max_age: 86400" \
      "2. Publish the TXT record (change the id at every change of the file):" \
      "= _mta-sts.$domain. IN TXT \"v=STSv1; id=$(date '+%Y%m%d')01\"" \
      "3. Ask for the TLS reports (TLS-RPT):" \
      "= _smtp._tls.$domain. IN TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@$domain\"" \
      "4. After some weeks of clean reports: mode: enforce, max_age: 604800, new id."
  fi
fi
tlsrpt_on=""
if txt "_smtp._tls.$domain" | grep -qi '^v=TLSRPTv1'; then ok "TLS-RPT" "published"; tlsrpt_on=1
else info "TLS-RPT" "not published (useful together with MTA-STS)"; fi
if txt "default._bimi.$domain" | grep -qi '^v=BIMI1'; then ok "BIMI" "published"
else info "BIMI" "not published (optional brand logo in mailboxes)"; fi

# DANE: TLSA records of the MX hosts (RFC 7672); they count only when DNSSEC validates them.
dane_data=""; dane_seen=" "; dane_found=0
if [[ -n $mx && $mx != "0 ." ]]; then
  while read -r _ mxh; do
    mxh=${mxh%.}
    [[ -n $mxh && $dane_seen != *" $mxh "* ]] || continue
    dane_seen+="$mxh "
    tl=$(dig +dnssec +comments +answer +time=3 +tries=2 TLSA "_25._tcp.$mxh" @"$RESOLVER" 2>/dev/null)
    recs=$(awk '$4 == "TLSA" {h = ""; for (i = 8; i <= NF; i++) h = h $i; print $5, $6, $7, tolower(h)}' <<<"$tl")
    [[ -n $recs ]] || continue
    dane_found=$((dane_found + 1))
    if grep -m1 '^;; flags:' <<<"$tl" | grep -q ' ad'; then
      ok "DANE $mxh" "$(wc -l <<<"$recs" | tr -d ' ') TLSA record(s), validated by DNSSEC"
      while read -r u sl m d; do dane_data+="$mxh $u $sl $m $d"$'\n'; done <<<"$recs"
    else
      warn "DANE $mxh" "TLSA records published but NOT validated by DNSSEC: senders ignore them"
      fix "dane-$mxh" 2 "DANE: the TLSA records of $mxh are not validated" \
        "TLSA works only inside a DNSSEC-signed zone. Sign the zone of $mxh (section 5 explains how)," \
        "or remove the TLSA records: a wrong or unvalidated record can make senders refuse the server."
    fi
  done <<<"$mx"
  if ((dane_found == 0)); then
    if [[ -n $reg_ds ]]; then
      tip "DANE" "not published although DNSSEC is on: TLSA records would let senders verify your mail servers"
    else
      info "DANE" "not published (optional; MTA-STS covers the same need without DNSSEC)"
    fi
  fi
fi

# TXT records often reveal the services a domain has been connected to over the years.
txt_all=$(txt "$domain")
if [[ -n $txt_all ]]; then
  txt_svc=""; txt_other=0; txt_n=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    txt_n=$((txt_n + 1))
    l=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
    case $l in
      v=spf1*) continue ;;
      google-site-verification=*) svc="Google" ;;
      ms=*) svc="Microsoft 365" ;;
      facebook-domain-verification=*) svc="Meta" ;;
      apple-domain-verification=*) svc="Apple" ;;
      atlassian-domain-verification=*) svc="Atlassian" ;;
      docusign=*) svc="DocuSign" ;;
      stripe-verification=*) svc="Stripe" ;;
      adobe-idp-site-verification=*) svc="Adobe" ;;
      zoho-verification=*) svc="Zoho" ;;
      mailru-verification:*|yandex-verification:*) svc="Mail.ru/Yandex" ;;
      zoom-domain-verification=*|zoom_verify_*) svc="Zoom" ;;
      amazonses:*) svc="Amazon SES" ;;
      globalsign-domain-verification=*) svc="GlobalSign" ;;
      cisco-ci-domain-verification=*) svc="Cisco" ;;
      onetrust-domain-verification=*) svc="OneTrust" ;;
      *) txt_other=$((txt_other + 1)); continue ;;
    esac
    [[ ", $txt_svc," == *", $svc,"* ]] || txt_svc+="${txt_svc:+, }$svc"
  done <<<"$txt_all"
  ((txt_other > 0)) && txt_more="; other: $txt_other" || txt_more=""
  info "TXT records" "$txt_n at the apex${txt_svc:+; verifications for: $txt_svc}$txt_more"
fi

# Mail client setup: autoconfig/autodiscover hosts and SRV records (RFC 6186).
if [[ -n $mx && $mx != "0 ." ]]; then
  cs=()
  for h in autoconfig autodiscover; do has_addr "$h.$domain" && cs+=("$h"); done
  for srv in _autodiscover._tcp _imaps._tcp _submission._tcp _submissions._tcp _pop3s._tcp; do
    q SRV "$srv.$domain" | awk 'NF >= 4 && $4 != "." {f = 1} END {exit !f}' && cs+=("$srv")
  done
  if ((${#cs[@]})); then
    info "Mail client setup" "${cs[*]}"
    if [[ " ${cs[*]} " == *" autoconfig "* ]] && have curl; then
      ac_ok=""; ac_blocked=""
      for scheme in https http; do
        ac_port=443; [[ $scheme == http ]] && ac_port=80
        pin_host "autoconfig.$domain" "$ac_port" || { ac_blocked=1; break; }
        ac=$(curl -sS -m "$NET_TIMEOUT" "${PIN[@]}" --max-filesize 65536 "$scheme://autoconfig.$domain/mail/config-v1.1.xml" 2>/dev/null | head -c 65536)
        [[ $ac == *"<clientConfig"* ]] && { ac_ok=$scheme; break; }
      done
      if [[ -n $ac_ok ]]; then ok "Autoconfig file" "served over $ac_ok"
      elif [[ -n $ac_blocked ]]; then info "Autoconfig file" "not contacted: autoconfig.$domain resolves to a non-public address"
      else tip "Autoconfig file" "autoconfig.$domain exists but serves no /mail/config-v1.1.xml"; fi
    fi
  else
    tip "Mail client setup" "no autoconfig/autodiscover host or SRV record: users type the mail server settings by hand"
  fi
fi

# A domain that receives no mail should say so, and refuse to be used as a sender.
if [[ -z $mx || $mx == "0 ." ]]; then
  parked=()
  [[ ${spf_l:-} == *" -all"* ]] || parked+=("SPF -all")
  [[ $(kv_tag "${dmarc:-}" p | tr '[:upper:]' '[:lower:]') == reject ]] || parked+=("DMARC p=reject")
  if ((${#parked[@]})); then
    tip "Mail spoofing" "this domain receives no mail: publish ${parked[*]}, so that nobody can send in its name"
    fix parked 4 "Mail: protect a domain that does not use mail" \
      "= $domain. IN TXT \"v=spf1 -all\"" \
      "= _dmarc.$domain. IN TXT \"v=DMARC1; p=reject; adkim=s; aspf=s\"" \
      "= $domain. IN MX 0 .   (null MX: declares that the domain accepts no mail)"
  fi
fi

# ---------------------------------------------------------- [8] mail servers ----
mail_host="mail.$domain"
has_addr "$mail_host" || mail_host=$first_mx
if [[ -n $PASSIVE ]]; then mail_src="none (passive mode)"
else mail_src="direct connections: MX ${first_mx:-none} (port 25), clients ${mail_host:-none}"; fi
section 8 "MAIL SERVERS" "$mail_src"

if [[ -n $PASSIVE ]]; then
  info "Mail servers" "not tested (passive mode: no connections to mail ports)"
elif [[ -z $first_mx && -z $mail_host ]]; then
  info "Mail servers" "no MX and no mail host to test"
elif have python3; then
  specs=()
  [[ -n $first_mx ]] && specs+=("smtp|$first_mx|25|SMTP 25 (MX)")
  if [[ -n $mail_host ]]; then
    specs+=("tls|$mail_host|465|SMTPS 465" "submission|$mail_host|587|Submission 587"
            "tls|$mail_host|993|IMAPS 993" "imap|$mail_host|143|IMAP 143"
            "tls|$mail_host|995|POP3S 995" "pop|$mail_host|110|POP3 110"
            "legacy|$mail_host|993|Legacy TLS 993" "weakc|$mail_host|993|Weak ciphers 993"
            "weakc|$mail_host|465|Weak ciphers 465")
  fi
  render <<<"$(NDM_PIN=$(probe_pins "${specs[@]}") python3 -I -c "$PY_PROBE" --mail "${specs[@]}" 2>/dev/null)"
  # DANE: the TLSA records must match the certificate the server really shows.
  if [[ -n $dane_data ]]; then
    while read -r mxh; do
      if ! pin_host "$mxh" 25; then
        info "DANE $mxh" "not checked against the certificate: it resolves to a non-public address"
        continue
      fi
      render <<<"$(awk -v h="$mxh" '$1 == h {print $2, $3, $4, $5}' <<<"$dane_data" \
        | NDM_PIN="$mxh=$PIN_IPS" python3 -I -c "$PY_DANE" "$mxh" 2>/dev/null)"
    done < <(awk 'NF {print $1}' <<<"$dane_data" | sort -u)
  fi
elif [[ -n $first_mx ]] && have openssl; then
  smtp=""
  pin_host "$first_mx" 25 && smtp=$(run_to $((NET_TIMEOUT + 4)) openssl s_client -starttls smtp -crlf \
    -connect "$PIN_ADDR:25" -servername "$first_mx" </dev/null 2>/dev/null)
  if [[ $smtp == *"BEGIN CERTIFICATE"* ]]; then ok "SMTP STARTTLS" "$first_mx:25"
  else info "SMTP STARTTLS" "no connection to $first_mx:25 (port 25 is often blocked by ISPs)"; fi
  info "Client ports" "skipped (python3 not available)"
fi

# ------------------------------------------------------------ [9] blocklists ----
# IPv4 addresses that send mail for this domain: MX hosts, mail.<domain>, single IPs in SPF.
send_items=()
add_send() {
  local i
  for i in "${send_items[@]+"${send_items[@]}"}"; do [[ ${i%%=*} == "$1" ]] && return; done
  send_items+=("$1=$2")
}
for ip in "${mail_ips[@]+"${mail_ips[@]}"}"; do add_send "$ip" "MX ${first_mx}"; done
for ip in $(q4 "mail.$domain") $(q6 "mail.$domain"); do add_send "$ip" "mail.$domain"; done
while IFS=$'\t' read -r kind net _; do
  if [[ $kind == direct && $net =~ ^[0-9.]+(/32)?$ ]]; then add_send "${net%/32}" "SPF ip4"
  elif [[ $kind == direct && $net == *:* && $net =~ ^[0-9a-f:]+(/128)?$ ]]; then add_send "${net%/128}" "SPF ip6"
  fi
done <<<"${spf_tree:-}"
send_ips=()
for i in "${send_items[@]+"${send_items[@]}"}"; do send_ips+=("${i%%=*}"); done

bl_source="system resolver (some lists refuse public resolvers)"
[[ -n $DNSBL_RESOLVER ]] && bl_source="resolver $DNSBL_RESOLVER"
section 9 "BLOCKLISTS (DNSBL)" "$bl_source"
if ((${#send_ips[@]} == 0)); then
  info "Blocklists" "no mail-sending IP to check"
else
  refused_all=""
  for ip in "${send_ips[@]}"; do
    if [[ $ip == *:* ]]; then
      # IPv6 lists use the 32 reversed nibbles of the address.
      rev=""
      have python3 && rev=$(python3 -I -c 'import sys, ipaddress
print(ipaddress.ip_address(sys.argv[1]).reverse_pointer[:-len(".ip6.arpa")])' "$ip" 2>/dev/null)
      if [[ -z $rev ]]; then info "Blocklist $ip" "IPv6 not checked (python3 needed)"; continue; fi
    else
      rev=$(awk -F. '{print $4 "." $3 "." $2 "." $1}' <<<"$ip")
    fi
    listed=(); refused=(); skipped=(); clean=0
    for entry in $DNSBLS; do
      IFS=: read -r zone sev v6mark _ <<<"$entry"
      # Most lists know only IPv4: IPv6 goes to Spamhaus ZEN and to the zones marked ":6".
      if [[ $ip == *:* && $v6mark != 6 && $zone != zen.spamhaus.org ]]; then
        skipped+=("$zone"); continue
      fi
      # A list can answer with several codes at once (Spamhaus ZEN): all of them count.
      ans=$(q_sys A "$rev.$zone")
      codes=$(grep '^127\.' <<<"$ans" | sort -u | paste -sd ',' -)
      # Spamhaus PBL (127.0.0.10/11): end-user/dynamic ranges that should not send mail
      # directly. Only a warning, unless the IP is also on a real list (SBL, XBL).
      if [[ -z $ans ]]; then
        clean=$((clean + 1))
      elif [[ -z $codes ]] || grep -q '^127\.255\.255\.' <<<"$ans"; then
        refused+=("$zone")
      elif [[ $zone == zen.spamhaus.org && $(grep '^127\.' <<<"$ans" | grep -cvE '^127\.0\.0\.1[01]$') == 0 ]]; then
        listed+=("$zone (PBL end-user range):warn:$codes")
      else
        listed+=("$zone:$sev:$codes")
      fi
    done
    for l in "${listed[@]+"${listed[@]}"}"; do
      IFS=: read -r zone sev code <<<"$l"
      if [[ $sev == fail ]]; then fail "Blocklist $ip" "LISTED on $zone ($code)"
      else warn "Blocklist $ip" "listed on $zone ($code)"; fi
      case $zone in
        *PBL*) bl_how=("The PBL lists ranges that should not send mail directly (home, dynamic)."
                 "Send through your provider's relay; a real server with its own PTR name" "can request removal:" "= https://check.spamhaus.org/") ;;
        zen.spamhaus.org) bl_how=("Removal request (after the cause is fixed):" "= https://check.spamhaus.org/") ;;
        psbl.surriel.com) bl_how=("Removal (self-service, effective in about half an hour):" "= https://psbl.org/remove") ;;
        *) bl_how=("See the website of $zone for its removal procedure.") ;;
      esac
      [[ $sev == fail ]] && bl_prio=1 || bl_prio=2
      fix "bl-$ip-${zone%% *}" "$bl_prio" "Blocklist: $ip is listed on ${zone%% *}" \
        "First find and stop the cause: a hacked mailbox or website, a form that sends spam," \
        "an open relay. Check the mail queue and the logs." "${bl_how[@]}"
    done
    if ((${#listed[@]} == 0)); then
      if ((clean > 0)); then ok "Blocklist $ip" "not listed ($clean lists checked)"
      elif ((${#refused[@]})); then info "Blocklist $ip" "no list could be checked"; fi
    fi
    for zone in "${refused[@]+"${refused[@]}"}"; do
      [[ " $refused_all " == *" $zone "* ]] || refused_all+="${refused_all:+ }$zone"
    done
    ((${#refused[@]})) && detail "not checked on ${refused[*]} (query refused)"
    if ((${#skipped[@]})); then
      if ((clean + ${#listed[@]} + ${#refused[@]} == 0)); then
        info "Blocklist $ip" "IPv6 not checked: no configured list supports it (mark one as zone:level:6)"
      else
        detail "IPv6: not covered by ${skipped[*]} (IPv4 only)"
      fi
    fi
  done
  if [[ -n $refused_all ]]; then
    warn "Blocklists" "$refused_all refused the queries: NOT checked (public or shared resolver?)"
    fix bl-refused 2 "Blocklists: $refused_all does not answer this resolver" \
      "Some lists, Spamhaus among them, refuse queries that arrive through public or shared" \
      "resolvers. Use your own resolver (for example Unbound or Knot Resolver on this machine)" \
      "or your ISP's as the system resolver, or set DNSBL_RESOLVER in the config file, then" \
      "run the script again. To test a resolver:" \
      "= dig +short 2.0.0.127.zen.spamhaus.org" \
      "127.0.0.x means the resolver is accepted; 127.255.255.254 means it is refused."
  fi
fi

# Domain-name lists: the reputation of the domain itself, whatever its IP addresses are.
if [[ -n $DOMAIN_DNSBLS ]]; then
  dom_listed=0; dom_clean=0; dom_refused=""
  for entry in $DOMAIN_DNSBLS; do
    IFS=: read -r zone sev _ <<<"$entry"
    ans=$(q_sys A "$domain.$zone")
    codes=$(grep '^127\.' <<<"$ans" | sort -u | paste -sd ',' -)
    if [[ -z $ans ]]; then
      dom_clean=$((dom_clean + 1))
    elif [[ -z $codes ]] || grep -q '^127\.255\.255\.' <<<"$ans" || [[ $zone == *uribl.com && $codes == 127.0.0.1 ]]; then
      dom_refused+="${dom_refused:+ }$zone"
    else
      dom_listed=$((dom_listed + 1))
      meaning=""
      if [[ $zone == dbl.spamhaus.org ]]; then
        for c in ${codes//,/ }; do
          case $c in
            127.0.1.2) meaning+=" spam domain" ;;           127.0.1.4) meaning+=" phishing" ;;
            127.0.1.5) meaning+=" malware" ;;               127.0.1.6) meaning+=" botnet C&C" ;;
            127.0.1.10[2-6]) meaning+=" abused legitimate site" ;;
          esac
        done
      fi
      if [[ $sev == fail ]]; then fail "Domain blocklist" "$domain LISTED on $zone ($codes)${meaning:+:$meaning}"
      else warn "Domain blocklist" "$domain listed on $zone ($codes)${meaning:+:$meaning}"; fi
      [[ $sev == fail ]] && bl_prio=1 || bl_prio=2
      fix "dbl-$zone" "$bl_prio" "Blocklist: $domain is listed on $zone" \
        "A domain is listed because mail or web content using its name was reported: a hacked site," \
        "a phishing page, spam sent in its name. Find and stop the cause, then ask for removal:" \
        "= https://check.spamhaus.org/"
    fi
  done
  ((dom_listed == 0 && dom_clean > 0)) && ok "Domain blocklists" "$domain not listed ($dom_clean lists checked)"
  if [[ -n $dom_refused ]]; then
    warn "Domain blocklists" "$dom_refused refused the queries: NOT checked (public or shared resolver?)"
    fix bl-refused-domain 2 "Blocklists: $dom_refused does not answer this resolver" \
      "Same cause as for the IP lists: set DNSBL_RESOLVER in the config file to a resolver that" \
      "the lists accept (see the template), then run the script again."
  fi
fi

# --------------------------------------------------------- [10] IP ownership ----
section 10 "IP ADDRESSES (OWNER, ASN, REVERSE DNS)" "RDAP via IANA bootstrap, RIPEstat (RIPE NCC) for the ASN, PTR via $RESOLVER"

# True when a PTR name looks like a provider's automatic name (IP digits or access keywords).
ptr_generic() {
  local o1 o2 o3 o4 p
  p=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
  if [[ $1 != *:* ]]; then
    IFS=. read -r o1 o2 o3 o4 <<<"$1"
    [[ $p == *"$o1"[-.]"$o2"[-.]"$o3"[-.]"$o4"* || $p == *"$o4"[-.]"$o3"[-.]"$o2"[-.]"$o1"* ]] && return 0
  fi
  [[ $p =~ (dynamic|dhcp|dsl|pool|cable|ppp|dial|customer|client|broadband|unassigned) ]]
}

ip_items=()
[[ -n ${web_ip:-} ]] && ip_items+=("$web_ip=website")
[[ -n ${web_ip6:-} ]] && ip_items+=("$web_ip6=website")
ip_items+=("${send_items[@]+"${send_items[@]}"}")
if ((${#ip_items[@]} == 0)); then
  info "IP addresses" "none found"
else
  ip_list=()
  for i in "${ip_items[@]}"; do ip_list+=("${i%%=*}"); done
  ipinfo_fetch "${ip_list[@]}"
  ipinfo=$ipinfo_cache
  done_ips=" "
  for i in "${ip_items[@]}"; do
    ip=${i%%=*}
    [[ $done_ips == *" $ip "* ]] && continue
    done_ips+="$ip "
    # All roles of this IP, e.g. "website, MX example.com".
    roles=$(printf '%s\n' "${ip_items[@]}" | awk -F= -v ip="$ip" '$1 == ip {print $2}' | paste -sd ',' - | sed 's/,/, /g')
    info "IP $ip" "$roles"
    IFS=$'\t' read -r _ network bgp netname org country rir asn asname abuse \
      < <(awk -F'\t' -v ip="$ip" '$1 == ip' <<<"$ipinfo")
    # '-' marks unknown fields in the helper output.
    for v in network bgp netname org country rir asn asname abuse; do
      [[ ${!v:-} == - ]] && printf -v "$v" '%s' ""
    done
    if [[ -z ${network:-}${asn:-} ]]; then
      detail "owner data not available (RDAP/ASN lookup failed or python3 missing)"
    else
      if [[ -n $org$network ]]; then
        detail "owner    ${org:-unknown}${netname:+ ($netname)}"
        detail "network  ${network:-?}${bgp:+  ·  BGP $bgp}${country:+  ·  $country}${rir:+  ·  $rir}"
      else
        detail "owner    not available (registry RDAP not reachable)"
        detail "network  BGP ${bgp:-?}${country:+  ·  $country}${rir:+  ·  $rir}"
      fi
      [[ -n $asn ]] && detail "ASN      AS$asn${asname:+ $asname}"
      [[ -n $abuse ]] && detail "abuse    $abuse"
    fi
    # Reverse DNS matters for IPs that send mail, not for a website-only IP.
    [[ $roles == website ]] && continue
    ptr=$(dig +short -x "$ip" @"$RESOLVER" 2>/dev/null | grep -v '^;' | head -1 | sed 's/\.$//')
    ip_owner=$(ip_owner_summary "$ip")
    ptr_name="mail.$domain"
    rr=A; [[ $ip == *:* ]] && rr=AAAA
    [[ $roles == *"MX "* && -n $first_mx ]] && ptr_name=$first_mx
    if [[ -z $ptr ]]; then
      fail "PTR $ip" "no reverse DNS: large mail providers reject or spam mail sent from it"
      fix "ptr-$ip" 1 "Reverse DNS: give $ip a name" \
        "Only the owner of the IP can set it (${ip_owner:-the provider}): usually in the" \
        "VPS/server panel, otherwise with a ticket. The name must resolve back to the IP:" \
        "= PTR of $ip  →  $ptr_name" \
        "= $ptr_name. IN $rr $ip"
    elif ! fwd_confirms "$ptr" "$ip"; then
      warn "PTR $ip" "$ptr does not resolve back to $ip"
      ptr_mine=""
      for rd in "$domain" $RELATED_DOMAINS; do
        [[ $ptr == "$rd" || $ptr == *".$rd" ]] && ptr_mine=1
      done
      if [[ -n $ptr_mine ]]; then
        fix "ptr-$ip" 2 "Reverse DNS: make $ptr resolve back to $ip" \
          "The PTR name is yours: add (or correct) its address:" \
          "= $ptr. IN $rr $ip"
      else
        fix "ptr-$ip" 2 "Reverse DNS: $ptr does not resolve back to $ip" \
          "Ask the owner of the IP (${ip_owner:-the provider}) to set the PTR to a name of yours," \
          "then add its address:" \
          "= PTR of $ip  →  $ptr_name" \
          "= $ptr_name. IN $rr $ip"
      fi
    else
      ok "PTR $ip" "$ptr (forward-confirmed)"
      if ptr_generic "$ip" "$ptr"; then
        tip "PTR $ip" "looks generic: ask the provider for a name like mail.$domain"
        fix "ptr-$ip" 4 "Reverse DNS: give $ip a name of yours" \
          "Ask the owner of the IP (${ip_owner:-the provider}) for this PTR, then add the A record:" \
          "= PTR of $ip  →  $ptr_name" \
          "= $ptr_name. IN $rr $ip"
      elif [[ $ptr != "$domain" && $ptr != *".$domain" ]]; then
        info "PTR $ip" "provider's name (normal on shared hosting; on your own server use one of yours)"
      fi
    fi
  done
fi

# ------------------------------------------------------------------ [11] CAA ----
section 11 "CERTIFICATE AUTHORITIES (CAA)" "resolver $RESOLVER"
caa=$(q CAA "$domain")
if [[ -z $caa ]]; then
  tip "CAA" "none: any certificate authority may issue for this domain"
  # Only the non-profit Let's Encrypt is known here; for other CAs their own
  # documentation gives the name to use in CAA.
  ca_dom=""
  [[ ${issuer:-} == *"Let's Encrypt"* ]] && ca_dom=letsencrypt.org
  caa_lines=()
  if [[ -n $ca_dom ]]; then
    caa_lines+=("The website certificate comes from ${issuer}. Allow it (and every other CA you use):"
      "= $domain. IN CAA 0 issue \"$ca_dom\"")
  elif [[ -n ${issuer:-} ]]; then
    caa_lines+=("The website certificate comes from ${issuer}: its documentation gives the name"
      "to put in the CAA record (and the same for every other CA you use):"
      "= $domain. IN CAA 0 issue \"<CA name for CAA>\"")
  else
    caa_lines+=("Allow only the certificate authorities you use, for example:"
      "= $domain. IN CAA 0 issue \"letsencrypt.org\"")
  fi
  fix caa 4 "Certificates: limit who may issue them (CAA)" "${caa_lines[@]}" \
    "Include the CAs of mail and other subdomains, and of any CDN or proxy that issues" \
    "certificates for you: their certificates may come from another CA."
else
  ok "CAA" "$(printf '%s\n' "$caa" | grep -c .) record(s)"
  while read -r line; do detail "$line"; done <<<"$caa"
fi

# ------------------------------------------------- [12] cert transparency ----
section 12 "CERTIFICATE TRANSPARENCY" "public CT logs via crt.sh (every name that ever had a certificate); CNAME targets via $RESOLVER"
if [[ $CT_LOOKUP == off ]]; then
  info "CT logs" "not searched (CT_LOOKUP=off in the config file)"
elif ! have python3; then
  info "CT logs" "skipped (python3 not available)"
else
  ct_err=$(awk -F'\t' '$1 == "error" {print $2}' <<<"$ct")
  read -r _ ct_total ct_current < <(awk -F'\t' '$1 == "summary" {print $1, $2, $3}' <<<"$ct")
  if [[ -n $ct_err || -z ${ct_total:-} ]]; then
    warn "CT logs" "crt.sh temporarily unavailable (${ct_err:-no answer}): names list not shown"
    detail "Try again later. Without it, SPF addresses of your subdomains are not recognized"
    detail "and may show up as \"to check\" in section 7."
  elif ((ct_total == 0)); then
    info "CT logs" "no certificates found for this domain"
  else
    # Names gone from DNS (and wildcards) with only expired certificates are history: CT logs
    # are append-only, so they stay listed forever. Counted in the header, not listed.
    read -r ct_old ct_old_years < <(awk -F'\t' '$1 == "row" && $4 == 0 && ($5 == "-" || $5 == "*") {
        n++; y = substr($3, 1, 4); if (!lo || y < lo) lo = y; if (y > hi) hi = y }
      END { print n + 0, (lo == hi ? lo : lo "–" hi) }' <<<"$ct")
    ct_head="$ct_total (valid certificate: $ct_current"
    ((ct_old)) && ct_head+="; expired and gone from DNS: $ct_old, $ct_old_years"
    info "Names in CT logs" "$ct_head)"
    while IFS=$'\t' read -r kind name expiry current ip; do
      [[ $kind == row ]] || continue
      ((!current)) && [[ $ip == '-' || $ip == '*' ]] && continue
      if ((current)); then state="cert valid until $expiry"; else state="last cert expired $expiry"; fi
      case $ip in
        '*') where="(wildcard)" ;;
        '-') where="not in DNS" ;;
        *)   where="→ $ip" ;;
      esac
      detail "$(printf '%-36s %-30s %s' "$name" "$state" "$where")"
    done <<<"$ct"
    ((ct_total > CT_LIMIT)) && detail "… and $((ct_total - CT_LIMIT)) more (see https://crt.sh/?q=%25.$domain)"
  fi
fi

# CNAMEs that point nowhere: whoever registers the target, or claims the abandoned service,
# can serve content on your name. The names are the common ones plus those found in the CT logs.
dang_names=$({ printf '%s.%s\n' www "$domain" mail "$domain" webmail "$domain" autodiscover "$domain" \
  autoconfig "$domain" mta-sts "$domain"
  awk -F'\t' -v d="$domain" '$1 == "row" && $2 != d && $2 !~ /^\*/ {print $2}' <<<"${ct:-}"; } | sort -u)
dang_i=0
for name in $dang_names; do
  dang_i=$((dang_i + 1))
  ((dang_i % 10 == 0)) && wait
  ( cname=$(q CNAME "$name" | head -1)
    if [[ -n $cname ]]; then
      rcode=$(dig +noall +comments +time=3 +tries=2 A "$name" @"$RESOLVER" 2>/dev/null | grep -o 'status: [A-Z]*' | head -1)
      printf '%s\t%s\t%s\n' "$name" "${cname%.}" "${rcode#status: }" >"$tmpdir/dang_$dang_i"
    fi ) &
done
wait
dang_all=$(cat "$tmpdir"/dang_* 2>/dev/null | sort)
dang_cnames=$(sed '/^$/d' <<<"$dang_all" | wc -l | tr -d ' ')
dang_bad=0
while IFS=$'\t' read -r name target dang_st; do
  [[ $dang_st == NXDOMAIN ]] || continue
  dang_bad=$((dang_bad + 1))
  fail "Dangling CNAME" "$name -> $target does not exist: anyone who registers it can take over this name"
  fix "dangling-$name" 1 "DNS: remove the dangling CNAME of $name" \
    "It points to $target, which does not exist (a deleted service or an expired domain)." \
    "Whoever registers or claims that target can publish content, or collect mail links," \
    "under your name. Delete the record if the service is no longer used:" \
    "= $name. IN CNAME $target." \
    "If the service is still needed, recreate it first, then check the record again."
done <<<"$dang_all"
if ((dang_bad == 0)); then
  if ((dang_cnames == 0)); then info "CNAME targets" "no CNAME among the $(wc -w <<<"$dang_names" | tr -d ' ') names checked"
  else ok "CNAME targets" "$dang_cnames CNAME(s) checked, every target exists"; fi
fi

# Own domains only: a certificate check of every live name found in the CT logs (forgotten
# subdomains are where expired certificates hide).
if [[ -z $PASSIVE ]] && have python3 && [[ -n ${ct:-} ]]; then
  ct_specs=()
  while IFS=$'\t' read -r kind name _ current cip; do
    [[ $kind == row && $current == 1 && $cip != '-' && $cip != '*' && $name != "$domain" ]] || continue
    case $name in "www.$domain"|"mail.$domain"|"webmail.$domain") continue ;; esac
    ct_specs+=("tls|$name|443|HTTPS $name")
  done <<<"$ct"
  if ((${#ct_specs[@]})); then
    ct_out=$(NDM_PIN=$(probe_pins "${ct_specs[@]}") python3 -I -c "$PY_PROBE" "${ct_specs[@]}" 2>/dev/null)
    ct_closed=$(awk -F'\t' '$1 == "info"' <<<"$ct_out" | wc -l | tr -d ' ')
    ct_bad=$(awk -F'\t' '$1 == "warn" || $1 == "fail"' <<<"$ct_out" | wc -l | tr -d ' ')
    render <<<"$(awk -F'\t' '$1 != "ok" && $1 != "info"' <<<"$ct_out")"
    info "HTTPS names (CT)" "${#ct_specs[@]} probed: $((${#ct_specs[@]} - ct_closed - ct_bad)) fine, $ct_bad with problems, $ct_closed not answering on 443"
  fi
fi

# Own domains only: CNAMEs to services that answer "this site does not exist" can be claimed
# by someone else, even though the target name still resolves.
if [[ -z $PASSIVE ]] && have curl; then
  while IFS=$'\t' read -r name target dang_st; do
    [[ -n $name && $dang_st != NXDOMAIN ]] || continue
    case $target in
      *.github.io)                       sig="There isn't a GitHub Pages site here" ;;
      *.s3.amazonaws.com|*.s3-website*.amazonaws.com|*.s3.*.amazonaws.com) sig="NoSuchBucket" ;;
      *.herokuapp.com|*.herokudns.com)   sig="No such app" ;;
      *.bitbucket.io)                    sig="Repository not found" ;;
      *.surge.sh)                        sig="project not found" ;;
      *.myshopify.com)                   sig="Sorry, this shop is currently unavailable" ;;
      *.zendesk.com)                     sig="Help Center Closed" ;;
      *) continue ;;
    esac
    pin_host "$name" 80 || continue
    page=$(curl -sS -m "$NET_TIMEOUT" "${PIN[@]}" --proto '=http,https' --max-filesize 65536 "http://$name/" 2>/dev/null | head -c 65536)
    if [[ $page == *"$sig"* ]]; then
      fail "Takeover risk" "$name -> $target: the service says nothing is hosted there (\"$sig\"): anyone can claim it"
      fix "takeover-$name" 1 "DNS: remove or reclaim $name" \
        "The CNAME points to a service where the site, bucket or app no longer exists. Another" \
        "customer of that service can claim the name and publish content on $name. Remove the record:" \
        "= $name. IN CNAME $target." \
        "or recreate the resource at the provider, then run the script again."
    fi
  done <<<"$dang_all"
fi

# --------------------------------------------------- [13] provider change ----
if [[ -z $BRIEF ]]; then
section 13 "IF YOU CHANGE REGISTRAR, DNS, HOSTING OR MAIL" "notes based on the setup detected above"
# The DNS provider is shown by its nameserver names.
dns_at_host=""
dns_provider=$(echo "$deleg_ns" | paste -sd ' ' -)
# The DNS is "at the hosting" when a nameserver shares the website's IP or its
# network (same ASN): leaving that hosting usually means moving the DNS too.
asn_of() { awk -F'\t' -v ip="$1" '$1 == ip {print $8; exit}' <<<"$ipinfo_cache"; }
if [[ -n ${web_ip:-}${web_ip6:-} ]]; then
  ns_ips=()
  while read -r ns; do
    [[ -n $ns ]] || continue
    while read -r ip; do [[ -n $ip ]] && ns_ips+=("$ip"); done < <(q4 "$ns"; q6 "$ns")
  done <<<"$deleg_ns"
  if ((${#ns_ips[@]})); then
    web_ips=(); [[ -n $web_ip ]] && web_ips+=("$web_ip"); [[ -n $web_ip6 ]] && web_ips+=("$web_ip6")
    ipinfo_fetch "${web_ips[@]}" "${ns_ips[@]}"
    web_asns=" "
    for ip in "${web_ips[@]}"; do web_asns+="$(asn_of "$ip") "; done
    for ip in "${ns_ips[@]}"; do
      ns_asn=$(asn_of "$ip")
      if [[ $ip == "$web_ip" || $ip == "$web_ip6" || ( -n $ns_asn && $ns_asn != - && $web_asns == *" $ns_asn "* ) ]]; then
        dns_at_host=1
        break
      fi
    done
  fi
fi
[[ -n $dns_at_host ]] && dns_provider+=" (same network as the website)"
ds_ttl=$(dig +norec +noall +answer DS "$domain" @"$parent_ns" 2>/dev/null | awk '{print $2; exit}')
a_ttl=$(dig +norec +noall +answer A "$domain" @"$first_ns" 2>/dev/null | awk '{print $2; exit}')
# Seconds as a readable duration ("604800" -> "7 days").
human_secs() {
  local n=${1:-0}
  [[ $n =~ ^[0-9]+$ ]] || { printf '%s' "$1"; return; }
  if ((n >= 172800)); then printf '%d days' $((n / 86400))
  elif ((n >= 86400)); then printf '1 day'
  elif ((n >= 7200)); then printf '%d hours' $((n / 3600))
  elif ((n >= 3600)); then printf '1 hour'
  else printf '%d s' "$n"; fi
}
dkim_names=""
for sel in "${dkim_found[@]+"${dkim_found[@]}"}"; do dkim_names+="${dkim_names:+, }$sel._domainkey"; done
info "Current setup" "DNS: $dns_provider · DNSSEC: $([[ -n $reg_ds ]] && echo "on" || echo "off")"
detail "web IP ${web_ip:-none}${web_ip6:+ / $web_ip6} (TTL ${a_ttl:-?} s) · MX ${first_mx:-none}"
detail "mail: DKIM ${dkim_names:-not found} · MTA-STS ${sts_mode:-off}${sts_max_age:+ (max_age $(human_secs "$sts_max_age"))} · TLS-RPT $([[ -n $tlsrpt_on ]] && echo on || echo off)"

info "Registrar change" "DNS records and DNSSEC keys do not move: only the registration does"
detail "Before: write down NS and DS (section 3), unlock the domain, get the auth code,"
detail "        make sure the registrant e-mail works (transfers are confirmed by e-mail)."
if [[ -n $reg_ds ]]; then
  detail "After:  check that NS and DS are unchanged. Some registrars drop the DS on"
  detail "        transfer: the domain keeps working, unsigned. Re-add the same DS."
else
  detail "After:  check that the NS are unchanged."
fi

info "DNS provider change" "new nameservers (another DNS provider or your own servers)"
copy_list="A/AAAA, CNAME, MX, SPF, DMARC (_dmarc)${dkim_names:+, DKIM ($dkim_names)}"
if [[ -n $sts_mode ]]; then
  sts_hosts="the mta-sts host"
  has_addr "www.mta-sts.$domain" && sts_hosts="the mta-sts and www.mta-sts hosts"
  copy_list+=", MTA-STS (_mta-sts and $sts_hosts)"
fi
[[ -n $tlsrpt_on ]] && copy_list+=", TLS-RPT (_smtp._tls)"
[[ -n ${caa:-} ]] && copy_list+=", CAA"
detail "1. Copy ALL records to the new provider, and check them one by one:"
while IFS= read -r l; do detail "   $l"; done < <(printf '%s, SRV and any other.\n' "$copy_list" | fold -s -w 76 | sed 's/ *$//')
detail "2. A day before, lower the TTLs (now ${a_ttl:-?} s on the apex A record)."
if [[ -n $reg_ds ]]; then
  detail "3. Remove the DS at the registrar FIRST, then wait at least ${ds_ttl:-3600} s"
  detail "   (the DS TTL) plus margin: 24 h is safe."
  detail "4. Switch the NS at the registrar and wait 24-48 h."
  detail "5. Enable DNSSEC at the new provider and give the NEW DS to the registrar."
  detail "   Never switch NS while the old DS is published: validating resolvers"
  detail "   (public ones and most providers') would stop resolving the domain."
else
  detail "3. Switch the NS at the registrar: old and new answers coexist up to 48 h."
  detail "4. Optional: enable DNSSEC at the new provider and give its DS to the registrar."
fi

info "Hosting change" "new server, new IP address"
if [[ -n $dns_at_host ]]; then
  detail "The nameservers are in the same network as the website: leaving that provider"
  detail "usually means a DNS provider change too (see above)$([[ -n $reg_ds ]] && echo ", DS removal first")."
fi
detail "- A day before, lower the TTLs; then update the A/AAAA of $domain${web_ip:+ ($web_ip)}"
detail "  and of every name that does not CNAME to it."
if [[ -n ${spf:-} && -n ${web_ip:-} && $spf == *"$web_ip"* ]]; then
  detail "- SPF contains ip4:$web_ip: replace it with the new IP."
fi
detail "- If the mail moves too, follow also \"Mail server change\" below."
[[ -n $sts_mode ]] && detail "- MTA-STS: the policy file is served by mta-sts.$domain: copy it to the new" &&
  detail "  hosting, with a valid certificate, BEFORE moving the address."
[[ -n ${caa:-} ]] && detail "- CAA: make sure it allows the new host's certificate authority."
[[ -n $reg_ds && -z $dns_at_host ]] && detail "- DNSSEC: unaffected (DNS stays at $dns_provider)."

info "Mail server change" "new MX: another mail server or mail provider"
step=1
if [[ $sts_mode == enforce ]]; then
  detail "$step. MTA-STS is in enforce: senders accept only the MX listed in the policy file."
  detail "   At least $(human_secs "${sts_max_age:-604800}") before the change (its max_age), add the NEW mail host"
  detail "   as an extra mx: line (or set mode: testing) and change the id in _mta-sts."
  step=$((step + 1))
fi
detail "$step. A day before, lower the TTL of the MX record."; step=$((step + 1))
detail "$step. Publish the new server's SPF entry and DKIM key BEFORE switching; keep the old"
detail "   ones until the move is over (mail already queued may still arrive from the old one)."
step=$((step + 1))
detail "$step. Change the MX$([[ -n $sts_mode ]] && echo ", then the mx: lines of the MTA-STS policy and its id")."
step=$((step + 1))
detail "$step. Check the new server's certificate for the MX name (section 8) and its PTR."
step=$((step + 1))
detail "$step. After a few days, remove the old SPF entry and DKIM key$([[ -n $sts_mode ]] && echo "; with clean TLS reports, $([[ $sts_mode == enforce ]] && echo "back" || echo "then") to enforce")."

if [[ -n $sts_mode || -n $reg_ds ]]; then
  info "Turning a protection off" "in this order, or the domain or its mail stops working"
  if [[ -n $sts_mode ]]; then
    detail "MTA-STS: set mode: none in the policy file and change the id in _mta-sts;"
    detail "  keep both for $(human_secs "${sts_max_age:-604800}") (max_age), then remove _mta-sts, the file and"
    detail "  the mta-sts host$([[ -n $tlsrpt_on ]] && echo " (_smtp._tls can stay: it only asks for reports)")."
  fi
  if [[ -n $reg_ds ]]; then
    detail "DNSSEC: remove the DS at the registrar, wait ${ds_ttl:-3600} s (its TTL) plus margin,"
    detail "  only then turn signing off at the DNS provider."
  fi
fi

# ---------------------------------------------------------- [14] how to fix ----
section 14 "HOW TO FIX" "practical steps for the findings above, most urgent first"
if ((${#FIX_1[@]} + ${#FIX_2[@]} + ${#FIX_3[@]} + ${#FIX_4[@]} == 0)); then
  info "Nothing to fix" "no action needed for the checks above"
else
  detail "Values on their own lines are ready to copy. Run the script again after each change."
  print_fixes "$C_RED" "✘" "${FIX_1[@]+"${FIX_1[@]}"}"
  print_fixes "$C_YELLOW" "⚠" "${FIX_2[@]+"${FIX_2[@]}"}"
  print_fixes "$C_CYAN" "◆" "${FIX_3[@]+"${FIX_3[@]}"}"
  print_fixes "$C_MAGENTA" "↑" "${FIX_4[@]+"${FIX_4[@]}"}"
fi
fi

# ------------------------------------------------------------ facts + changes ----
# Stable facts about the domain (volatile ones start with "~": days left, counts). A saved report
# keeps them as #NDM_FACT lines, so the next run can tell what changed.
FACTS=()
fact() { FACTS+=("$1=$(printf '%s' "$2" | tr '\n' ' ')"); }
set_join() { sed '/^$/d' | sort -u | paste -sd '|' -; }
case ${spf_l:-} in
  "") spf_all="none" ;;
  *" -all"*) spf_all="-all" ;;
  *" ~all"*) spf_all="~all" ;;
  *" ?all"*) spf_all="?all" ;;
  *redirect=*) spf_all="redirect" ;;
  *) spf_all="+all" ;;
esac
dmarc_pol=$(kv_tag "${dmarc:-}" p | tr '[:upper:]' '[:lower:]')
fact registrar "${registrar_name:-}"
fact expires "${reg_expires:-}"
fact status "${st:-}"
fact nameservers "$(printf '%s\n' "$deleg_l" | set_join)"
fact ds "$(awk 'NF {print $1 "/" $2 "/" $3 "/" substr($4, 1, 16)}' <<<"$reg_ds" | set_join)"
fact dnskey_algs "${dnskey_algs:-}"
fact mx "$(awk 'NF {print $1 "/" tolower($2)}' <<<"$mx" | sed 's/\.$//' | set_join)"
fact spf "${spf_l:-}"
fact dmarc "${dmarc:-}"
fact dkim "$(printf '%s\n' "${dkim_found[@]+"${dkim_found[@]}"}" | set_join)"
fact caa "$(printf '%s\n' "${caa:-}" | set_join)"
fact tls_issuer "${issuer:-}"
fact cert_sans "$(tr ', ' '\n' <<<"${sans:-}" | set_join)"
fact hsts "${hsts:-}"
fact mta_sts "${sts_mode:-}"
fact tlsrpt "${tlsrpt_on:+on}"
fact dane "$(awk 'NF {print $1}' <<<"${dane_data:-}" | set_join)"
fact '~reg_days' "${reg_days:-}"
fact '~cert_days' "${end_left:-}"
fact '~dnssec' "$([[ -n $reg_ds ]] && echo on || echo off)"
fact '~spf_all' "$spf_all"
fact '~dmarc_policy' "${dmarc_pol:--}"
fact '~mta_sts' "${sts_mode:--}"
fact '~mail' "$([[ -z $mx || $mx == "0 ." ]] && echo no || echo yes)"

if [[ -n ${_NDM_SAVE:-} || -n $COMPARE ]]; then
  prev=""
  for f in "$OUTPUT_DIR/${domain}_"*.txt; do [[ -e $f ]] && prev=$f; done   # names sort by date and time
  if [[ -n $prev ]]; then prev_src=$(basename "$prev"); else prev_src="no report saved yet in $OUTPUT_DIR"; fi
  section 15 "CHANGES SINCE THE LAST REPORT" "$prev_src"
  if [[ -z $prev ]]; then
    info "Changes" "nothing to compare with yet: save a report with -o, the next run will compare itself with it"
  elif ! grep -qa '^#NDM_FACT ' "$prev"; then
    info "Changes" "the last report has no comparison data (made by an older version)"
  else
    printf '%s\n' "${FACTS[@]}" | grep -v '^~' >"$tmpdir/facts_cur"
    grep -a '^#NDM_FACT ' "$prev" | sed 's/^#NDM_FACT //' | grep -v '^~' >"$tmpdir/facts_prev"
    changes=$(awk -v prevf="$tmpdir/facts_prev" -v curf="$tmpdir/facts_cur" '
      function load(file, arr,    line, i) {
        while ((getline line < file) > 0) { i = index(line, "="); if (i) arr[substr(line, 1, i - 1)] = substr(line, i + 1) }
        close(file)
      }
      BEGIN { load(prevf, old); load(curf, cur)
              for (k in cur) if ((k in old) && old[k] != cur[k]) printf "%s\t%s\t%s\n", k, old[k], cur[k] }' | sort)
    n_changes=0
    while IFS=$'\t' read -r k o n; do
      [[ -n $k ]] || continue
      n_changes=$((n_changes + 1))
      case $k in
        nameservers|ds|mx|dkim|caa|cert_sans|dane)
          added=$(comm -13 <(tr '|' '\n' <<<"$o" | sort) <(tr '|' '\n' <<<"$n" | sort) | sed '/^$/d' | paste -sd ' ' -)
          removed=$(comm -23 <(tr '|' '\n' <<<"$o" | sort) <(tr '|' '\n' <<<"$n" | sort) | sed '/^$/d' | paste -sd ' ' -)
          msg="${added:+added: $added}${added:+${removed:+; }}${removed:+removed: $removed}" ;;
        *) msg="${o:--} -> ${n:--}"; msg=${msg:0:150} ;;
      esac
      case $k in
        expires|tls_issuer|cert_sans|hsts|registrar|status) info "Changed: $k" "$msg" ;;
        *) check "Changed: $k" "$msg" ;;
      esac
    done <<<"$changes"
    ((n_changes == 0)) && ok "Changes" "nothing changed since $(basename "$prev" .txt | sed -E 's/^.*_([0-9]{4})([0-9]{2})([0-9]{2})-([0-9]{2})([0-9]{2})[0-9]{2}$/\1-\2-\3 \4:\5/')"
  fi
fi

# --------------------------------------------------------------- summary ----
if [[ -s $tmpdir/dns_errors ]]; then
  section "!" "DNS QUERY ERRORS" "resolver $RESOLVER"
  warn "DNS errors" "$(wc -l <"$tmpdir/dns_errors" | tr -d ' ') queries to $RESOLVER got no reply: findings such as \"missing\" may be wrong, run again"
fi
printf '\n'; rule
printf '%s  SUMMARY: %s%s   %s✔ %d ok%s  %s↑ %d improvable%s  %s◆ %d to check%s  %s⚠ %d warnings%s  %s✘ %d errors%s\n' \
  "$C_BOLD" "$domain" "$C_RESET" "$C_GREEN" "$OK_COUNT" "$C_RESET" "$C_MAGENTA" "$TIP_COUNT" "$C_RESET" \
  "$C_CYAN" "$CHECK_COUNT" "$C_RESET" "$C_YELLOW" "$WARN_COUNT" "$C_RESET" "$C_RED" "$FAIL_COUNT" "$C_RESET"
for f in "${FAIL_LIST[@]+"${FAIL_LIST[@]}"}"; do printf '  %s✘ %s%s\n' "$C_RED" "$f" "$C_RESET"; done
for w in "${WARN_LIST[@]+"${WARN_LIST[@]}"}"; do printf '  %s⚠ %s%s\n' "$C_YELLOW" "$w" "$C_RESET"; done
if ((CHECK_COUNT)); then
  printf '  %sTo check (cannot be judged automatically):%s\n' "$C_DIM" "$C_RESET"
  for c in "${CHECK_LIST[@]}"; do printf '  %s◆ %s%s\n' "$C_CYAN" "$c" "$C_RESET"; done
fi
if ((TIP_COUNT)); then
  printf '  %sImprovements:%s\n' "$C_DIM" "$C_RESET"
  for t in "${TIP_LIST[@]}"; do printf '  %s↑ %s%s\n' "$C_MAGENTA" "$t" "$C_RESET"; done
fi
rule; printf '\n'

fact '~err' "$FAIL_COUNT"; fact '~warn' "$WARN_COUNT"; fact '~check' "$CHECK_COUNT"; fact '~tip' "$TIP_COUNT"; fact '~ok' "$OK_COUNT"
if [[ -n ${_NDM_SAVE:-} ]]; then
  printf '#NDM_NOTE %s\n' \
    "Comparison data, hidden on screen: values found by this run." \
    "The next run with -o or -c compares itself with them (section 15, CHANGES)." \
    "Keys starting with ~ are counters for the multi-domain summary: not compared." \
    "Do not edit these lines."
  printf '#NDM_FACT %s\n' "${FACTS[@]}"
fi
[[ -n ${_NDM_FACTS_FILE:-} ]] && printf '%s\n' "${FACTS[@]}" >"$_NDM_FACTS_FILE"

((FAIL_COUNT == 0))
