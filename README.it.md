# NDM Domain Health Check

[English](README.md) · **Italiano**

[![License: AGPL v3+](https://img.shields.io/badge/License-AGPL_v3%2B-blue.svg)](LICENSE)
![Version](https://img.shields.io/badge/version-1.1.0-informational)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25)

**NDM Domain Health Check** controlla registrazione, DNS, DNSSEC, web/TLS e posta di un dominio
(SPF, DKIM, DMARC, server di posta, blocklist, proprietari degli IP) e assegna un
giudizio a ogni risultato, in un unico report a colori che indica da dove proviene ogni
valore.

È un solo script Bash senza librerie aggiuntive: usa `dig` e, quando disponibili,
strumenti standard come `python3` (solo libreria standard), `delv`, `openssl` e `curl`.

> Lo script, i suoi messaggi e i commenti nel codice sono in inglese; questa è la
> traduzione italiana della documentazione. In caso di differenze fa fede il
> [README in inglese](README.md).

## Origine

Faccio il sistemista dal 1993. Controllare un dominio ha sempre voluto dire la stessa
routine: qualche interrogazione con `dig`, uno sguardo al certificato, una prova del server
di posta. La routine è cresciuta insieme a Internet: SPF, DKIM, DMARC, DNSSEC, Certificate
Transparency e MTA-STS hanno aggiunto ogni volta qualcosa da controllare, e l'ho aggiunto a
uno script quando il lavoro lo richiedeva. NDM Domain Health Check è quello script,
in gran parte riscritto e documentato per la pubblicazione; la 1.1.0 è la prima versione
pubblica.

---

## Indice

- [Cosa controlla](#cosa-controlla)
  - [Come correggere](#come-correggere)
- [Livelli dei risultati](#livelli-dei-risultati)
- [Requisiti](#requisiti)
- [Installazione](#installazione)
  - [Windows (WSL)](#windows-wsl)
- [Utilizzo](#utilizzo)
- [Configurazione](#configurazione)
- [Salvare i report](#salvare-i-report)
- [Esempio di output](#esempio-di-output)
- [Operazioni delicate](#operazioni-delicate)
- [Uso responsabile e controllo passivo](#uso-responsabile-e-controllo-passivo)
- [Servizi esterni contattati](#servizi-esterni-contattati)
- [Codici di uscita](#codici-di-uscita)
- [Struttura del progetto](#struttura-del-progetto)
- [Versioni](#versioni)
- [Licenza e disclaimer](#licenza-e-disclaimer)

---

## Cosa controlla

Il report è diviso in sezioni numerate; ognuna indica la propria **fonte** (registro,
nameserver autoritativi, resolver pubblico, server web o di posta, servizio esterno).

| # | Sezione | Controlli principali |
|---|---------|----------------------|
| 1 | Registrazione | Registrar, intestatario (se pubblicato), creazione, scadenza con i giorni rimanenti, stato e blocco dei trasferimenti (via RDAP, altrimenti WHOIS) |
| 2 | Disponibilità | Ping, sito online con codice HTTP e tempo di risposta, servizio di posta raggiungibile |
| 3 | Registro (delega) | Nameserver e record DS così come li pubblica il registro del dominio di primo livello, record glue, scadenza dei domini che ospitano i nameserver |
| 4 | DNS autoritativi | Seriale SOA uguale su tutti i nameserver, nameserver nella zona e al registry, record glue, DNS su TCP, diversità dei nameserver, timer SOA, wildcard e TTL, trasferimento di zona (AXFR) rifiutato, DNSKEY; ricorsione aperta e versione del software dei nameserver *(solo domini tuoi)* |
| 5 | DNSSEC | Ogni DS confrontato con le chiavi pubblicate (scopre algoritmo o digest sbagliati), elencabilità della zona (NSEC/NSEC3), durata delle firme, algoritmi in uso, CDS/CDNSKEY, parametri NSEC3, validazione completa |
| 6 | Web e TLS | A/AAAA, redirect da HTTP a HTTPS, HSTS, header di sicurezza, versione TLS, emittente, nomi e scadenza del certificato, certificati di `www`/`mail`/`webmail`, versione HTTP, flag dei cookie, `security.txt`, versioni del software negli header, HSTS preload, chiave, firma, durata e catena del certificato, TLS 1.0/1.1 obsoleti e suite di cifratura deboli *(solo domini tuoi)* |
| 7 | Posta (DNS) | MX, SPF espanso per intero (ogni `include` fino alle reti, etichette facoltative per i tuoi provider, conteggio esatto delle ricerche DNS), mittenti autorizzati dall'SPF e loro coerenza con gli host del dominio, DMARC (policy dei sottodomini, `pct`, allineamento, indirizzi dei report presso altri domini che non li autorizzano), DKIM (dimensione della chiave, modalità di prova, chiavi revocate), MTA-STS, TLS-RPT, BIMI |
| 8 | Server di posta | Porte 25, 465, 587, 993, 995, 143, 110: STARTTLS / TLS, certificato, login offerto prima della cifratura, login in chiaro, banner SMTP e `VRFY`/`EXPN`, record TLSA confrontati con il certificato mostrato *(solo domini tuoi)* |
| 9 | Blocklist | IP che inviano posta presenti nelle DNSBL più comuni (la PBL di Spamhaus è distinta dagli inserimenti veri), IPv6 dove la lista lo supporta, e il nome del dominio nelle blocklist di domini |
| 10 | Indirizzi IP | Proprietario, rete, ASN e contatto abuse (RDAP tramite il bootstrap IANA, RIPEstat); DNS inverso presente, confermato, generico o del provider |
| 11 | CAA | Quali autorità di certificazione possono emettere certificati per il dominio |
| 12 | Certificate Transparency | Ogni nome che ha avuto un certificato (crt.sh), se è ancora valido e ancora nel DNS; CNAME che puntano a un bersaglio inesistente (rischio di subdomain takeover); *solo domini tuoi:* HTTPS di ogni nome attivo, CNAME verso servizi che segnalano il sito come non rivendicato |
| 13 | Note per i cambi di provider | Cosa fare, per la configurazione di *questo* dominio, se cambi registrar, provider DNS, hosting o server di posta, e come disattivare DNSSEC o MTA-STS senza rischi (vedi [Operazioni delicate](#operazioni-delicate)) |
| 14 | Come correggere | Passi pratici per i risultati precedenti, dai più urgenti, con i valori pronti da copiare (vedi sotto) |
| 15 | Cambiamenti | Con `--output` o `--compare`: cosa è cambiato dall'ultimo report salvato (nameserver, DS, MX, SPF, DMARC, DKIM, certificati…) |

Un **riepilogo** finale elenca errori, avvisi, voci da verificare e possibili
miglioramenti.

**IPv6:** i record AAAA sono controllati insieme agli A ovunque: sito, host MX, host di posta,
SPF (`ip6:` e la lunghezza IPv6 di `a`/`mx`, per esempio `a:host/24//64`), DNS inverso e
proprietario/ASN di ogni indirizzo. Le blocklist sono interrogate via IPv6 solo su Spamhaus ZEN
e sulle zone indicate come `zona:livello:6` in `DNSBLS`; le altre risultano non adatte a IPv6.
Le connessioni ai server web e di posta usano l'IPv6 della macchina da cui lanci lo script,
se ne ha uno.

### Come correggere

Le sezioni 1–12 restano compatte: fanno solo la diagnosi. La sezione 14 raccoglie cosa
fare, numerato dal più urgente (errori, poi avvisi, voci da verificare, miglioramenti),
e calcola i valori per *questo* dominio dove possibile:

- **DNSSEC**: quando la zona è firmata ma il registro non ha il DS, i parametri da
  inserire nel pannello del registrar (key tag, algoritmo, tipo di digest, digest), il
  record DS completo e, per i pannelli che lo chiedono, il DNSKEY; quale DS togliere
  quando uno è vecchio o quando la zona non è più firmata;
- **posta**: i record SPF, DMARC (con un percorso graduale da `p=none` alla protezione
  piena), il file della policy MTA-STS (costruito dagli MX) e il record TLS-RPT da
  pubblicare;
- **web**: redirect da HTTP a HTTPS, HSTS e header di sicurezza per Apache e nginx;
- **server**: versioni TLS, cifratura e login in chiaro per Dovecot, Exim e Postfix;
- **DNS inverso, CAA e blocklist**: il PTR da chiedere, il record CAA per l'autorità che
  ha emesso il certificato attuale, la pagina di rimozione di ogni blocklist.

Con `--brief` le sezioni 13 e 14 vengono saltate, quando serve solo la diagnosi.

## Livelli dei risultati

| Simbolo | Livello | Significato |
|:-------:|---------|-------------|
| ✔ | OK | Corretto |
| ↑ | Migliorabile | Funziona, ma si può migliorare |
| ◆ | Da verificare | Non si può giudicare in automatico: una persona deve confermare che sia voluto |
| ⚠ | Avviso | Funziona, ma è rischioso o richiede attenzione a breve |
| ✘ | Errore | Non funziona o non è sicuro |
| ℹ | Info | Informazione neutra |

Il livello "da verificare" serve per casi come un indirizzo IP autorizzato nell'SPF che
non corrisponde a nessun host del dominio: può essere un servizio esterno legittimo o un
server dimenticato, e solo tu puoi saperlo.

## Requisiti

| Strumento | Serve per | |
|-----------|-----------|---|
| `dig` | Tutte le interrogazioni DNS | **obbligatorio** |
| `python3` | Registrazione, prove TLS e posta, analisi SPF, dati sugli IP, log CT (solo libreria standard) | facoltativo |
| `delv` | Validazione DNSSEC completa | facoltativo |
| `openssl` | Dettagli dei certificati | facoltativo |
| `curl` | Controlli web, policy MTA-STS | facoltativo |
| `ping` | Disponibilità | facoltativo |

Se manca uno strumento facoltativo vengono saltati solo i controlli relativi, e il
report lo dice. Con `./ndm_domain-health-check.sh --requirements` vedi cosa manca e il comando
esatto per installarlo sul tuo sistema:

| Sistema | Comando |
|---------|---------|
| Debian / Ubuntu | `sudo apt install dnsutils python3 openssl curl iputils-ping` |
| Fedora / RHEL 8+ | `sudo dnf install bind-utils python3 openssl curl iputils` |
| CentOS / RHEL 7 | `sudo yum install bind-utils python3 openssl curl iputils` |
| openSUSE | `sudo zypper install bind-utils python3 openssl curl iputils` |
| Arch / Manjaro | `sudo pacman -S bind python openssl curl iputils` |
| Alpine | `sudo apk add bind-tools python3 openssl curl iputils` |
| macOS (Homebrew) | `brew install bind python openssl curl` |
| Windows | Usalo in WSL: vedi [Windows (WSL)](#windows-wsl) |

## Installazione

```bash
git clone https://github.com/nidamanx/NDM_Domain-Health-Check.git
cd NDM_Domain-Health-Check
chmod +x ndm_domain-health-check.sh
./ndm_domain-health-check.sh --requirements      # verifica gli strumenti necessari
```

Facoltativo: rendilo disponibile ovunque con un collegamento simbolico. Lo script trova
comunque il file di configurazione e la cartella `reports/` accanto alla sua posizione
reale.

```bash
ln -s "$PWD/ndm_domain-health-check.sh" ~/.local/bin/ndm_domain-health-check
```

### Windows (WSL)

Lo script ha bisogno di una shell Linux o macOS. Su Windows 10 e 11 si usa dentro
**WSL** (Windows Subsystem for Linux), che fornisce un vero ambiente Ubuntu. Git Bash,
MSYS2 e Cygwin non sono supportati.

1. Apri **PowerShell come amministratore**, installa WSL (Ubuntu è la scelta
   predefinita) e riavvia Windows quando richiesto:

   ```powershell
   wsl --install
   ```

2. Apri **Ubuntu** dal menu Start, crea l'utente Linux quando richiesto, poi installa
   gli strumenti e lo script nella tua cartella home di Linux:

   ```bash
   sudo apt update
   sudo apt install git dnsutils python3 openssl curl iputils-ping
   cd ~
   git clone https://github.com/nidamanx/NDM_Domain-Health-Check.git
   cd NDM_Domain-Health-Check
   ./ndm_domain-health-check.sh --requirements
   ```

Note per Windows:

- Tieni la cartella nella home di Linux (`~`), non sotto `/mnt/c/...`: sui dischi di
  Windows il permesso di esecuzione può andare perso e l'accesso ai file è più lento.
- Clona da dentro WSL. Il file `.gitattributes` del repository mantiene le terminazioni
  di riga Linux anche se cloni con Git per Windows: quelle di Windows (CRLF)
  romperebbero lo script con errori come `/usr/bin/env: 'bash\r': No such file or
  directory`.
- Per aprire i report salvati in Esplora file, dalla cartella dello script esegui
  `explorer.exe reports`.

## Utilizzo

```
./ndm_domain-health-check.sh [opzioni] [dominio]
```

Se non indichi il dominio, lo script lo chiede. Indica il dominio registrato
(`example.com`), non un sottodominio: `www`, gli MX e gli altri nomi vengono controllati
in automatico.

| Opzione | Descrizione |
|---------|-------------|
| `-p`, `--passive` | Solo interrogazioni DNS e normali visite web: nessuna richiesta AXFR, nessuna prova di TLS obsoleti, nessuna connessione alle porte di posta |
| `-b`, `--brief` | Solo diagnosi: salta le sezioni 13 (note per i cambi di provider) e 14 (come correggere) |
| `-c`, `--compare` | Mostra cosa è cambiato dall'ultimo report salvato del dominio (salvando con `--output` lo fa sempre) |
| `-a`, `--all` | Controlla il dominio indicato e ogni dominio di `RELATED_DOMAINS`, quattro alla volta, e stampa una tabella riassuntiva |
| `-r`, `--related-domains ELENCO` | I tuoi altri domini, separati da virgola o spazio. Un IP che invia posta, il cui DNS inverso è un host confermato di uno di essi, viene riconosciuto come tuo. Ha la precedenza su `RELATED_DOMAINS` |
| `-o`, `--output` | Salva il report anche come testo semplice (vedi [Salvare i report](#salvare-i-report)) |
| `-d`, `--output-dir CARTELLA` | Salva il report in `CARTELLA` (implica `--output`) |
| `--requirements` | Mostra gli strumenti necessari e come installarli |
| `-v`, `--version` | Mostra nome, versione, autore, licenza e disclaimer |
| `-h`, `--help` | Mostra l'aiuto |

Esempi:

```bash
# Controllo completo del TUO dominio (sostituisci example.com con il tuo)
./ndm_domain-health-check.sh example.com

# Un dominio che non è tuo: controllo passivo
./ndm_domain-health-check.sh --passive example.org

# Il tuo dominio; gli host dei tuoi altri domini sono riconosciuti come tuoi
./ndm_domain-health-check.sh --related-domains "example.net example.org" example.com

# Il tuo dominio, con il report salvato anche in reports/
./ndm_domain-health-check.sh -o example.com
```

I nomi `example.*` qui sopra sono segnaposto riservati alla documentazione (RFC 2606):
esegui il controllo completo solo sui domini che possiedi o gestisci, e `--passive` su
tutti gli altri (vedi [Uso responsabile e controllo passivo](#uso-responsabile-e-controllo-passivo)).
Alcune reti bloccano le connessioni in uscita verso la porta 25: da lì i controlli dei
server di posta possono dare la porta 25 irraggiungibile anche quando funziona.

## Configurazione

Le impostazioni stanno in un file **accanto allo script**, con lo stesso nome ed
estensione `.conf`: `ndm_domain-health-check.conf`. Parti dal modello:

```bash
cp ndm_domain-health-check.conf.example ndm_domain-health-check.conf
```

Una riga `CHIAVE=valore` per impostazione; le righe che iniziano con `#` sono ignorate.
Il file viene **solo letto, mai eseguito**. È personale (contiene i tuoi domini), per
questo è elencato in `.gitignore`: nel repository va solo il modello `.example`.

| Chiave | Predefinito | Descrizione |
|--------|-------------|-------------|
| `RELATED_DOMAINS` | *(nessuno)* | I tuoi altri domini (vedi `--related-domains`) |
| `RESOLVER` | `9.9.9.10` | Resolver che valida DNSSEC usato per i controlli (Quad9 senza filtro malware, vedi [Servizi esterni contattati](#servizi-esterni-contattati)) |
| `DKIM_SELECTORS` | i più comuni (vedi il modello) | Selettori DKIM da cercare: il DNS non permette di elencarli, quindi aggiungi il tuo se non viene trovato |
| `OUTPUT_DIR` | `reports` | Cartella per `--output`; i percorsi relativi partono dalla cartella dello script |
| `NO_COLOR` | *(vuoto)* | Qualsiasi valore disattiva i colori |
| `DNSBLS` | PSBL, Spamhaus ZEN | Blocklist da controllare, come `zona:livello` (`fail` o `warn` se l'IP è in lista); aggiungi `:6` (`zona:livello:6`) se la lista risponde anche per IPv6 |
| `DOMAIN_DNSBLS` | Spamhaus DBL | Blocklist di nomi di dominio, come `zona:livello`; lasciala vuota per saltarle |
| `DNSBL_RESOLVER` | *(resolver di sistema)* | Resolver usato solo per le blocklist: Spamhaus e altre rifiutano i resolver pubblici o condivisi, quindi indica il tuo (per esempio `127.0.0.1`) |
| `CT_LOOKUP` | `on` | `off` salta la ricerca nei log di Certificate Transparency |
| `SPF_PROVIDERS` | *(vuoto)* | Etichette per gli include SPF: `testo=Etichetta; testo=Etichetta` (senza etichette gli include sono mostrati col loro nome) |

**Precedenza:** opzioni da riga di comando › ambiente › file di configurazione › valori
predefiniti. Per una singola esecuzione puoi passare un'impostazione nell'ambiente:

```bash
RESOLVER=127.0.0.1 ./ndm_domain-health-check.sh example.com
```

`RELATED_DOMAINS` è l'eccezione: viene letto **solo** dal file di configurazione o da
`--related-domains`, mai dall'ambiente, così una variabile rimasta esportata nella
shell non può cambiare i risultati senza che tu te ne accorga. Se è commentato o
assente, non ci sono domini collegati.

### Scegliere il resolver per le blocklist

Alcune blocklist, Spamhaus tra queste, rifiutano le query che arrivano da resolver pubblici o
condivisi. In quel caso il report mostra un avviso (`refused the queries: NOT checked`) e
quella lista non rientra nel conteggio di "not listed". `DNSBL_RESOLVER` manda al resolver
accettato dalle liste solo le query delle blocklist; tutto il resto continua a usare `RESOLVER`.

Cosa usare, in ordine di preferenza:

1. **`127.0.0.1`**, se la macchina ha un proprio resolver ricorsivo (Unbound, Knot Resolver,
   BIND). Le query partono dal tuo indirizzo, come si aspettano le liste. Non serve se
   `127.0.0.1` si limita a inoltrare a un altro resolver (uno stub come `systemd-resolved` o
   `dnsmasq`): la query esce comunque dall'upstream del forwarder.
2. **Il router o gateway, oppure il resolver del provider**, se risolve da sé o inoltra al
   provider. Le liste vedono un normale cliente a basso volume e accettano. Non funziona se il
   router inoltra a un resolver pubblico.
3. **Evita i resolver pubblici** (Google, Cloudflare, Quad9...): sono condivisi da moltissimi
   client, le liste non li distinguono e li rifiutano per limitare gli abusi.

Per verificare se un resolver è accettato (sostituisci `<ip-resolver>` con il suo indirizzo):

```bash
dig +short 2.0.0.127.zen.spamhaus.org @<ip-resolver>
```

`2.0.0.127` è l'indirizzo di prova di Spamhaus ed è sempre in lista:

| Risposta | Significato |
|----------|-------------|
| `127.0.0.2` (spesso con `127.0.0.4` e `127.0.0.10`) | Accettato: usa questo resolver |
| `127.255.255.254` (qualsiasi `127.255.255.x`) | Rifiutato: resolver pubblico o condiviso |
| nessuna risposta, o timeout | Il resolver non risponde o non risolve |

Poi impostalo nel file di configurazione, per esempio `DNSBL_RESOLVER=127.0.0.1`.

## Salvare i report

```bash
./ndm_domain-health-check.sh -o example.com
# ...report a schermo...
Report saved to: /percorso/NDM_Domain-Health-Check/reports/example.com_20261014-113538.txt
```

- Nome del file: `<dominio>_<AAAAMMGG>-<HHMMSS>.txt`, testo semplice (senza colori). Il file è
  privato (modo 600: contiene i dati reali del tuo dominio) e un file esistente non viene mai
  sovrascritto.
- Ogni report salvato termina con righe `#NDM_FACT`, precedute da alcune righe `#NDM_NOTE` che
  le spiegano (entrambe nascoste a schermo). La volta dopo, con `--output` o `--compare`, lo
  script si confronta con l'ultimo report dello stesso dominio e stampa la sezione 15:
  cambiamenti di nameserver, DS, MX, SPF, DMARC, DKIM, CAA e simili sono segnati come "da
  verificare".
- Cartella predefinita: `reports/` accanto allo script. Viene distribuita vuota (nel
  repository c'è solo il segnaposto `.gitkeep`); i report salvati lì sono ignorati da
  Git.
- `OUTPUT_DIR` nel file di configurazione la cambia in modo permanente; `--output-dir
  CARTELLA` la cambia per una sola esecuzione (una `CARTELLA` relativa parte dalla
  cartella corrente).

## Esempio di output

> **Nota:** questo output è solo un esempio. Nomi di dominio, indirizzi, chiavi e
> record sono valori fittizi riservati alla documentazione (RFC 2606, RFC 5737,
> RFC 5398): non sono i dati reali di `example.com` e possono non corrispondere a ciò
> che lo script mostra oggi. Anche l'impaginazione del report può cambiare tra una
> versione e l'altra. Il report è in inglese, come lo script.

Un report ridotto, prodotto in modalità passiva come per qualsiasi dominio che non è
tuo:

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

## Operazioni delicate

Alcune protezioni legano tra loro registrar, provider DNS, hosting e server di posta.
Cambiarne uno nell'ordine sbagliato può rendere il dominio, o la sua posta,
irraggiungibile per ore o giorni. La sezione 13 del report elenca questi passi per il
dominio analizzato, con i suoi valori reali (TTL, `max_age`, selettori); qui trovi il
riferimento completo.

Prima di qualsiasi cambio, salva un report dello stato attuale (`--output`): è l'elenco di ciò
che dopo deve essere ancora al suo posto. Dopo ogni passo, rilancia lo script.

### Cambio di registrar

I record DNS e le chiavi DNSSEC non si spostano: si sposta solo la registrazione.

1. Annota i nameserver e i record DS (sezione 3).
2. Sblocca il dominio, chiedi il codice di trasferimento, verifica che l'e-mail
   dell'intestatario funzioni.
3. Dopo il trasferimento, controlla che nameserver e DS siano invariati. Alcuni
   registrar perdono il DS: il dominio continua a funzionare, ma senza firma.
   Reinserisci lo stesso DS.

### Cambio di provider DNS

1. Copia **tutti** i record nel nuovo provider, poi confrontali uno per uno con il
   report salvato: A/AAAA, CNAME, MX, SPF, DKIM, DMARC, MTA-STS (`_mta-sts`), TLS-RPT
   (`_smtp._tls`), CAA, SRV e ogni altro.
2. Il giorno prima, abbassa i TTL.
3. Con DNSSEC attivo: togli **prima** il DS dal registrar, poi aspetta il suo TTL più un
   margine (24 ore sono sicure). Non cambiare mai i nameserver mentre il vecchio DS è
   pubblicato: i resolver che validano smetterebbero di risolvere il dominio.
4. Cambia i nameserver presso il registrar e aspetta 24–48 ore.
5. Attiva DNSSEC nel nuovo provider e dai al registrar il **nuovo** DS.

### Cambio di hosting web

1. Il giorno prima, abbassa i TTL.
2. Se i nameserver sono dell'hosting, è anche un cambio di provider DNS: segui prima
   quella procedura.
3. Con MTA-STS: copia il file della policy nel nuovo hosting, con un certificato valido
   per `mta-sts.<dominio>`, **prima** di spostarne l'indirizzo.
4. Aggiorna i record A/AAAA e ogni indirizzo IP scritto nell'SPF.
5. Se la posta sta sullo stesso hosting, segui anche la procedura seguente.

### Cambio di server o servizio di posta

1. Con MTA-STS in `enforce`: almeno `max_age` prima del cambio, aggiungi il nuovo server
   di posta come riga `mx:` in più nella policy (oppure imposta `mode: testing`) e
   cambia l'`id` in `_mta-sts`. I mittenti accettano solo gli MX elencati nella policy
   che hanno in memoria.
2. Il giorno prima, abbassa il TTL del record MX.
3. Pubblica la voce SPF e la chiave DKIM del nuovo server **prima** del cambio; tieni le
   vecchie finché il trasloco non è finito.
4. Cambia l'MX, poi le righe `mx:` della policy MTA-STS e il suo `id`.
5. Controlla il certificato del nuovo server per il nome dell'MX (sezione 8) e il suo
   DNS inverso.
6. Dopo qualche giorno, togli la vecchia voce SPF e la vecchia chiave DKIM; con rapporti
   TLS puliti, torna a `enforce`.

### DNSSEC: attivazione e disattivazione

- **Attivare**: attiva la firma nel provider DNS, poi dai al registrar il DS mostrato
  nella sezione 14. Serve solo la chiave di firma delle chiavi (flags 257).
- **Disattivare**: togli il DS dal registrar, aspetta il suo TTL più un margine, e solo
  dopo disattiva la firma. L'ordine inverso rompe il dominio per i resolver che
  validano.

### MTA-STS: attivazione, enforce, modifica, disattivazione

MTA-STS dice ai server che ti spediscono posta: "consegnala ai miei MX solo via TLS,
con un certificato valido". Per tutte le operazioni qui sotto valgono due regole:

- i mittenti tengono la policy in memoria per `max_age` secondi, quindi una modifica
  arriva a tutti solo dopo quel tempo;
- ogni modifica del file della policy richiede un **nuovo `id`** nel record TXT
  `_mta-sts`, altrimenti i mittenti non scaricano nemmeno il file nuovo.

**Prima di iniziare**

1. Il server di posta deve presentare, sulla porta 25, un certificato valido che
   contenga il nome dell'MX: lo dice la sezione 8 del report, oppure
   `openssl s_client -starttls smtp -connect <mx>:25 -servername <mx> -verify_hostname <mx> -brief </dev/null`
   deve rispondere `Verification: OK`.
2. Crea una casella (o un inoltro) per i rapporti TLS, per esempio `tlsrpt@<dominio>`.

**Attivare (modalità `testing`: non viene mai rifiutato niente)**

1. DNS: crea `mta-sts.<dominio>` (record A o CNAME) che punti al server web che servirà
   il file, **senza** proxy o CDN.
2. Server web: crea il sito `mta-sts.<dominio>` e ottieni il suo certificato. Se il
   pannello dell'hosting vuole anche `www.mta-sts.<dominio>` e non permette di
   escluderlo, aggiungi nel DNS `www.mta-sts.<dominio>. CNAME mta-sts.<dominio>.`
3. In quel sito crea il file `.well-known/mta-sts.txt` con una riga `mx:` per ogni record
   MX (la sezione 14 del report te lo dà già pronto, costruito dai tuoi MX):
   ```
   version: STSv1
   mode: testing
   mx: mail.example.com
   max_age: 86400
   ```
4. Verifica che risponda direttamente con `200`, senza redirect, e mostri il file:
   `curl -i https://mta-sts.<dominio>/.well-known/mta-sts.txt`
5. DNS: pubblica i due record TXT (l'`id` è un testo libero: la data più un contatore è
   comoda):
   ```
   _mta-sts.<dominio>.    TXT  "v=STSv1; id=2026101501"
   _smtp._tls.<dominio>.  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@<dominio>"
   ```
6. Lancia lo script: la sezione 7 deve mostrare `MTA-STS mode testing` e
   `TLS-RPT published`.

**Passare a `enforce`**

1. Leggi i rapporti TLS giornalieri per 2–4 settimane: `total-failure-session-count`
   deve restare a `0`. Un errore vuol dire che un mittente non è riuscito a ottenere una
   connessione TLS valida: scopri il motivo prima di andare avanti.
2. Nel file imposta `mode: enforce` e `max_age: 604800` (una settimana).
3. Cambia l'`id` in `_mta-sts` (per esempio `id=2026111501`).
4. Verifica con `curl` e con lo script: la sezione 7 deve mostrare
   `MTA-STS mode enforce`.

**Modificare la policy** (un altro MX, un nuovo server di posta)

1. Modifica il file: aggiungi o togli le righe `mx:`.
2. Cambia l'`id` in `_mta-sts`.
3. Se la posta si sposta su un altro server, segui
   [Cambio di server o servizio di posta](#cambio-di-server-o-servizio-di-posta): in
   `enforce` il nuovo server deve essere nella policy almeno `max_age` prima del cambio.

**Disattivare**

1. Nel file imposta `mode: none` e cambia l'`id` in `_mta-sts`.
2. Lascia online file e record per `max_age` (una settimana con `604800`): i mittenti
   sostituiscono la policy in memoria con quella `none`.
3. Poi togli il record `_mta-sts`, il file, il sito `mta-sts` e i suoi record DNS
   (compreso `www.mta-sts`, se l'avevi aggiunto). `_smtp._tls` può restare: chiede solo
   i rapporti.

**Cosa può andare storto**

- In `enforce`, un certificato del server di posta scaduto o senza il nome dell'MX: i
  mittenti tengono la tua posta in coda e, dopo qualche giorno, la restituiscono al
  mittente. Tieni d'occhio i rinnovi dei certificati e i rapporti TLS.
- Un file modificato con lo stesso `id`: i mittenti ignorano la modifica fino alla
  scadenza di `max_age`.
- Record tolti senza passare da `mode: none`: i mittenti tengono la vecchia policy fino
  alla scadenza di `max_age`.

### DMARC: rendere la policy più rigida

Procedi un passo alla volta, leggendo i rapporti (`rua=`) tra un passo e l'altro:
`p=none` (monitoraggio) → `p=quarantine` → `p=reject`. Prima di ogni passo, ogni
servizio che invia posta a nome del tuo dominio deve superare SPF o DKIM allineati con
esso: una newsletter o un gestionale di fatturazione dimenticati vedrebbero la loro
posta messa in quarantena o rifiutata.

### Rotazione di una chiave DKIM

Pubblica la nuova chiave con un selettore **nuovo**, fai firmare con quella, e togli la
vecchia solo una settimana dopo: la posta già inviata viene ancora verificata con la
vecchia.

## Uso responsabile e controllo passivo

Quasi tutto ciò che lo script legge è pubblico per sua natura: record DNS, dati di
registrazione, certificati, header HTTP, blocklist. Alcuni controlli vanno un passo
oltre e si eseguono normalmente sui **tuoi** domini, o su domini che gestisci con il
consenso del proprietario:

- **AXFR**: chiede a ogni nameserver l'intera zona (un server configurato bene rifiuta);
- **TLS obsoleti**: prova una connessione TLS 1.0/1.1;
- **porte di posta**: si collega alle porte 25, 465, 587, 993, 995, 143 e 110 e ne legge
  le funzionalità. Non tenta mai un login e non usa credenziali;
- **sonde sui server**: suite di cifratura deboli sulle porte TLS di web e posta, il banner SMTP e
  i comandi `VRFY`/`EXPN`, ricorsione e `version.bind` sui nameserver, TLS su ogni nome attivo
  trovato nei log CT, e una richiesta web ai nomi il cui CNAME punta a un servizio dove i siti
  possono essere rivendicati.

Per i domini che non sono tuoi usa `--passive`: salta tutti. Evita controlli
ripetuti o di massa su domini di terzi. I dati di registrazione possono contenere dati
personali (GDPR): leggerli è legittimo, conservarli o riutilizzarli no.

Quello che un dominio controllato può far fare allo script è limitato. Ogni connessione (web,
TLS, porte di posta, ping) va solo verso indirizzi pubblici: un nome del dominio, o un redirect,
che risolve verso loopback, la LAN o un'altra rete privata non viene contattato (altrimenti un
dominio ostile potrebbe puntare lo script alla tua rete). Gli indirizzi sono verificati tramite il
resolver configurato e poi fissati, così ogni strumento si collega proprio agli indirizzi
verificati. I controlli web seguono al massimo 5 redirect, e solo verso HTTP(S). I nomi letti dai
record DNS sono validati prima di arrivare a `dig`, l'albero SPF è analizzato fino a 50 record, le
risposte lette da un server hanno un limite di dimensione e ogni sonda di posta ha un tempo
massimo complessivo. Gli helper Python incorporati girano in modalità isolata, quindi non
importano mai moduli dalla cartella corrente.

## Servizi esterni contattati

| Servizio | Usato per |
|----------|-----------|
| Resolver che valida DNSSEC (`RESOLVER`, predefinito Quad9 `9.9.9.10`) | Interrogazioni DNS e validazione DNSSEC |
| Nameserver del registro del dominio di primo livello | NS e DS esattamente come li pubblica il registro |
| Nameserver autoritativi del dominio | SOA, DNSKEY, firme, prova AXFR |
| Bootstrap RDAP di IANA, server RDAP / WHOIS dei registri | Registrazione del dominio e proprietari degli IP |
| RIPEstat (RIPE NCC) | Prefisso annunciato e ASN di origine degli indirizzi IP |
| crt.sh | Log di Certificate Transparency (`CT_LOOKUP=off` lo salta) |
| Gestori delle DNSBL (tramite il resolver del tuo sistema, o `DNSBL_RESOLVER`) | Controlli delle blocklist |
| Server web e di posta del dominio | Controlli HTTP/TLS e di posta (non in modalità passiva, tranne le normali visite web) |

I valori predefiniti privilegiano enti senza scopo di lucro e servizi gratuiti, e
ognuno si può cambiare nel file di configurazione:

- **Quad9** è gestito da una fondazione svizzera senza scopo di lucro e non conserva gli
  indirizzi IP dei client. `9.9.9.10` valida DNSSEC ma, a differenza di `9.9.9.9`, non
  blocca i domini che considera malevoli, quindi anche quelli vengono controllati per
  come sono davvero. Va bene anche un tuo resolver che valida (per esempio Knot
  Resolver o Unbound).
- **RIPEstat** è il servizio di dati pubblici del RIPE NCC, il registro regionale
  europeo senza scopo di lucro; copre gli indirizzi di tutte le regioni. Le richieste
  si identificano con `sourceapp=ndm_domain-health-check`, come chiede RIPEstat.
- **Blocklist**: quelle predefinite (PSBL, Spamhaus ZEN) sono gestite da progetti senza
  scopo di lucro o comunitari, e sono gratuite da consultare e da cui uscire. Puoi
  aggiungerne altre in `DNSBLS`.
- **crt.sh** è software open source e un servizio pubblico gratuito, la ricerca più
  completa nei log CT. Con `CT_LOOKUP=off` viene saltata.

I consigli pratici della sezione 14 fanno riferimento a software open source (Apache,
BIND, certbot, Dovecot, Exim, Knot DNS, nginx, OpenDKIM, PowerDNS, Postfix, rspamd) e
per il resto descrivono l'impostazione da cercare, senza nominare pannelli o provider
commerciali. I nomi di provider e autorità di certificazione compaiono nel report solo
quando si trovano nei dati del dominio analizzato.

## Codici di uscita

| Codice | Significato |
|:------:|-------------|
| `0` | Controllo completato, nessun errore (possono esserci avvisi e suggerimenti) |
| `1` | Controllo completato con almeno un errore, oppure impossibile da eseguire (strumento obbligatorio mancante, dominio non valido, registro irraggiungibile) |
| `2` | Uso non valido della riga di comando |

Così lo script si può usare in un cron o da altri script.

## Struttura del progetto

```
NDM_Domain-Health-Check/
├── ndm_domain-health-check.sh            lo script
├── ndm_domain-health-check.conf.example  modello di configurazione (nel repository)
├── ndm_domain-health-check.conf          la tua configurazione (personale, ignorata da Git)
├── reports/                              report salvati (contenuto ignorato da Git)
│   └── .gitkeep                          mantiene la cartella vuota nel repository
├── .github/workflows/ci.yml              controlli automatici (ShellCheck, test di base)
├── .github/dependabot.yml                aggiornamento mensile delle GitHub Actions usate dalla CI
├── .gitattributes                        mantiene le terminazioni di riga Linux (serve su Windows)
├── .gitignore
├── LICENSE                               GNU AGPL v3
├── CHANGELOG.md                          modifiche di ogni versione (in inglese)
├── SECURITY.md                           come segnalare una vulnerabilità
├── README.md                             documentazione in inglese
└── README.it.md                          documentazione in italiano
```

## Versioni

Il progetto segue il [Semantic Versioning](https://semver.org/lang/it/). Nome,
descrizione, autore, versione e data di rilascio sono nel blocco **APP INFO** in cima a
`ndm_domain-health-check.sh`; `--version` li mostra. Ogni versione ha un tag Git `vX.Y.Z`
e le modifiche di ciascuna sono elencate in [CHANGELOG.md](CHANGELOG.md) (in inglese).

## Licenza e disclaimer

Copyright (C) 2026 Nicola Davide Mannarelli ([@nidamanx](https://github.com/nidamanx))

Questo programma è software libero: puoi ridistribuirlo e/o modificarlo secondo i
termini della **GNU Affero General Public License** pubblicata dalla Free Software
Foundation, nella versione 3 della licenza o (a tua scelta) in qualsiasi versione
successiva (`SPDX-License-Identifier: AGPL-3.0-or-later`). Vedi il file
[LICENSE](LICENSE): il testo della licenza che ha valore legale è quello inglese.

**Disclaimer.** Questo software è fornito "così com'è", senza garanzie di alcun tipo,
esplicite o implicite. In nessun caso l'autore potrà essere ritenuto responsabile di
reclami, danni o altre responsabilità, compresi perdita di dati, interruzioni di
servizio o indirizzi IP bloccati, derivanti dall'uso o dall'uso improprio di questo
software. Sei l'unico responsabile di come lo usi, compresi i controlli eseguiti su
domini e server che non possiedi o non gestisci, e di ogni decisione presa sulla base
dei suoi risultati. Questa è una traduzione di cortesia: fa fede il testo inglese.
