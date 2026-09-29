# Fork: matchlock mit zwei Patches für Safehouse

**Branch:** `patches-v2`, aufgesetzt auf Upstream `main` (Stand 26.08.2026).
Der frühere Branch `allow-private-ips` hing 171 Commits zurück und ist überholt.

## Warum der Sprung nötig war

Auf dem alten Stand starb die Sandbox reproduzierbar: nach 3 bis 18 Requests lieferte DNS
`EAI_AGAIN`, neue Verbindungen liefen in Timeouts, und die VM erholte sich nicht mehr —
selbst ein lokales `ip addr show` im Gast antwortete nicht mehr. Der Host-Prozess stand
dabei bei 0 % CPU und baute keine einzige neue Verbindung auf.

Ursache waren ein Socket-Leck im DNS-Forwarder und ein fehlendes Deadline beim
Upstream-Read. Beides ist upstream behoben:

```
58d7b0b fix(net): bound DNS forwarder concurrency and close upstream sockets
0cebd53 fix(net/darwin): bound upstream DNS read with a 2s deadline
32b2477 fix(net): update darwin DNS upstream timeout and logging
72543bf fix(net): refactor Darwin DNS forwarding with timed upstream exchange
```

Nach dem Update: 25 von 25 Requests im Dauertest, kein Fehler, Median 2,5 s.

**Lehre für das nächste Mal:** Bevor man tagelang Hypothesen misst, prüft man, ob der
eingesetzte Stand aktuell ist. Auch das mitgelieferte `guest-init` gehört dazu — das lag
hier noch auf v0.2.1, während v0.2.17 aktuell war.

---

## Patch 1: `--allow-private-ips`

`BlockPrivateIPs` ist im CLI hart auf `true` gesetzt (`cmd_run.go`). Das blockiert alle
Verbindungen zu privaten IP-Bereichen (10/8, 172.16/12, 192.168/16) — auch wenn die IP
explizit in `--allow-host` steht.

Das verhindert SSH-Agent-Forwarding über eine socat-Brücke, bei der die Guest-VM eine
TCP-Verbindung zur privaten Host-IP aufbauen muss.

```diff
- BlockPrivateIPs: true,
+ BlockPrivateIPs: !allowPrivateIPs,
```

Neuer Flag `--allow-private-ips` (Default `false`, Verhalten bleibt abwärtskompatibel).

**Weiterhin offen (nicht gefixt):** Der gVisor-Passthrough für Nicht-HTTP-Ports prüft
`IsHostAllowed()` mit der aufgelösten IP, die Allowlist enthält aber Hostnamen. Deshalb
müssen Hostname **und** IP angegeben werden. Safehouse löst das im Wrapper per `dig` und
gibt zusätzlich ein `--add-host <name>:<ip>` mit, damit der Gast den Namen auch selbst
auflösen kann.

---

## Patch 2: `--secret-from-file`

`ParseSecret` liest den Wert einmal beim Start, danach ist er für die Laufzeit der VM
fest. Für rotierende Credentials trägt das nicht: ein Claude-Max-OAuth-Token ist
kurzlebig, und in der VM kann ihn niemand erneuern — dort liegt nur der Platzhalter, kein
Refresh-Token. Ein langer Sandbox-Lauf stirbt also mitten in der Arbeit.

```bash
matchlock run \
    --secret-from-file ANTHROPIC_AUTH_TOKEN=/pfad/zum/token@api.anthropic.com \
    ...
```

**Namenswahl:** Upstream hat inzwischen selbst ein `--secret-file` — das ist eine
JSON-Datei mit vollständigen Secret-Definitionen und etwas anderes. Deshalb heißt unser
Flag `--secret-from-file`.

| Datei | Änderung |
|---|---|
| `pkg/api/config.go` | `Secret.ValueFile` |
| `pkg/api/secret.go` | `ParseSecretFile()` — prüft Existenz und Nicht-Leere beim Start, damit ein Tippfehler sofort auffällt |
| `pkg/policy/engine.go` | `resolveValue()` — liest die Datei neu, sobald mtime oder Größe sich ändern (eigener Mutex, weil `OnRequest` bereits `e.mu` als RLock hält) |
| `cmd/matchlock/cmd_run.go` | Flag, Hilfetext, Einbau in `parseRunSecrets`, Kollisionsprüfung gegen `--secret` |

Verhalten in den Randfällen, bewusst so gewählt:

- Datei verschwindet oder wird unlesbar → der zuletzt gelesene Wert bleibt gültig. Ein
  kurzzeitig fehlender Pfad soll einen laufenden Agenten nicht abschiessen.
- Datei ist leer → es wird **nicht** ersetzt; der Platzhalter geht raus und holt sich ein
  401. Ein leeres Credential wäre stiller und schwerer zu finden.
- Trailing Whitespace wird abgeschnitten, damit eine per `echo` geschriebene Datei
  funktioniert.
- `ErrSecretLeak` greift unverändert: geht der Platzhalter an einen Host, für den das
  Secret nicht freigegeben ist, stirbt der Request.

---

## Patch 3: `--audit-db` und `--record`

Ohne Mitschrift ist nach dem Ende einer VM nicht mehr nachvollziehbar, wohin der Agent
gesprochen hat und was abgewiesen wurde.

- `--audit-db <datei>` schreibt jeden ausgehenden Request nach SQLite: `runs` (ein Lauf)
  und `requests` (Zeitpunkt, Methode, Host, URL, Status, Bytes, Dauer, blockiert samt
  Grund).
- `--record <datei.jsonl>` legt den vollständigen Austausch daneben, mit redigierten
  Secrets — zum Filtern, Auswerten und Wiederholen.

| Datei | Änderung |
|---|---|
| `pkg/audit/audit.go` | `Logger`, Schema, `Consume()` über den Ereignisstrom |
| `pkg/audit/record.go` | JSONL-Mitschnitt mit Redaktion |
| `cmd/matchlock/cmd_run.go` | Flags und Verdrahtung |

Ein Schreibfehler stört den Lauf nicht: das Audit ist Beobachtung, nicht Bedingung.

## Patch 4: Roh-TCP-Verbindungen im Audit

Patch 3 erfasst, was durch den MITM geht — also HTTP und HTTPS. Alles andere läuft über
den **Passthrough**: SSH, Datenbankports, was auch immer auf einem erlaubten Host lauscht.
Davon stand bisher nur im Protokoll, was die Allowlist *abgelehnt* hat. Eine erlaubte
Verbindung war hinterher unsichtbar — ein Bild, das ausgerechnet dann ruhig aussieht, wenn
es das nicht sein sollte.

Jetzt meldet der Passthrough jede Verbindung als `method = 'TCP'`:

```sql
select ts, host, request_bytes, response_bytes, duration_ms
  from requests where method = 'TCP' order by id desc;
-- 2026-09-16T11:27:40Z|192.0.0.2:2201|2427|3305|481
```

**Kein Inhalt.** Dieser Weg terminiert das Protokoll nicht und soll es auch nicht. Wissen
lässt sich, wer, wann, wie lange und wie viel — genau der Umfang der Allowlist-Entscheidung,
die eine Zeile darüber fällt. Scheitert der Verbindungsaufbau, steht der Grund in
`block_reason`, während `blocked` auf 0 bleibt: ein Netzfehler ist keine Ablehnung.

| Datei | Änderung |
|---|---|
| `pkg/net/stack_darwin.go` | `handlePassthrough` misst Zeit und Bytes, `emitPassthroughEvent`, `copyWithCancel` liefert die Menge zurück |
| `pkg/net/proxy.go` | dasselbe für den Linux-Pfad |

Eine Feinheit: nach dem Ende der einen Richtung sitzt die andere noch im `Read`. Ohne ein
gesetztes Deadline wäre die Byte-Zählung regelmäßig um den letzten Block zu kurz.

## Patch 5: Sperrgrund statt „Blocked by policy"

Eine Ablehnung im MITM hieß bisher immer `403` mit dem Text `Blocked by policy` — ob der
Host fehlte, ein Platzhalter an den falschen Host ging oder eine Regel griff, war von
innen nicht zu unterscheiden. Bei HTTPS mit nicht erlaubtem SNI kam nicht einmal das:
die Verbindung wurde nach dem Handshake wortlos geschlossen, im Gast ein
`connection reset`, nicht zu unterscheiden von einem Netzfehler. Ein Agent probiert dann
weiter, statt nach der richtigen Freigabe zu fragen.

Jetzt trägt jede Ablehnung ihren Grund, im Body und maschinenlesbar im Header:

```
HTTP/1.1 403 Forbidden
X-Matchlock-Blocked: host not in allowlist

matchlock: request to "evil.example" blocked by sandbox policy: host not in allowlist
```

Beim abgelehnten SNI liest der Proxy den ersten Request auf dem ohnehin schon
entschlüsselten Kanal (Deadline 5 s) und beantwortet ihn so. Sendet der Client nichts,
bleibt es beim Schließen.

Nicht erfasst: der Passthrough. Roh-TCP hat kein Protokoll, in das sich ein Grund
schreiben ließe; die Verbindung wird weiterhin geschlossen, der Grund steht im Audit.

Vorbild: `deniedDomainReasons` in Anthropics
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime).

| Datei | Änderung |
|---|---|
| `pkg/net/http.go` | `writeBlocked`, `answerBlockedTLS`; alle `403`-Stellen nutzen sie |
| `pkg/net/http_blocked_test.go` | HTTP- und SNI-Fall |

## Patch 6: Ports in der Allowlist, `--guard-resolved-ips`

Zwei Löcher, beide gemessen am 29.09.2026 aus der VM heraus:

**Die Allowlist kannte keine Ports.** `IsHostAllowed` schnitt alles ab dem ersten `:` ab.
Sandburg muss die LAN-IP des Hosts freigeben, damit Bastion und Bridges erreichbar sind —
und damit war *jeder* Dienst auf dieser IP offen. Ein beliebiger `http.server` auf
`0.0.0.0:18999` antwortete aus der VM mit `200`.

Jetzt darf ein Eintrag einen Port tragen: `--allow-host 192.168.2.102:2201` öffnet genau
diesen Port. Einträge ohne Port gelten wie bisher für jeden Port; IPv6 in eckigen Klammern
(`[2001:db8::1]:443`). Geprüft wird an allen vier Stellen — HTTP, HTTPS und beide
Passthrough-Pfade — über `IsEndpointAllowed(host, port)`.

**Ein erlaubter Name durfte überallhin zeigen.** Der MITM prüfte den Namen und wählte dann
den Namen; wohin er auflöste, entschied das DNS. Mit `--allow-private-ips` (Patch 1, für
Sandburg nötig) fiel auch der Rest-Schutz. Ein Gast konnte mit
`curl --resolve name:80:<beliebige IP> http://name/` jeden erlaubten Namen ansteuern, der
auf `127.0.0.1` zeigt, und landete auf dem Loopback des Hosts.

Mit `--guard-resolved-ips` löst der Proxy selbst auf, einmal, und verwirft Adressen der
Klassen Loopback, unspecified, Link-Local (inkl. `169.254.169.254`), Multicast, Broadcast,
weitere Cloud-Metadaten-Endpunkte und **die eigenen Interface-Adressen des Hosts**. Gewählt
wird genau die geprüfte Adresse, es gibt keinen zweiten Lookup; das TLS-Zertifikat wird
weiter gegen den Namen geprüft. Private Netze (10/8, 192.168/16, …) bleiben erlaubt: ein
Intranet-Name ist eine legitime Freigabe. Ausnahme: steht die Adresse selbst als Literal in
der Allowlist (mit passendem Port), ist sie erlaubt — über den Namen gewinnt man dann nichts,
was das Literal nicht schon gibt.

```
HTTP/1.1 403 Forbidden
X-Matchlock-Blocked: resolved address denied: localtest.me resolved to a loopback address
```

Default aus, das CLI-Verhalten bleibt abwärtskompatibel; Sandburg setzt den Flag immer.

Vorbild: der „Resolved-address check" in Anthropics
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime).

| Datei | Änderung |
|---|---|
| `pkg/policy/endpoint.go` | `splitPatternPort`, `IsEndpointAllowed`-Helfer, `DialAddress`, Adressklassen |
| `pkg/policy/engine.go` | `IsHostAllowed` versteht `host:port`, `IsEndpointAllowed` |
| `pkg/net/http.go` | Port-Prüfung, Wählen der geprüften Adresse, 403 bei verworfener Auflösung |
| `pkg/net/proxy.go`, `pkg/net/stack_darwin.go` | Port-Prüfung im Passthrough |
| `pkg/api/config.go`, `cmd/matchlock/cmd_run.go` | `GuardResolvedIPs`, `--guard-resolved-ips` |

## Installation

```bash
git clone https://github.com/sebastian-fahrenkrog/matchlock-fork.git matchlock
cd matchlock
git checkout patches-v2
go build -o ~/.local/bin/matchlock ./cmd/matchlock/

# Entitlement signieren, sonst darf das Binary keine VMs starten
codesign --force --sign - --entitlements matchlock.entitlements ~/.local/bin/matchlock

# guest-init passend zur Upstream-Version holen
gh release download v0.2.17 -R jingkaihe/matchlock -p "guest-init-linux-arm64"
install -m 755 guest-init-linux-arm64 ~/.local/bin/guest-init
```

`e2fsprogs` muss im PATH sein (`/opt/homebrew/opt/e2fsprogs/sbin`), sonst scheitert der
Image-Build an fehlendem `mke2fs`.

## Upstream nachziehen

```bash
git fetch origin
git rebase origin/main        # bei Konflikten: beide Seiten behalten, sie ergänzen sich
go test ./cmd/... ./pkg/...
```

Nach jedem Nachziehen die passende `guest-init`-Version mitnehmen — Host-Binary und
Guest-Init müssen zusammenpassen.
