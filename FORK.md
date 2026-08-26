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
