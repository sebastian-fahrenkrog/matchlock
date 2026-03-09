# Fork: allow-private-ips

Dieser Fork ergänzt den `--allow-private-ips` CLI-Flag für `matchlock run`.

## Problem

`BlockPrivateIPs` ist im CLI auf `true` hardcoded (`cmd_run.go:330`). Das blockiert alle Verbindungen zu privaten IP-Bereichen (10/8, 172.16/12, 192.168/16) — auch wenn die IP explizit in `--allow-host` steht.

Das verhindert Use Cases wie SSH-Agent-Forwarding via socat, bei denen die Guest-VM eine TCP-Verbindung zur privaten Host-IP aufbauen muss.

## Fix

```diff
- BlockPrivateIPs: true,
+ BlockPrivateIPs: !allowPrivateIPs,
```

Neuer Flag: `--allow-private-ips` (default: `false`, Verhalten bleibt abwärtskompatibel).

## Zweites Problem: Hostname vs. IP im Passthrough-Proxy

Der gVisor-Passthrough-Proxy (für nicht-HTTP-Ports wie 22/SSH) prüft `IsHostAllowed()` mit der aufgelösten IP-Adresse. Die Allowlist enthält aber Hostnamen. Da `matchGlob("example.com", "93.184.216.34")` immer `false` ergibt, werden SSH-Verbindungen blockiert, obwohl der Host erlaubt ist.

**Workaround:** Hostname UND aufgelöste IP in `--allow-host` angeben:

```bash
matchlock run \
    --allow-host m.dev.testserver.online \
    --allow-host 116.203.243.212 \
    ...
```

Dieser Bug ist nicht in diesem Fork gefixt, da er eine grössere Änderung am DNS/Policy-Layer erfordert (z.B. DNS-Response-Caching mit Reverse-Lookup).

## Installation

```bash
git clone https://github.com/sebastian-fahrenkrog/matchlock.git
cd matchlock
git checkout allow-private-ips
go build -o ~/.local/bin/matchlock ./cmd/matchlock/

# Entitlement signieren (macOS)
codesign --force --sign - --entitlements entitlements.plist ~/.local/bin/matchlock
```

## Upstream

- Repo: https://github.com/jingkaihe/matchlock
- Basis: v0.2.1 (`1fdbd1a`)
