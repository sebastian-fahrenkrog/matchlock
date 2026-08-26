// Package audit schreibt die Ereignisse einer Sandbox in eine SQLite-Datei.
//
// Der MITM-Proxy sieht ohnehin jeden ausgehenden Request. Ohne Mitschrift ist
// diese Sicht nach dem Ende der VM verloren — man weiss hinterher nicht, wohin
// ein Agent gesprochen hat, wie oft, mit welchem Ergebnis, und was die Policy
// abgewiesen hat. Genau das beantwortet diese Tabelle.
//
// Bewusst nicht mitgeschrieben werden Header und Bodies: dort stehen die
// Credentials, die die Sandbox gar nicht erst sehen soll, und der Mitschnitt
// wäre die Stelle, an der sie doch auf der Platte landen.
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jingkaihe/matchlock/pkg/api"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id          TEXT    NOT NULL,
    ts             TEXT    NOT NULL,
    method         TEXT,
    host           TEXT,
    url            TEXT,
    status_code    INTEGER,
    request_bytes  INTEGER,
    response_bytes INTEGER,
    duration_ms    INTEGER,
    blocked        INTEGER NOT NULL DEFAULT 0,
    block_reason   TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_vm   ON requests(vm_id, ts);
CREATE INDEX IF NOT EXISTS idx_requests_host ON requests(host);
CREATE INDEX IF NOT EXISTS idx_requests_blk  ON requests(blocked) WHERE blocked = 1;

CREATE TABLE IF NOT EXISTS runs (
    vm_id      TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    image      TEXT,
    workspace  TEXT,
    command    TEXT
);
`

// Logger schreibt Ereignisse in die Datenbank. Alle Methoden sind
// nebenläufigkeitssicher.
type Logger struct {
	db   *sql.DB
	vmID string

	mu     sync.Mutex
	closed bool
}

// Open legt die Datenbank an, falls nötig, und vermerkt den Start des Laufs.
func Open(path, vmID, image, workspace, command string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	// WAL, damit ein zweites Fenster mitlesen kann, während eine VM schreibt.
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit pragma: %w", err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit schema: %w", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit perms: %w", err)
	}

	l := &Logger{db: db, vmID: vmID}
	if _, err := db.Exec(
		`INSERT OR REPLACE INTO runs (vm_id, started_at, image, workspace, command) VALUES (?,?,?,?,?)`,
		vmID, now(), image, workspace, command,
	); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit run: %w", err)
	}
	return l, nil
}

// Consume liest den Ereignisstrom der Sandbox, bis er schliesst oder der
// Kontext endet. Blockiert; für den Aufruf in einer eigenen Goroutine gedacht.
func (l *Logger) Consume(ctx context.Context, events <-chan api.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if event.Network != nil {
				l.logNetwork(event.Network)
			}
		}
	}
}

func (l *Logger) logNetwork(e *api.NetworkEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}

	blocked := 0
	if e.Blocked {
		blocked = 1
	}
	// Ein Fehler beim Schreiben darf den Lauf nicht stören — das Audit ist
	// Beobachtung, nicht Bedingung.
	_, _ = l.db.Exec(
		`INSERT INTO requests
		   (vm_id, ts, method, host, url, status_code, request_bytes, response_bytes, duration_ms, blocked, block_reason)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		l.vmID, now(), e.Method, e.Host, e.URL, e.StatusCode,
		e.RequestBytes, e.ResponseBytes, e.DurationMS, blocked, e.BlockReason,
	)
}

// Close vermerkt das Ende des Laufs und schliesst die Datenbank.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true

	_, _ = l.db.Exec(`UPDATE runs SET ended_at = ? WHERE vm_id = ?`, now(), l.vmID)
	return l.db.Close()
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
