package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxBodyBytes begrenzt, wieviel von einem Body mitgeschrieben wird. Ein
// Mitschnitt soll nachvollziehbar machen, was gesendet wurde, und nicht die
// Platte füllen; alles darüber wird abgeschnitten und als solches markiert.
const MaxBodyBytes = 256 * 1024

// Exchange ist ein aufgezeichneter Request samt Antwort. Eine Zeile JSON je
// Austausch (JSONL): mit jq filterbar, mit wenigen Zeilen in HAR oder curl
// übersetzbar, und vollständig genug zum Wiederholen.
type Exchange struct {
	Timestamp string `json:"ts"`
	VMID      string `json:"vm_id,omitempty"`
	Host      string `json:"host"`

	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Proto   string              `json:"proto,omitempty"`
	ReqHead map[string][]string `json:"request_headers,omitempty"`
	ReqBody string              `json:"request_body,omitempty"`
	ReqCut  bool                `json:"request_body_truncated,omitempty"`

	Status   int                 `json:"status,omitempty"`
	RespHead map[string][]string `json:"response_headers,omitempty"`
	RespBody string              `json:"response_body,omitempty"`
	RespCut  bool                `json:"response_body_truncated,omitempty"`
	Streamed bool                `json:"streamed,omitempty"`

	DurationMS  int64  `json:"duration_ms,omitempty"`
	Blocked     bool   `json:"blocked,omitempty"`
	BlockReason string `json:"block_reason,omitempty"`
}

// Recorder schreibt Austausche als JSONL. Nebenläufigkeitssicher.
type Recorder struct {
	mu     sync.Mutex
	file   *os.File
	enc    *json.Encoder
	vmID   string
	redact func(string) string
}

// SetRedactor hinterlegt eine Funktion, die echte Secret-Werte durch ihre
// Platzhalter ersetzt. Sie läuft über jeden Header und jeden Body, bevor
// geschrieben wird — Antworten spiegeln gesendete Header gern zurück.
func (r *Recorder) SetRedactor(f func(string) string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.redact = f
}

// NewRecorder legt die Datei an (Modus 600) und hängt an eine bestehende an.
func NewRecorder(path, vmID string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Recorder{file: f, enc: json.NewEncoder(f), vmID: vmID}, nil
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Close()
}

// Write hält einen Austausch fest. Fehler beim Schreiben werden geschluckt —
// der Mitschnitt ist Beobachtung, nicht Bedingung für den Lauf.
func (r *Recorder) Write(ex *Exchange) {
	if r == nil || ex == nil {
		return
	}
	ex.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	ex.VMID = r.vmID

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.redact != nil {
		ex.ReqBody = r.redact(ex.ReqBody)
		ex.RespBody = r.redact(ex.RespBody)
		redactHeaders(ex.ReqHead, r.redact)
		redactHeaders(ex.RespHead, r.redact)
	}
	_ = r.enc.Encode(ex)
}

// CaptureRequest hält Methode, URL, Header und Body fest.
//
// WICHTIG: Der Aufruf gehört VOR die Secret-Substitution. Dann stehen im
// Mitschnitt die Platzhalter und nicht die echten Credentials — der Mitschnitt
// wäre sonst genau die Stelle, an der die Geheimnisse doch auf der Platte
// landen, die die Sandbox nie sehen sollte.
func CaptureRequest(req *http.Request, host string) *Exchange {
	if req == nil {
		return nil
	}

	ex := &Exchange{
		Host:    host,
		Method:  req.Method,
		Proto:   req.Proto,
		ReqHead: cloneHeader(req.Header),
	}
	if req.URL != nil {
		url := *req.URL
		if url.Host == "" {
			url.Host = host
		}
		if url.Scheme == "" {
			url.Scheme = "https"
		}
		ex.URL = url.String()
	}

	body, cut, restored := captureBody(req.Body)
	req.Body = restored
	ex.ReqBody, ex.ReqCut = body, cut
	return ex
}

// CaptureResponse ergänzt Status, Header und Body. Gestreamte Antworten werden
// nur vermerkt, nicht mitgelesen: sie würden den Mitschnitt sprengen und das
// Weiterreichen an den Gast verzögern.
func CaptureResponse(ex *Exchange, resp *http.Response, streamed bool, took time.Duration) {
	if ex == nil || resp == nil {
		return
	}
	ex.Status = resp.StatusCode
	ex.RespHead = cloneHeader(resp.Header)
	ex.DurationMS = took.Milliseconds()
	ex.Streamed = streamed

	if streamed {
		return
	}
	body, cut, restored := captureBody(resp.Body)
	resp.Body = restored
	ex.RespBody, ex.RespCut = body, cut
}

// captureBody liest bis zur Obergrenze und gibt einen Reader zurück, aus dem
// derselbe Inhalt erneut gelesen werden kann — der Aufrufer braucht ihn ja noch.
func captureBody(body io.ReadCloser) (string, bool, io.ReadCloser) {
	if body == nil {
		return "", false, nil
	}
	defer body.Close()

	limited := io.LimitReader(body, MaxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", false, io.NopCloser(bytes.NewReader(data))
	}

	truncated := len(data) > MaxBodyBytes
	rest := data
	if truncated {
		// Der Rest muss trotzdem weitergereicht werden, sonst wäre der Request
		// unvollständig — nur der Mitschnitt wird gekürzt.
		more, _ := io.ReadAll(body)
		rest = append(data, more...)
		data = data[:MaxBodyBytes]
	}
	return string(data), truncated, io.NopCloser(bytes.NewReader(rest))
}

func redactHeaders(h map[string][]string, redact func(string) string) {
	for key, values := range h {
		for i, v := range values {
			h[key][i] = redact(v)
		}
	}
}

func cloneHeader(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		// Cookies stehen bewusst mit drin: für Replay und Fehlersuche zählt,
		// was tatsächlich gesendet wurde. Credentials sind hier ohnehin nur
		// Platzhalter, siehe CaptureRequest.
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Blocked hält einen abgewiesenen Request fest.
func Blocked(ex *Exchange, reason string) *Exchange {
	if ex == nil {
		ex = &Exchange{}
	}
	ex.Blocked = true
	ex.BlockReason = strings.TrimSpace(reason)
	return ex
}
