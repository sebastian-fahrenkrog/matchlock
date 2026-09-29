package net

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/audit"
	"github.com/jingkaihe/matchlock/pkg/policy"
)

type HTTPInterceptor struct {
	policy   *policy.Engine
	events   chan api.Event
	caPool   *CAPool
	connPool *upstreamConnPool
	recorder *audit.Recorder
}

// SetRecorder schaltet den vollständigen Mitschnitt ein. Aufzeichnet wird der
// Request, wie der Gast ihn gesendet hat — also mit Platzhaltern statt echter
// Credentials, weil die Substitution erst danach greift.
func (i *HTTPInterceptor) SetRecorder(r *audit.Recorder) {
	i.recorder = r
	if r != nil && i.policy != nil {
		r.SetRedactor(i.policy.Redact)
	}
}

func NewHTTPInterceptor(pol *policy.Engine, events chan api.Event, caPool *CAPool) *HTTPInterceptor {
	return &HTTPInterceptor{
		policy:   pol,
		events:   events,
		caPool:   caPool,
		connPool: newUpstreamConnPool(),
	}
}

func (i *HTTPInterceptor) HandleHTTP(guestConn net.Conn, dstIP string, dstPort int) {
	defer guestConn.Close()

	guestReader := bufio.NewReader(guestConn)

	for {
		req, err := http.ReadRequest(guestReader)
		if err != nil {
			return
		}

		start := time.Now()

		host := req.Host
		if host == "" {
			host = dstIP
		}

		hostOnly := stripPort(host)
		if !i.policy.IsEndpointAllowed(hostOnly, dstPort) {
			i.emitBlockedEvent(req, host, "host not in allowlist")
			i.writeRecord(audit.Blocked(i.record(req, host), "host not in allowlist"))
			writeBlocked(guestConn, host, "host not in allowlist")
			return
		}

		exchange := i.record(req, host)

		modifiedReq, err := i.policy.OnRequest(req, host)
		if err != nil {
			i.emitBlockedEvent(req, host, err.Error())
			i.writeRecord(audit.Blocked(exchange, err.Error()))
			writeBlocked(guestConn, host, err.Error())
			return
		}

		targetHost := net.JoinHostPort(host, fmt.Sprintf("%d", dstPort))

		// Try to reuse an existing upstream connection from the pool.
		pc := i.connPool.get(targetHost)
		if pc == nil {
			dialAddr, err := i.policy.DialAddress(context.Background(), hostOnly, dstPort)
			if err != nil {
				i.refuseResolved(guestConn, exchange, modifiedReq, host, err)
				return
			}
			realConn, err := net.DialTimeout("tcp", dialAddr, 30*time.Second)
			if err != nil {
				writeHTTPError(guestConn, http.StatusBadGateway, "Failed to connect")
				return
			}
			pc = &pooledConn{
				conn:   realConn,
				reader: bufio.NewReader(realConn),
			}
		}

		if err := modifiedReq.Write(pc.conn); err != nil {
			pc.conn.Close()
			writeHTTPError(guestConn, http.StatusBadGateway, "Failed to write request")
			return
		}

		resp, err := http.ReadResponse(pc.reader, modifiedReq)
		if err != nil {
			pc.conn.Close()
			return
		}

		modifiedResp, err := i.policy.OnResponse(resp, modifiedReq, host)
		if err != nil {
			i.emitBlockedEvent(modifiedReq, host, err.Error())
			writeBlocked(guestConn, host, err.Error())
			resp.Body.Close()
			pc.conn.Close()
			return
		}

		if isStreamingResponse(modifiedResp) {
			audit.CaptureResponse(exchange, modifiedResp, true, time.Since(start))
			i.writeRecord(exchange)
			i.emitEvent(modifiedReq, modifiedResp, host, time.Since(start))
			err := writeResponseHeadersAndStreamBody(guestConn, modifiedResp)
			resp.Body.Close()
			pc.conn.Close()
			if err != nil {
				return
			}
			return
		}

		duration := time.Since(start)
		audit.CaptureResponse(exchange, modifiedResp, false, duration)
		i.writeRecord(exchange)
		i.emitEvent(modifiedReq, modifiedResp, host, duration)

		if err := writeResponse(guestConn, modifiedResp); err != nil {
			resp.Body.Close()
			pc.conn.Close()
			return
		}

		resp.Body.Close()

		// Return the connection to the pool if neither side requested close.
		if modifiedReq.Close || modifiedResp.Close {
			pc.conn.Close()
		} else {
			i.connPool.put(targetHost, pc)
		}

		if modifiedReq.Close || modifiedResp.Close {
			return
		}
	}
}

func (i *HTTPInterceptor) HandleHTTPS(guestConn net.Conn, dstIP string, dstPort int) {
	defer guestConn.Close()

	tlsConn := tls.Server(guestConn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return i.caPool.GetCertificate(hello.ServerName)
		},
		InsecureSkipVerify: true,
	})

	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	serverName := tlsConn.ConnectionState().ServerName
	if serverName == "" {
		serverName = dstIP
	}

	if !i.policy.IsEndpointAllowed(serverName, dstPort) {
		i.emitBlockedEvent(nil, serverName, "host not in allowlist")
		i.writeRecord(audit.Blocked(&audit.Exchange{Host: serverName}, "host not in allowlist"))
		answerBlockedTLS(tlsConn, serverName, "host not in allowlist")
		return
	}

	dialAddr, err := i.policy.DialAddress(context.Background(), serverName, dstPort)
	if err != nil {
		if errors.Is(err, policy.ErrResolvedAddressDenied) {
			i.emitBlockedEvent(nil, serverName, err.Error())
			i.writeRecord(audit.Blocked(&audit.Exchange{Host: serverName}, err.Error()))
			answerBlockedTLS(tlsConn, serverName, err.Error())
		}
		return
	}

	// Dial the checked address; the certificate is still verified against
	// the name the guest asked for.
	realConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", dialAddr, &tls.Config{
		ServerName: serverName,
	})
	if err != nil {
		return
	}
	defer realConn.Close()

	guestReader := bufio.NewReader(tlsConn)
	serverReader := bufio.NewReader(realConn)

	for {
		req, err := http.ReadRequest(guestReader)
		if err != nil {
			return
		}

		start := time.Now()

		// Vor der Substitution mitschneiden: im Log stehen dann Platzhalter.
		exchange := i.record(req, serverName)

		modifiedReq, err := i.policy.OnRequest(req, serverName)
		if err != nil {
			i.emitBlockedEvent(req, serverName, err.Error())
			i.writeRecord(audit.Blocked(exchange, err.Error()))
			writeBlocked(tlsConn, serverName, err.Error())
			return
		}

		if err := modifiedReq.Write(realConn); err != nil {
			return
		}

		resp, err := http.ReadResponse(serverReader, modifiedReq)
		if err != nil {
			return
		}

		modifiedResp, err := i.policy.OnResponse(resp, modifiedReq, serverName)
		if err != nil {
			i.emitBlockedEvent(modifiedReq, serverName, err.Error())
			writeBlocked(tlsConn, serverName, err.Error())
			resp.Body.Close()
			return
		}

		if isStreamingResponse(modifiedResp) {
			audit.CaptureResponse(exchange, modifiedResp, true, time.Since(start))
			i.writeRecord(exchange)
			i.emitEvent(modifiedReq, modifiedResp, serverName, time.Since(start))
			if err := writeResponseHeadersAndStreamBody(tlsConn, modifiedResp); err != nil {
				resp.Body.Close()
				return
			}
			resp.Body.Close()
			return
		}

		duration := time.Since(start)
		audit.CaptureResponse(exchange, modifiedResp, false, duration)
		i.writeRecord(exchange)
		i.emitEvent(modifiedReq, modifiedResp, serverName, duration)

		if err := writeResponse(tlsConn, modifiedResp); err != nil {
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		if modifiedReq.Close || modifiedResp.Close {
			return
		}
	}
}

func (i *HTTPInterceptor) emitEvent(req *http.Request, resp *http.Response, host string, duration time.Duration) {
	if i.events == nil {
		return
	}

	var reqBytes, respBytes int64
	if req.ContentLength > 0 {
		reqBytes = req.ContentLength
	}
	if resp.ContentLength > 0 {
		respBytes = resp.ContentLength
	}

	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	select {
	case i.events <- api.Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Network: &api.NetworkEvent{
			Method:        req.Method,
			URL:           fmt.Sprintf("%s://%s%s", scheme, host, req.URL.Path),
			Host:          host,
			StatusCode:    resp.StatusCode,
			RequestBytes:  reqBytes,
			ResponseBytes: respBytes,
			DurationMS:    duration.Milliseconds(),
			Blocked:       false,
		},
	}:
	default:
	}
}

func (i *HTTPInterceptor) emitBlockedEvent(req *http.Request, host, reason string) {
	if i.events == nil {
		return
	}

	event := api.Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Network: &api.NetworkEvent{
			Host:        host,
			Blocked:     true,
			BlockReason: reason,
		},
	}

	if req != nil {
		event.Network.Method = req.Method
		event.Network.URL = req.URL.String()
	}

	select {
	case i.events <- event:
	default:
	}
}

func (i *HTTPInterceptor) record(req *http.Request, host string) *audit.Exchange {
	if i.recorder == nil {
		return nil
	}
	return audit.CaptureRequest(req, host)
}

func (i *HTTPInterceptor) writeRecord(ex *audit.Exchange) {
	if i.recorder == nil || ex == nil {
		return
	}
	i.recorder.Write(ex)
}

// refuseResolved answers a failed DialAddress on the plain HTTP path: a denied
// resolution is a policy refusal and says so, anything else is a gateway error.
func (i *HTTPInterceptor) refuseResolved(guestConn net.Conn, exchange *audit.Exchange, req *http.Request, host string, err error) {
	if !errors.Is(err, policy.ErrResolvedAddressDenied) {
		writeHTTPError(guestConn, http.StatusBadGateway, "Failed to connect")
		return
	}
	i.emitBlockedEvent(req, host, err.Error())
	i.writeRecord(audit.Blocked(exchange, err.Error()))
	writeBlocked(guestConn, host, err.Error())
}

// stripPort drops a ":port" suffix from a Host header value.
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// blockedHeader carries the reason for a policy refusal in machine-readable form.
const blockedHeader = "X-Matchlock-Blocked"

// writeBlocked answers a refused request with 403 and says why.
//
// A bare "Blocked by policy" leaves an agent inside the sandbox guessing: it
// cannot tell a missing allowlist entry from a secret sent to the wrong host
// or a server-side error, and tends to retry or to probe other routes. The
// reason in the body and in a header lets it stop and ask for the right change
// instead.
func writeBlocked(conn net.Conn, host, reason string) {
	body := fmt.Sprintf("matchlock: request to %q blocked by sandbox policy: %s\n", host, reason)
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n%s: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		http.StatusForbidden, http.StatusText(http.StatusForbidden), blockedHeader, reason, len(body), body)
	io.WriteString(conn, resp)
}

// answerBlockedTLS turns a refusal after the TLS handshake into a readable 403.
//
// The SNI check runs once the handshake with the guest has completed, so the
// channel is already decrypted. Closing it silently shows up inside the VM as
// "connection reset" or "empty reply", indistinguishable from a network fault.
// Reading the first request and answering it costs one round trip and tells
// the client what happened. A client that sends nothing within the deadline
// gets the plain close as before.
func answerBlockedTLS(tlsConn *tls.Conn, host, reason string) {
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := http.ReadRequest(bufio.NewReader(tlsConn)); err != nil {
		return
	}
	writeBlocked(tlsConn, host, reason)
}

func writeHTTPError(conn net.Conn, status int, message string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(message), message)
	io.WriteString(conn, resp)
}

func writeResponse(conn net.Conn, resp *http.Response) error {
	bw := bufio.NewWriterSize(conn, 64*1024)
	if err := resp.Write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

func isStreamingResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		return true
	}
	for _, te := range resp.TransferEncoding {
		if te == "chunked" {
			return true
		}
	}
	if resp.ContentLength == -1 && resp.ProtoMajor == 1 && resp.ProtoMinor == 1 {
		return true
	}
	return false
}

func writeResponseHeadersAndStreamBody(conn net.Conn, resp *http.Response) error {
	bw := bufio.NewWriterSize(conn, 4*1024)

	statusLine := fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))
	if _, err := bw.WriteString(statusLine); err != nil {
		return err
	}

	if err := resp.Header.Write(bw); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	buf := make([]byte, 4*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
