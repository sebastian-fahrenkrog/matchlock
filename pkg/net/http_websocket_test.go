package net

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wsUpgradeAccept = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"

// wsUpstream starts a minimal upstream on 127.0.0.1. It reads the HTTP request,
// hands it to onRequest, then runs reply(conn) to play the server side. The
// returned port is the destination the interceptor dials.
func wsUpstream(t *testing.T, onRequest func(*http.Request), reply func(conn net.Conn, buffered *bufio.Reader)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if onRequest != nil {
			onRequest(req)
		}
		reply(conn, br)
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// dialWSUpgrade runs HandleHTTP against a piped guest connection and sends a
// WebSocket upgrade request, returning the guest end of the pipe.
func dialWSUpgrade(t *testing.T, i *HTTPInterceptor, port int, extraHeaders string) net.Conn {
	t.Helper()
	guest, proxySide := net.Pipe()
	t.Cleanup(func() { guest.Close() })
	go i.HandleHTTP(proxySide, "127.0.0.1", port)

	guest.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := io.WriteString(guest,
		"GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
			extraHeaders+"\r\n")
	require.NoError(t, err)
	return guest
}

func allowLocalhostEngine() *policy.Engine {
	return policy.NewEngine(&api.NetworkConfig{AllowedHosts: []string{"127.0.0.1"}})
}

// TestWebSocket_EchoBothDirections covers the server sending first (a greeting
// buffered during the handshake read) and the guest sending after (echoed back).
func TestWebSocket_EchoBothDirections(t *testing.T) {
	port := wsUpstream(t, nil, func(conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, wsUpgradeAccept)
		io.WriteString(conn, "hello") // server speaks first
		io.Copy(conn, br)             // then echo
	})
	interceptor := NewHTTPInterceptor(allowLocalhostEngine(), nil, nil)

	guest := dialWSUpgrade(t, interceptor, port, "")

	// Read the handshake and all tunnel bytes through one reader so nothing
	// buffered past the 101 is lost.
	br := bufio.NewReader(guest)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	// Server-initiated bytes (upstream -> guest).
	greeting := make([]byte, 5)
	_, err = io.ReadFull(br, greeting)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(greeting))

	// Guest-initiated bytes echoed back (guest -> upstream -> guest).
	_, err = io.WriteString(guest, "ping")
	require.NoError(t, err)
	echoed := make([]byte, 4)
	_, err = io.ReadFull(br, echoed)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(echoed))
}

// TestWebSocket_SecretReplacedInUpgradeHeader verifies the placeholder in the
// upgrade request's header reaches the upstream as the real value.
func TestWebSocket_SecretReplacedInUpgradeHeader(t *testing.T) {
	gotAuth := make(chan string, 1)
	port := wsUpstream(t, func(req *http.Request) {
		gotAuth <- req.Header.Get("Authorization")
	}, func(conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, wsUpgradeAccept)
		io.Copy(conn, br)
	})

	engine := policy.NewEngine(&api.NetworkConfig{
		AllowedHosts: []string{"127.0.0.1"},
		Secrets: map[string]api.Secret{
			"TOKEN": {Value: "real-secret-value", Placeholder: "PLACEHOLDER_TOKEN", Hosts: []string{"127.0.0.1"}},
		},
	})
	interceptor := NewHTTPInterceptor(engine, nil, nil)

	guest := dialWSUpgrade(t, interceptor, port, "Authorization: Bearer PLACEHOLDER_TOKEN\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(guest), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	select {
	case auth := <-gotAuth:
		assert.Equal(t, "Bearer real-secret-value", auth)
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the upgrade request")
	}
}

// TestWebSocket_BlockedByPolicy: an upgrade to a disallowed host is refused like
// any request, with a reason, and never reaches a tunnel.
func TestWebSocket_BlockedByPolicy(t *testing.T) {
	engine := policy.NewEngine(&api.NetworkConfig{AllowedHosts: []string{"allowed.example"}})
	interceptor := NewHTTPInterceptor(engine, nil, nil)

	guest, proxySide := net.Pipe()
	defer guest.Close()
	go interceptor.HandleHTTP(proxySide, "203.0.113.7", 80)

	guest.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := io.WriteString(guest,
		"GET /chat HTTP/1.1\r\nHost: evil.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(guest), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "host not in allowlist", resp.Header.Get(blockedHeader))
}

// TestWebSocket_UpstreamDeclines: without a 101 the exchange stays an ordinary
// request/response and no tunnel is established.
func TestWebSocket_UpstreamDeclines(t *testing.T) {
	port := wsUpstream(t, nil, func(conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
	})
	interceptor := NewHTTPInterceptor(allowLocalhostEngine(), nil, nil)

	guest := dialWSUpgrade(t, interceptor, port, "")

	resp, err := http.ReadResponse(bufio.NewReader(guest), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "no", string(body))
}

// TestWebSocket_GuestCloseTearsDownUpstream: closing the guest end ends the
// upstream side of the tunnel too.
func TestWebSocket_GuestCloseTearsDownUpstream(t *testing.T) {
	upstreamClosed := make(chan struct{})
	port := wsUpstream(t, nil, func(conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, wsUpgradeAccept)
		io.Copy(conn, br) // returns when the interceptor closes the upstream conn
		close(upstreamClosed)
	})
	interceptor := NewHTTPInterceptor(allowLocalhostEngine(), nil, nil)

	guest := dialWSUpgrade(t, interceptor, port, "")
	resp, err := http.ReadResponse(bufio.NewReader(guest), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	guest.Close()

	select {
	case <-upstreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not torn down after the guest closed")
	}
}

// readWSEvent pulls the next network event off the channel, failing the test on
// timeout.
func readWSEvent(t *testing.T, events <-chan api.Event) *api.NetworkEvent {
	t.Helper()
	select {
	case ev := <-events:
		require.NotNil(t, ev.Network)
		return ev.Network
	case <-time.After(5 * time.Second):
		t.Fatal("no audit event for the WebSocket connection")
		return nil
	}
}

// TestWebSocket_AuditEntryOnOpen: the connection is audited the moment the 101
// is relayed, before any frame is exchanged and before either side closes. An
// RC WebSocket stays open for the whole session, so the entry must not wait for
// the close -- otherwise a still-open or VM-terminated tunnel leaves no trace.
func TestWebSocket_AuditEntryOnOpen(t *testing.T) {
	events := make(chan api.Event, 4)
	// Upstream accepts the upgrade and then holds the connection open, never
	// closing, so any audit entry we see can only be the open-time one.
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	port := wsUpstream(t, nil, func(conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, wsUpgradeAccept)
		<-hold
	})
	interceptor := NewHTTPInterceptor(allowLocalhostEngine(), events, nil)

	guest := dialWSUpgrade(t, interceptor, port, "")
	resp, err := http.ReadResponse(bufio.NewReader(guest), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	ev := readWSEvent(t, events)
	assert.Equal(t, "WS", ev.Method)
	assert.Equal(t, http.StatusSwitchingProtocols, ev.StatusCode)
	assert.Equal(t, "127.0.0.1", ev.Host)
	assert.Contains(t, ev.URL, "/chat")
	assert.False(t, ev.Blocked)
	assert.Equal(t, int64(0), ev.RequestBytes, "open entry carries no bytes yet")
	assert.Equal(t, int64(0), ev.ResponseBytes, "open entry carries no bytes yet")
}

// TestWebSocket_AuditEntrySecure drives tunnelWebSocket on the secure path
// (secure=true) the way HandleHTTPS and the darwin stack's port-443 route do.
// A full TLS end-to-end run is not reproducible under Linux -- the upstream dial
// verifies against the system roots -- so this covers the shared relay directly:
// the open and close entries must use the wss:// scheme.
func TestWebSocket_AuditEntrySecure(t *testing.T) {
	events := make(chan api.Event, 4)
	interceptor := NewHTTPInterceptor(allowLocalhostEngine(), events, nil)

	guestConn, guestClient := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	t.Cleanup(func() { guestClient.Close(); upstreamPeer.Close() })
	// Drain anything the relay forwards upstream so its io.Copy never blocks on
	// the synchronous pipe.
	go io.Copy(io.Discard, upstreamPeer)

	req, err := http.NewRequest(http.MethodGet, "https://bridge.example/chat", nil)
	require.NoError(t, err)
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}},
	}

	go interceptor.tunnelWebSocket(guestConn, bufio.NewReader(guestConn),
		upstreamConn, bufio.NewReader(upstreamConn), resp, nil,
		"bridge.example", req, true, time.Now())

	head, err := http.ReadResponse(bufio.NewReader(guestClient), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, head.StatusCode)

	open := readWSEvent(t, events)
	assert.Equal(t, "WS", open.Method)
	assert.Equal(t, "bridge.example", open.Host)
	assert.Equal(t, "wss://bridge.example/chat", open.URL)
	assert.Equal(t, int64(0), open.RequestBytes)
	assert.Equal(t, int64(0), open.ResponseBytes)

	// Closing the guest end ends the tunnel; the close entry keeps the scheme.
	guestClient.Close()
	closed := readWSEvent(t, events)
	assert.Equal(t, "WS", closed.Method)
	assert.Equal(t, "wss://bridge.example/chat", closed.URL)
}

// TestWebSocket_AuditEntry: a WebSocket connection produces an open entry (no
// bytes) and, once it closes, a second entry with the byte counts per direction.
func TestWebSocket_AuditEntry(t *testing.T) {
	events := make(chan api.Event, 4)
	port := wsUpstream(t, nil, func(conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, wsUpgradeAccept)
		io.Copy(conn, br)
	})
	interceptor := NewHTTPInterceptor(allowLocalhostEngine(), events, nil)

	guest := dialWSUpgrade(t, interceptor, port, "")
	br := bufio.NewReader(guest)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	// First event: the open entry, before any bytes flow.
	open := readWSEvent(t, events)
	assert.Equal(t, "WS", open.Method)
	assert.Equal(t, http.StatusSwitchingProtocols, open.StatusCode)
	assert.Equal(t, int64(0), open.RequestBytes)
	assert.Equal(t, int64(0), open.ResponseBytes)

	_, err = io.WriteString(guest, "ping")
	require.NoError(t, err)
	echoed := make([]byte, 4)
	_, err = io.ReadFull(br, echoed)
	require.NoError(t, err)

	guest.Close()

	// Second event: the close entry, carrying the byte counts.
	closed := readWSEvent(t, events)
	assert.Equal(t, "WS", closed.Method)
	assert.Equal(t, http.StatusSwitchingProtocols, closed.StatusCode)
	assert.Equal(t, "127.0.0.1", closed.Host)
	assert.Contains(t, closed.URL, "/chat")
	assert.GreaterOrEqual(t, closed.RequestBytes, int64(4))
	assert.False(t, closed.Blocked)
}
