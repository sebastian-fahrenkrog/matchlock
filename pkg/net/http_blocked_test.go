package net

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
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

func TestHandleHTTP_BlockedCarriesReason(t *testing.T) {
	engine := policy.NewEngine(&api.NetworkConfig{AllowedHosts: []string{"allowed.example"}})
	interceptor := NewHTTPInterceptor(engine, nil, nil)

	guest, proxySide := net.Pipe()
	defer guest.Close()
	go interceptor.HandleHTTP(proxySide, "203.0.113.7", 80)

	guest.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := io.WriteString(guest, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(guest), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "host not in allowlist", resp.Header.Get(blockedHeader))
	assert.Contains(t, string(body), `"evil.example"`)
	assert.Contains(t, string(body), "host not in allowlist")
}

func TestHandleHTTPS_BlockedSNIAnswersInsteadOfClosing(t *testing.T) {
	pool, err := NewCAPool()
	require.NoError(t, err)
	engine := policy.NewEngine(&api.NetworkConfig{AllowedHosts: []string{"allowed.example"}})
	interceptor := NewHTTPInterceptor(engine, nil, pool)

	guest, proxySide := net.Pipe()
	defer guest.Close()
	go interceptor.HandleHTTPS(proxySide, "203.0.113.7", 443)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pool.CACertPEM())
	client := tls.Client(guest, &tls.Config{ServerName: "evil.example", RootCAs: roots})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, client.Handshake())

	_, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err, "a refused SNI should get an HTTP answer, not a bare close")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "host not in allowlist", resp.Header.Get(blockedHeader))
}
