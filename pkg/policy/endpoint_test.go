package policy

import (
	"context"
	"net"
	"testing"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitPatternPort(t *testing.T) {
	tests := []struct {
		entry string
		host  string
		port  int
	}{
		{"api.example.com", "api.example.com", 0},
		{"api.example.com:443", "api.example.com", 443},
		{"*.example.com:8443", "*.example.com", 8443},
		{"10.0.0.5", "10.0.0.5", 0},
		{"10.0.0.5:2201", "10.0.0.5", 2201},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"2001:db8::1", "2001:db8::1", 0},
		{"host:notaport", "host:notaport", 0},
		{"host:70000", "host:70000", 0},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			host, port := splitPatternPort(tt.entry)
			assert.Equal(t, tt.host, host)
			assert.Equal(t, tt.port, port)
		})
	}
}

func TestEngine_IsEndpointAllowed_PortEntries(t *testing.T) {
	engine := NewEngine(&api.NetworkConfig{
		AllowedHosts: []string{"192.168.2.102:2201", "api.example.com", "[2001:db8::1]:443"},
	})

	assert.True(t, engine.IsEndpointAllowed("192.168.2.102", 2201), "listed port")
	assert.False(t, engine.IsEndpointAllowed("192.168.2.102", 18999), "other port on the same address")
	assert.False(t, engine.IsEndpointAllowed("192.168.2.102", 0), "unknown port must not match a port entry")
	assert.True(t, engine.IsEndpointAllowed("api.example.com", 8080), "entry without port matches any port")
	assert.True(t, engine.IsEndpointAllowed("2001:db8::1", 443))
	assert.False(t, engine.IsEndpointAllowed("2001:db8::1", 22))
	assert.True(t, engine.IsHostAllowed("192.168.2.102:2201"), "host:port form")
	assert.False(t, engine.IsHostAllowed("192.168.2.102:22"))
}

func TestDeniedClass(t *testing.T) {
	own := net.ParseIP("192.168.2.102")
	tests := []struct {
		ip    string
		class string
	}{
		{"127.0.0.1", "loopback"},
		{"::ffff:127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"169.254.169.254", "link-local"},
		{"100.100.100.200", "cloud metadata"},
		{"0.0.0.0", "unspecified"},
		{"192.168.2.102", "this host's"},
		{"10.0.0.1", ""},
		{"192.168.2.50", ""},
		{"140.82.112.3", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.class, deniedClass(net.ParseIP(tt.ip), []net.IP{own}))
		})
	}
}

func TestDialAddress_GuardOffDialsByName(t *testing.T) {
	engine := NewEngine(&api.NetworkConfig{AllowedHosts: []string{"localhost"}})

	addr, err := engine.DialAddress(context.Background(), "localhost", 80)
	require.NoError(t, err)
	assert.Equal(t, "localhost:80", addr)
}

func TestDialAddress_GuardRefusesLoopbackName(t *testing.T) {
	engine := NewEngine(&api.NetworkConfig{
		AllowedHosts:     []string{"localhost"},
		GuardResolvedIPs: true,
	})

	_, err := engine.DialAddress(context.Background(), "localhost", 80)
	require.ErrorIs(t, err, ErrResolvedAddressDenied)
	assert.Contains(t, err.Error(), "loopback")
}

func TestDialAddress_GuardHonoursLiteralEntry(t *testing.T) {
	engine := NewEngine(&api.NetworkConfig{
		AllowedHosts:     []string{"localhost", "127.0.0.1:8080", "::1:8080"},
		GuardResolvedIPs: true,
	})

	addr, err := engine.DialAddress(context.Background(), "localhost", 8080)
	require.NoError(t, err)
	host, port, _ := net.SplitHostPort(addr)
	assert.True(t, net.ParseIP(host).IsLoopback())
	assert.Equal(t, "8080", port)

	_, err = engine.DialAddress(context.Background(), "localhost", 9090)
	assert.ErrorIs(t, err, ErrResolvedAddressDenied, "the literal entry covers its own port only")
}

func TestDialAddress_GuardPassesLiterals(t *testing.T) {
	engine := NewEngine(&api.NetworkConfig{
		AllowedHosts:     []string{"192.168.2.102:2201"},
		GuardResolvedIPs: true,
	})

	addr, err := engine.DialAddress(context.Background(), "192.168.2.102", 2201)
	require.NoError(t, err)
	assert.Equal(t, "192.168.2.102:2201", addr)
}

func TestHostAddresses_ExtendTheGuardsOwnAddresses(t *testing.T) {
	engine := NewEngine(&api.NetworkConfig{HostAddresses: []string{"192.168.1.20", "[2001:db8::7]", "not-an-ip"}})

	extra := engine.hostAddresses()
	require.Len(t, extra, 2, "invalid entries are skipped")
	assert.Equal(t, "this host's", deniedClass(net.ParseIP("192.168.1.20"), extra))
	assert.Equal(t, "this host's", deniedClass(net.ParseIP("2001:db8::7"), extra))
	assert.Equal(t, "", deniedClass(net.ParseIP("192.168.1.21"), extra))
}
