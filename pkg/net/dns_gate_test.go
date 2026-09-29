package net

import (
	"testing"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func buildGateQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	out, err := msg.Pack()
	require.NoError(t, err)
	return out
}

func TestGateDNSQuery(t *testing.T) {
	engine := policy.NewEngine(&api.NetworkConfig{
		AllowedHosts: []string{"example.com", "*.github.com", "192.168.2.102:2201"},
		DNSAllowlist: true,
	})

	for _, name := range []string{"example.com.", "api.github.com.", "EXAMPLE.com."} {
		refused, blocked := gateDNSQuery(buildGateQuery(t, 7, name), engine.IsNameResolvable)
		assert.Nil(t, refused, name)
		assert.Empty(t, blocked, name)
	}

	refused, blocked := gateDNSQuery(buildGateQuery(t, 42, "secret.attacker.example."), engine.IsNameResolvable)
	require.NotNil(t, refused)
	assert.Equal(t, "secret.attacker.example.", blocked)

	var p dnsmessage.Parser
	header, err := p.Start(refused)
	require.NoError(t, err)
	assert.Equal(t, uint16(42), header.ID)
	assert.True(t, header.Response)
	assert.Equal(t, dnsmessage.RCodeRefused, header.RCode)
}

func TestGateDNSQuery_Unparsable(t *testing.T) {
	engine := policy.NewEngine(&api.NetworkConfig{AllowedHosts: []string{"example.com"}, DNSAllowlist: true})
	_, blocked := gateDNSQuery([]byte{1, 2, 3}, engine.IsNameResolvable)
	assert.Equal(t, "<unparsable query>", blocked)
}

func TestGateDNSQuery_FlagOffForwardsAll(t *testing.T) {
	engine := policy.NewEngine(&api.NetworkConfig{AllowedHosts: []string{"example.com"}})
	refused, blocked := gateDNSQuery(buildGateQuery(t, 1, "wikipedia.org."), engine.IsNameResolvable)
	assert.Nil(t, refused)
	assert.Empty(t, blocked)
}
