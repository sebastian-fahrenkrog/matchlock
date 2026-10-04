//go:build linux

package net

import (
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestGateRulesSkipOnlyMarkedPackets(t *testing.T) {
	g := NewGateRules(GateMark, 8080, 8443, 9000, 5353)

	for _, rule := range append(g.natRules(), g.filterRules()...) {
		meta, ok := rule[0].(*expr.Meta)
		require.True(t, ok)
		require.Equal(t, expr.MetaKeyMARK, meta.Key)
		cmp, ok := rule[1].(*expr.Cmp)
		require.True(t, ok)
		require.Equal(t, expr.CmpOpNeq, cmp.Op)
		require.Equal(t, binaryutil.NativeEndian.PutUint32(GateMark), cmp.Data)
	}
}

func TestGateNATRuleOrder(t *testing.T) {
	g := NewGateRules(GateMark, 8080, 8443, 9000, 5353)
	rules := g.natRules()
	require.Len(t, rules, 5)

	// DNS first: a query to Docker's embedded resolver on 127.0.0.11 must
	// reach the forwarder, not slip through the loopback exemption.
	require.Equal(t, uint16(5353), natTargetPort(t, rules[0]))
	require.Equal(t, []byte{unix.IPPROTO_UDP}, rules[0][3].(*expr.Cmp).Data)

	// Then loopback, so the agent's own local services are never redirected.
	last := rules[1][len(rules[1])-1].(*expr.Verdict)
	require.Equal(t, expr.VerdictAccept, last.Kind)

	require.Equal(t, uint16(8080), natTargetPort(t, rules[2]))
	require.Equal(t, uint16(8443), natTargetPort(t, rules[3]))
	// The catch-all has no port match and comes last.
	require.Equal(t, uint16(9000), natTargetPort(t, rules[4]))
	require.Len(t, rules[4], 7)
}

func TestGateNATWithoutDNSOrPassthrough(t *testing.T) {
	g := NewGateRules(GateMark, 8080, 8443, 0, 0)
	require.Len(t, g.natRules(), 3)
}

func TestGateFilterAcceptsLoopbackAndRedirectedThenDrops(t *testing.T) {
	g := NewGateRules(GateMark, 8080, 8443, 9000, 5353)
	rules := g.filterRules()
	require.Len(t, rules, 3)

	require.Equal(t, ifname("lo"), rules[0][3].(*expr.Cmp).Data)
	require.Equal(t, expr.VerdictAccept, rules[0][4].(*expr.Verdict).Kind)

	ct, ok := rules[1][2].(*expr.Ct)
	require.True(t, ok)
	require.Equal(t, expr.CtKeySTATUS, ct.Key)
	require.Equal(t, binaryutil.NativeEndian.PutUint32(ctStatusDstNAT), rules[1][3].(*expr.Bitwise).Mask)
	require.Equal(t, expr.VerdictAccept, rules[1][5].(*expr.Verdict).Kind)

	require.Equal(t, expr.VerdictDrop, rules[2][2].(*expr.Verdict).Kind)
}

func natTargetPort(t *testing.T, rule []expr.Any) uint16 {
	t.Helper()
	imm, ok := rule[len(rule)-2].(*expr.Immediate)
	require.True(t, ok)
	return binaryutil.BigEndian.Uint16(imm.Data)
}
