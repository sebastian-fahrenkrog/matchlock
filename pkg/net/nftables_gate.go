//go:build linux

package net

import (
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/jingkaihe/matchlock/internal/errx"
	"golang.org/x/sys/unix"
)

const gateTableName = "matchlock_gate"

// GateMark is the SO_MARK the gate puts on its own sockets (SetDialMark).
const GateMark = 0x53424752 // "SBGR"

// GateRules confine every process in a network namespace that the gate shares
// with the agent container (docker run --network container:<gate>), except
// the gate itself.
//
// The VM path matches traffic by the TAP interface it enters on. A container
// sharing the gate's namespace has no interface of its own, and its UID says
// nothing either: under rootless Docker the agent runs as container root, the
// same UID as the gate. What tells the two apart is the mark the gate sets on
// every socket it dials; the agent holds no capability that could set it.
// Every unmarked UDP/53 packet goes to the DNS forwarder, whatever its
// address -- Docker's embedded resolver on 127.0.0.11 included, which would
// otherwise answer every name. Every other unmarked packet to a non-loopback
// address is redirected in nat OUTPUT: TCP/80 and TCP/443 to the MITM, all
// other TCP to the passthrough. filter OUTPUT drops whatever unmarked packet was
// not redirected: other UDP, ICMP and all of IPv6. Loopback stays untouched so
// the agent's own local services keep working; the gate's listeners there
// enforce the policy themselves.
type GateRules struct {
	mark             uint32
	httpPort         uint16
	httpsPort        uint16
	passthroughPort  uint16
	dnsForwarderPort uint16
	conn             *nftables.Conn
	natTable         *nftables.Table
	filterTable      *nftables.Table
}

func NewGateRules(mark uint32, httpPort, httpsPort, passthroughPort, dnsForwarderPort int) *GateRules {
	return &GateRules{
		mark:             mark,
		httpPort:         uint16(httpPort),
		httpsPort:        uint16(httpsPort),
		passthroughPort:  uint16(passthroughPort),
		dnsForwarderPort: uint16(dnsForwarderPort),
	}
}

func (g *GateRules) Setup() error {
	conn, err := nftables.New()
	if err != nil {
		return errx.Wrap(ErrNFTablesConn, err)
	}
	g.conn = conn

	g.natTable = conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: gateTableName})
	natChain := conn.AddChain(&nftables.Chain{
		Name:     chainOutput,
		Table:    g.natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		// Ahead of Docker's own DOCKER_OUTPUT (dstnat), which would hand
		// 127.0.0.11:53 to the embedded resolver first.
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 10),
	})

	// inet covers IPv4 and IPv6 in one chain, so the agent gets no IPv6 path.
	g.filterTable = conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: gateTableName})
	filterChain := conn.AddChain(&nftables.Chain{
		Name:     chainOutput,
		Table:    g.filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	for _, exprs := range g.natRules() {
		conn.AddRule(&nftables.Rule{Table: g.natTable, Chain: natChain, Exprs: exprs})
	}
	for _, exprs := range g.filterRules() {
		conn.AddRule(&nftables.Rule{Table: g.filterTable, Chain: filterChain, Exprs: exprs})
	}

	if err := conn.Flush(); err != nil {
		return errx.Wrap(ErrNFTablesApply, err)
	}
	return nil
}

// natRules are evaluated in order; the first match wins.
func (g *GateRules) natRules() [][]expr.Any {
	var rules [][]expr.Any
	if g.dnsForwarderPort > 0 {
		rules = append(rules, g.redirectRule(unix.IPPROTO_UDP, 53, g.dnsForwarderPort))
	}
	rules = append(rules,
		g.loopbackAcceptRule(),
		g.redirectRule(unix.IPPROTO_TCP, 80, g.httpPort),
		g.redirectRule(unix.IPPROTO_TCP, 443, g.httpsPort),
	)
	if g.passthroughPort > 0 {
		rules = append(rules, g.redirectRule(unix.IPPROTO_TCP, 0, g.passthroughPort))
	}
	return rules
}

// filterRules let the agent reach loopback and whatever nat OUTPUT redirected,
// and drop everything else it sends. A redirected packet is recognised by its
// conntrack DNAT status, not by its interface: at this hook it still carries
// the output interface of the original route.
func (g *GateRules) filterRules() [][]expr.Any {
	loopback := append(g.matchAgent(),
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	redirected := append(g.matchAgent(),
		&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(ctStatusDstNAT),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
	drop := append(g.matchAgent(), &expr.Verdict{Kind: expr.VerdictDrop})
	return [][]expr.Any{loopback, redirected, drop}
}

// ctStatusDstNAT is IPS_DST_NAT from linux/netfilter/nf_conntrack_common.h.
const ctStatusDstNAT = 1 << 5

// matchAgent matches every packet that does not carry the gate's mark.
func (g *GateRules) matchAgent() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(g.mark)},
	}
}

// loopbackAcceptRule leaves agent traffic to 127.0.0.0/8 untranslated.
func (g *GateRules) loopbackAcceptRule() []expr.Any {
	return append(g.matchAgent(),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0xff, 0, 0, 0},
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{127, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// redirectRule DNATs agent packets of proto (and dstPort, 0 = any) to
// 127.0.0.1:toPort, where SO_ORIGINAL_DST still yields the real target.
func (g *GateRules) redirectRule(proto byte, dstPort, toPort uint16) []expr.Any {
	exprs := append(g.matchAgent(),
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	)
	if dstPort != 0 {
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(dstPort)},
		)
	}
	return append(exprs,
		&expr.Immediate{Register: 1, Data: net.IPv4(127, 0, 0, 1).To4()},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(toPort)},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	)
}

func (g *GateRules) Cleanup() error {
	if g.conn == nil {
		return nil
	}
	if g.natTable != nil {
		g.conn.DelTable(g.natTable)
	}
	if g.filterTable != nil {
		g.conn.DelTable(g.filterTable)
	}
	return g.conn.Flush()
}
