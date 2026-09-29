package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ErrResolvedAddressDenied is returned when every address an allowed hostname
// resolves to falls into a denied class.
var ErrResolvedAddressDenied = errors.New("resolved address denied")

// splitHostPort splits "host:port", "[v6]:port", "host" and a bare IPv6
// literal. A missing or invalid port yields 0.
func splitHostPort(hostport string) (string, int) {
	if host, portStr, err := net.SplitHostPort(hostport); err == nil {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return host, 0
		}
		return host, port
	}
	return strings.Trim(hostport, "[]"), 0
}

// splitPatternPort separates an optional ":port" suffix from an allowlist entry.
//
// "api.example.com:443" and "[2001:db8::1]:443" carry a port; "*.example.com",
// "10.0.0.5" and an unbracketed IPv6 literal do not. Anything after the colon
// that is not a valid port leaves the entry untouched, so existing patterns
// keep their meaning.
func splitPatternPort(entry string) (string, int) {
	if strings.HasPrefix(entry, "[") {
		return splitHostPort(entry)
	}
	if strings.Count(entry, ":") != 1 {
		return entry, 0
	}
	idx := strings.LastIndex(entry, ":")
	port, err := strconv.Atoi(entry[idx+1:])
	if err != nil || port < 1 || port > 65535 {
		return entry, 0
	}
	return entry[:idx], port
}

// deniedRanges are the address classes a hostname must not resolve to.
//
// The allowlist matches names, but whoever controls a permitted name's DNS
// controls where it points. Without this check an allowed name that resolves
// to 127.0.0.1, to the cloud metadata endpoint or to one of the host's own
// addresses reaches services that were never meant to be opened. Private
// ranges (10/8, 192.168/16, ...) are deliberately absent: an intranet hostname
// is a legitimate thing to allow.
var deniedRanges = []struct {
	class string
	cidr  *net.IPNet
}{
	{"loopback", mustCIDR("127.0.0.0/8")},
	{"loopback", mustCIDR("::1/128")},
	{"unspecified", mustCIDR("0.0.0.0/8")},
	{"unspecified", mustCIDR("::/128")},
	{"link-local", mustCIDR("169.254.0.0/16")},
	{"link-local", mustCIDR("fe80::/10")},
	{"multicast", mustCIDR("224.0.0.0/4")},
	{"multicast", mustCIDR("ff00::/8")},
	{"broadcast", mustCIDR("255.255.255.255/32")},
	{"cloud metadata", mustCIDR("100.100.100.200/32")},
	{"cloud metadata", mustCIDR("168.63.129.16/32")},
	{"cloud metadata", mustCIDR("192.0.0.192/32")},
	{"cloud metadata", mustCIDR("fd00:ec2::/32")},
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// deniedClass names the class an address belongs to, or "" if it is fine.
// IPv4-mapped IPv6 addresses are judged by the IPv4 address they carry.
func deniedClass(ip net.IP, local []net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, r := range deniedRanges {
		if r.cidr.Contains(ip) {
			return r.class
		}
	}
	for _, own := range local {
		if own.Equal(ip) {
			return "this host's"
		}
	}
	return ""
}

// localAddresses lists the addresses assigned to this host's interfaces. A
// service bound to 0.0.0.0 answers on each of them exactly as on loopback.
// Read per call: interfaces come and go (tethering, VPN).
func localAddresses() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

// literalAllowed reports whether ip is itself an allowlist entry for port.
// Allowing a literal is an explicit choice; reaching the same address through
// a name grants nothing the literal entry does not.
func (e *Engine) literalAllowed(ip net.IP, port int) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, entry := range e.config.AllowedHosts {
		pattern, entryPort := splitPatternPort(entry)
		if entryPort != 0 && entryPort != port {
			continue
		}
		if lit := net.ParseIP(pattern); lit != nil && lit.Equal(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) guardEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.GuardResolvedIPs
}

// DialAddress returns the address to dial for an already allowed host.
//
// With the guard off it is host:port, resolved by the dialer as before. With
// it on, a hostname is resolved once here, every address in a denied class is
// dropped unless allowed as a literal, and the surviving address is returned --
// the one that passed the check is the one dialed, there is no second lookup
// for DNS to answer differently. IP literals pass unchanged: the allowlist
// already named them.
func (e *Engine) DialAddress(ctx context.Context, host string, port int) (string, error) {
	host = strings.Trim(host, "[]")
	portStr := strconv.Itoa(port)
	if !e.guardEnabled() || net.ParseIP(host) != nil {
		return net.JoinHostPort(host, portStr), nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("%w: %s resolved to no address", ErrResolvedAddressDenied, host)
	}

	local := localAddresses()
	lastClass := ""
	for _, a := range addrs {
		class := deniedClass(a.IP, local)
		if class == "" || e.literalAllowed(a.IP, port) {
			return net.JoinHostPort(a.IP.String(), portStr), nil
		}
		lastClass = class
	}
	return "", fmt.Errorf("%w: %s resolved to a %s address", ErrResolvedAddressDenied, host, lastClass)
}

func (e *Engine) dnsAllowlistEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.DNSAllowlist
}

// IsNameResolvable reports whether the guest may resolve name through DNS.
//
// Without the DNS allowlist every name is forwarded, as before. With it, only
// names matching an allowlist entry are: a query is data leaving the sandbox,
// and "<secret>.attacker.example" reaches the attacker's name server no matter
// what the HTTP allowlist says. IP-literal entries never match a name.
func (e *Engine) IsNameResolvable(name string) bool {
	if !e.dnsAllowlistEnabled() {
		return true
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.config.AllowedHosts) == 0 {
		return true
	}
	for _, entry := range e.config.AllowedHosts {
		pattern, _ := splitPatternPort(entry)
		if matchGlob(strings.ToLower(pattern), name) {
			return true
		}
	}
	return false
}
