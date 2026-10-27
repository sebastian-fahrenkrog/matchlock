package net

import (
	"bufio"
	"os"
	"strings"
)

// dockerEmbeddedDNS is the address of Docker's embedded resolver, which every
// container on a user-defined network gets as its only nameserver.
const dockerEmbeddedDNS = "127.0.0.11"

// ResolvConfUpstreams returns the resolvers a gate should forward DNS to, read
// from a resolv.conf: its nameserver lines, except that Docker's embedded
// resolver is replaced by the external servers it would forward to, which
// Docker lists in a comment ("# ExtServers: [10.0.2.3]").
//
// The embedded resolver dials those servers from the container's own network
// namespace, unmarked -- so with the gate's rules in place its queries are
// redirected back into the gate's forwarder, which asks the embedded resolver
// again: SERVFAIL after a 4 s loop, measured 27 Oct 2026 under rootless docker
// with slirp4netns. Dialing the external servers directly, with the gate's
// mark, has no such loop. Servers Docker marks as host(...) are loopback
// addresses of the host that it reaches from the host's namespace; for those
// the embedded resolver works and stays. Empty when the file names no usable
// server; the caller then falls back to its defaults.
func ResolvConfUpstreams(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var nameservers, external []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "# ExtServers:"):
			external = parseExtServers(strings.TrimPrefix(line, "# ExtServers:"))
		case strings.HasPrefix(line, "nameserver"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				nameservers = append(nameservers, fields[1])
			}
		}
	}

	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, ns := range nameservers {
		if ns != dockerEmbeddedDNS {
			add(ns)
			continue
		}
		if len(external) == 0 {
			add(ns)
			continue
		}
		for _, ext := range external {
			add(ext)
		}
	}
	return out
}

// parseExtServers reads Docker's "[10.0.2.3 1.1.1.1 host(127.0.0.53)]" list
// and keeps the servers a container can dial itself; host(...) entries are
// left out (see ResolvConfUpstreams).
func parseExtServers(list string) []string {
	list = strings.Trim(strings.TrimSpace(list), "[]")
	var servers []string
	for _, entry := range strings.Fields(list) {
		if strings.HasPrefix(entry, "host(") {
			continue
		}
		servers = append(servers, strings.Trim(entry, ","))
	}
	return servers
}
