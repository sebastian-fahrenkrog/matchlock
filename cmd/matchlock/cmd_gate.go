//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/audit"
	sandboxnet "github.com/jingkaihe/matchlock/pkg/net"
	"github.com/jingkaihe/matchlock/pkg/policy"
)

// The gate is the network half of `run` without the VM. It runs as root in a
// container of its own; the agent container joins its network namespace
// (docker run --network container:<gate>) and nftables rules send every packet
// not carrying the gate's own socket mark through the same MITM proxy,
// passthrough, DNS forwarder, policy engine and audit sinks the VM backends
// use. Secrets, the CA key and the logs exist only in the gate's mount and PID
// namespaces, which the agent does not share.
var gateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Run the network gate for a container that shares this network namespace",
	Long: `Run the network gate for a container that shares this network namespace.

Applies nftables rules in the current network namespace so that every packet
not sent by the gate itself goes through matchlock's MITM proxy (TCP 80/443),
the policy-gated passthrough (other TCP) or the DNS forwarder (UDP 53);
everything else is dropped, IPv6 included. The gate tells its own sockets apart
by SO_MARK, which a process without CAP_NET_ADMIN/CAP_NET_RAW cannot set, so the
agent container must run with --cap-drop ALL. Requires CAP_NET_ADMIN in the
namespace. Runs until SIGINT/SIGTERM.

--ca-out receives ca.crt (the MITM CA certificate, never its key) and env
(NAME=VALUE lines: secret placeholders and CA variables) for the agent
container. ready is written last, once the rules are in place.`,
	Args: cobra.NoArgs,
	RunE: runGate,
}

func init() {
	f := gateCmd.Flags()
	f.StringSlice("allow-host", nil, "Allowed hosts (can be repeated)")
	f.StringArray("secret", nil, "Secret (NAME=VALUE@host1,host2 or NAME@host1,host2)")
	f.StringArray("secret-placeholder", nil, "Secret placeholder override (NAME=PLACEHOLDER)")
	f.String("secret-file", "", "JSON file with full secret definitions")
	f.StringSlice("secret-from-file", nil, "Secret read from a file at request time (NAME=/path@host1,host2)")
	f.StringSlice("dns-servers", nil, "Upstream DNS servers (default 8.8.8.8, 8.8.4.4)")
	f.Bool("allow-private-ips", false, "Allow connections to private IP ranges")
	f.Bool("guard-resolved-ips", false, "Refuse allowed names that resolve to loopback, link-local, metadata or host addresses")
	f.Bool("dns-allowlist", false, "Answer DNS only for names matching --allow-host")
	f.StringSlice("host-address", nil, "Further addresses the resolved-IP guard treats as the host's own (repeatable)")
	f.String("audit-db", "", "Record every outbound request into this SQLite file")
	f.String("record", "", "Record full exchanges as JSONL")
	f.String("file-owner", "", "UID:GID to hand the files the gate writes to (rootful Docker, where the gate's root is the host's root)")
	f.String("run-id", "", "Identifier written as vm_id into the audit DB (required)")
	f.String("ca-out", "", "Directory for ca.crt, env and the ready marker (required)")
	f.String("workspace", "/workspace", "Workspace path recorded in the audit DB")
	f.String("image", "", "Image name recorded in the audit DB")
	rootCmd.AddCommand(gateCmd)
}

type gateOptions struct {
	network  *api.NetworkConfig
	auditDB  string
	owner    *fileOwner
	runID    string
	caOut    string
	image    string
	work     string
}

func runGate(cmd *cobra.Command, _ []string) error {
	opts, err := parseGateOptions(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := contextWithSignal(context.Background())
	defer cancel()

	g, err := startGate(opts)
	if err != nil {
		return err
	}
	defer g.close()

	if opts.auditDB != "" {
		logger, err := audit.Open(opts.auditDB, opts.runID, opts.image, opts.work, "gate")
		if err != nil {
			return fmt.Errorf("audit db: %w", err)
		}
		defer logger.Close()
		opts.owner.chown(opts.auditDB, opts.auditDB+"-wal", opts.auditDB+"-shm")
		go logger.Consume(ctx, g.events)
	}

	opts.owner.chown(opts.network.RecordPath)
	if err := writeGateOutputs(opts.caOut, g, opts.owner); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "gate ready: http %d, https %d, passthrough %d, dns %d\n",
		g.proxy.HTTPPort(), g.proxy.HTTPSPort(), g.proxy.PassthroughPort(), g.dns.Port())

	<-ctx.Done()
	return nil
}

func parseGateOptions(cmd *cobra.Command) (*gateOptions, error) {
	f := cmd.Flags()
	str := func(name string) string { v, _ := f.GetString(name); return v }
	slice := func(name string) []string { v, _ := f.GetStringSlice(name); return v }
	array := func(name string) []string { v, _ := f.GetStringArray(name); return v }
	boolean := func(name string) bool { v, _ := f.GetBool(name); return v }

	opts := &gateOptions{runID: str("run-id"), caOut: str("ca-out"), auditDB: str("audit-db"),
		image: str("image"), work: str("workspace")}
	if opts.runID == "" || opts.caOut == "" {
		return nil, fmt.Errorf("--run-id and --ca-out are required")
	}
	owner, err := parseFileOwner(str("file-owner"))
	if err != nil {
		return nil, err
	}
	opts.owner = owner

	secrets, err := parseRunSecrets(array("secret"), array("secret-placeholder"), str("secret-file"), slice("secret-from-file"))
	if err != nil {
		return nil, err
	}
	opts.network = &api.NetworkConfig{
		AllowedHosts:     slice("allow-host"),
		BlockPrivateIPs:  !boolean("allow-private-ips"),
		GuardResolvedIPs: boolean("guard-resolved-ips"),
		DNSAllowlist:     boolean("dns-allowlist"),
		HostAddresses:    slice("host-address"),
		RecordPath:       str("record"),
		Secrets:          secrets,
		DNSServers:       slice("dns-servers"),
		Intercept:        true,
	}
	return opts, opts.network.Validate()
}

type gate struct {
	policy   *policy.Engine
	caPool   *sandboxnet.CAPool
	proxy    *sandboxnet.TransparentProxy
	dns      *sandboxnet.DNSForwarder
	rules    *sandboxnet.GateRules
	recorder *audit.Recorder
	events   chan api.Event
}

// startGate brings up proxy, DNS forwarder and nftables rules, in that order,
// so no agent packet is ever redirected to a port that is not listening yet.
// The dial mark goes first: an unmarked dial of the gate's own would be
// redirected into itself once the rules are in place.
func startGate(opts *gateOptions) (*gate, error) {
	sandboxnet.SetDialMark(sandboxnet.GateMark)
	g := &gate{policy: policy.NewEngine(opts.network), events: make(chan api.Event, 100)}

	var err error
	if g.caPool, err = sandboxnet.NewCAPool(); err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}
	if opts.network.RecordPath != "" {
		if g.recorder, err = audit.NewRecorder(opts.network.RecordPath, opts.runID); err != nil {
			return nil, fmt.Errorf("record: %w", err)
		}
	}

	g.proxy, err = sandboxnet.NewTransparentProxy(&sandboxnet.ProxyConfig{
		BindAddr: "127.0.0.1", Policy: g.policy, Events: g.events, CAPool: g.caPool, Recorder: g.recorder,
	})
	if err != nil {
		g.close()
		return nil, fmt.Errorf("proxy: %w", err)
	}
	g.proxy.Start()

	if g.dns, err = sandboxnet.NewDNSForwarder("127.0.0.1", opts.network.GetDNSServers()); err != nil {
		g.close()
		return nil, fmt.Errorf("dns forwarder: %w", err)
	}
	g.dns.SetNameFilter(g.policy.IsNameResolvable)

	g.rules = sandboxnet.NewGateRules(sandboxnet.GateMark, g.proxy.HTTPPort(), g.proxy.HTTPSPort(), g.proxy.PassthroughPort(), g.dns.Port())
	if err := g.rules.Setup(); err != nil {
		g.rules = nil
		g.close()
		return nil, fmt.Errorf("nftables (CAP_NET_ADMIN missing?): %w", err)
	}
	return g, nil
}

func (g *gate) close() {
	// Rules first: with the listeners gone, a redirected packet would only hit
	// a closed port, but there is no reason to leave the window open.
	if g.rules != nil {
		_ = g.rules.Cleanup()
	}
	if g.dns != nil {
		_ = g.dns.Close()
	}
	if g.proxy != nil {
		_ = g.proxy.Close()
	}
	if g.recorder != nil {
		_ = g.recorder.Close()
	}
}

// gateCACertPath is where the agent container sees the CA certificate; the
// same path the VM backends inject into the guest root filesystem.
const gateCACertPath = "/etc/ssl/certs/matchlock-ca.crt"

// writeGateOutputs writes ca.crt, env and finally ready into dir.
func writeGateOutputs(dir string, g *gate, owner *fileOwner) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{"ca.crt", g.caPool.CACertPEM()},
		{"env", []byte(gateEnvFile(g.policy.GetPlaceholders()))},
		{"ready", nil},
	}
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, f.data, 0o644); err != nil {
			return err
		}
		owner.chown(path)
	}
	return nil
}

// fileOwner hands files the gate creates to the operator. Under rootful Docker
// the gate's root is the host's root, and an audit DB at mode 600 owned by it
// would be unreadable for the person running sandburg. Nil means "leave as is"
// (rootless: the gate's root already is the operator).
type fileOwner struct{ uid, gid int }

func parseFileOwner(spec string) (*fileOwner, error) {
	if spec == "" {
		return nil, nil
	}
	var o fileOwner
	if _, err := fmt.Sscanf(spec, "%d:%d", &o.uid, &o.gid); err != nil {
		return nil, fmt.Errorf("--file-owner %q: want UID:GID", spec)
	}
	return &o, nil
}

// chown skips empty paths and files that do not exist (yet).
func (o *fileOwner) chown(paths ...string) {
	if o == nil {
		return
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if err := os.Chown(p, o.uid, o.gid); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: chown %s: %v\n", p, err)
		}
	}
}

// gateEnvFile renders the environment the VM backends hand the guest
// (prepareExecEnv): CA variables plus one placeholder per secret, sorted for a
// stable file.
func gateEnvFile(placeholders map[string]string) string {
	lines := []string{
		"SSL_CERT_FILE=" + gateCACertPath,
		"REQUESTS_CA_BUNDLE=" + gateCACertPath,
		"CURL_CA_BUNDLE=" + gateCACertPath,
		"NODE_EXTRA_CA_CERTS=" + gateCACertPath,
	}
	names := make([]string, 0, len(placeholders))
	for name := range placeholders {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		lines = append(lines, name+"="+placeholders[name])
	}
	return strings.Join(lines, "\n") + "\n"
}
