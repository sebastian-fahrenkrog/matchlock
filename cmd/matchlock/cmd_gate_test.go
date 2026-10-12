//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestGateEnvFileSortedWithCAVariables(t *testing.T) {
	got := gateEnvFile(map[string]string{"ZED": "SANDBOX_SECRET_z", "ALPHA": "SANDBOX_SECRET_a"})
	require.Equal(t, "SSL_CERT_FILE=/etc/ssl/certs/matchlock-ca.crt\n"+
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/matchlock-ca.crt\n"+
		"CURL_CA_BUNDLE=/etc/ssl/certs/matchlock-ca.crt\n"+
		"NODE_EXTRA_CA_CERTS=/etc/ssl/certs/matchlock-ca.crt\n"+
		"ALPHA=SANDBOX_SECRET_a\n"+
		"ZED=SANDBOX_SECRET_z\n", got)
}

func TestGateRequiresRunIDAndCAOut(t *testing.T) {
	require.NoError(t, gateCmd.Flags().Set("run-id", ""))
	_, err := parseGateOptions(gateCmd)
	require.ErrorContains(t, err, "--run-id and --ca-out are required")
}

func TestParseFileOwner(t *testing.T) {
	o, err := parseFileOwner("")
	require.NoError(t, err)
	require.Nil(t, o)

	o, err = parseFileOwner("1000:1001")
	require.NoError(t, err)
	require.Equal(t, &fileOwner{uid: 1000, gid: 1001}, o)

	_, err = parseFileOwner("agent")
	require.ErrorContains(t, err, "want UID:GID")
}

func TestGateSecretFromFileMultipleHosts(t *testing.T) {
	// StringArray keeps the comma-separated host list in one value.
	require.NoError(t, gateCmd.Flags().Set("run-id", "r1"))
	require.NoError(t, gateCmd.Flags().Set("ca-out", "/tmp/ca.crt"))
	f := filepath.Join(t.TempDir(), "tok")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	require.NoError(t, gateCmd.Flags().Set("secret-from-file", "SANDBURG_RC_ACCESS="+f+"@api.anthropic.com,bridge.claudeusercontent.com"))
	t.Cleanup(func() {
		_ = gateCmd.Flags().Set("run-id", "")
		_ = gateCmd.Flags().Set("ca-out", "")
		_ = gateCmd.Flags().Lookup("secret-from-file").Value.(pflag.SliceValue).Replace(nil)
	})

	opts, err := parseGateOptions(gateCmd)
	require.NoError(t, err)
	s, ok := opts.network.Secrets["SANDBURG_RC_ACCESS"]
	require.True(t, ok)
	require.Equal(t, f, s.ValueFile)
	require.Equal(t, []string{"api.anthropic.com", "bridge.claudeusercontent.com"}, s.Hosts)
}
