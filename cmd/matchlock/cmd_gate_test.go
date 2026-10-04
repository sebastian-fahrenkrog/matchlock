//go:build linux

package main

import (
	"testing"

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
