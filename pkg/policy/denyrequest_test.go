package policy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func denyEngine(t *testing.T, rules ...string) *Engine {
	t.Helper()
	cfg := &api.NetworkConfig{
		AllowedHosts: []string{"api.github.com"},
		DenyRequests: rules,
		Secrets: map[string]api.Secret{
			"GITHUB_TOKEN": {Value: "ghp_real", Hosts: []string{"api.github.com"}},
		},
	}
	require.NoError(t, cfg.Validate())
	return NewEngine(cfg)
}

func reqTo(method, host, rawPath string, placeholder string) *http.Request {
	return &http.Request{
		Method: method,
		Host:   host,
		URL:    &url.URL{Scheme: "https", Host: host, Path: rawPath},
		Header: http.Header{"Authorization": []string{"Bearer " + placeholder}},
	}
}

func TestDenyRequest_RefusesBeforeSubstitution(t *testing.T) {
	engine := denyEngine(t, `POST api.github.com ^/user/keys$`)
	ph := engine.GetPlaceholder("GITHUB_TOKEN")

	req := reqTo("POST", "api.github.com", "/user/keys", ph)
	_, err := engine.OnRequest(req, "api.github.com")
	require.ErrorIs(t, err, api.ErrRequestDenied)
	assert.Contains(t, err.Error(), "POST api.github.com /user/keys")
	assert.Equal(t, "Bearer "+ph, req.Header.Get("Authorization"), "the placeholder must not have been replaced")
}

func TestDenyRequest_OtherMethodAndPathPass(t *testing.T) {
	engine := denyEngine(t, `POST api.github.com ^/user/keys$`)
	ph := engine.GetPlaceholder("GITHUB_TOKEN")

	for _, c := range []struct{ method, path string }{
		{"GET", "/user/keys"},
		{"POST", "/user/keys/extra"},
		{"POST", "/repos/o/r/issues"},
	} {
		req := reqTo(c.method, "api.github.com", c.path, ph)
		out, err := engine.OnRequest(req, "api.github.com")
		require.NoError(t, err, "%s %s", c.method, c.path)
		assert.Equal(t, "Bearer ghp_real", out.Header.Get("Authorization"))
	}
}

func TestDenyRequest_PathIsCleanedAndLowerCased(t *testing.T) {
	engine := denyEngine(t, `POST api.github.com ^/user/keys$`)
	ph := engine.GetPlaceholder("GITHUB_TOKEN")

	for _, p := range []string{"/User/Keys", "/user/./keys", "/user/x/../keys", "/user/keys/"} {
		req := reqTo("post", "api.github.com", p, ph)
		_, err := engine.OnRequest(req, "api.github.com")
		require.ErrorIs(t, err, api.ErrRequestDenied, "path %q should be denied", p)
	}
}

func TestDenyRequest_AnyMethodAndHostGlob(t *testing.T) {
	engine := denyEngine(t, `* *.github.com ^/repos/[^/]+/[^/]+/hooks(/[0-9]+(/config)?)?$`)
	ph := engine.GetPlaceholder("GITHUB_TOKEN")

	for _, c := range []struct{ method, path string }{
		{"POST", "/repos/o/r/hooks"},
		{"PATCH", "/repos/o/r/hooks/42"},
		{"PATCH", "/repos/o/r/hooks/42/config"},
	} {
		req := reqTo(c.method, "api.github.com", c.path, ph)
		_, err := engine.OnRequest(req, "api.github.com")
		require.ErrorIs(t, err, api.ErrRequestDenied, "%s %s", c.method, c.path)
	}
	req := reqTo("GET", "api.github.com", "/repos/o/r", ph)
	_, err := engine.OnRequest(req, "api.github.com")
	require.NoError(t, err)
}

func TestDenyRequest_InvalidEntryFailsValidate(t *testing.T) {
	for _, entry := range []string{"POST api.github.com", "P0ST api.github.com ^/x$", "POST api.github.com ^(/x$"} {
		cfg := &api.NetworkConfig{DenyRequests: []string{entry}}
		assert.ErrorIs(t, cfg.Validate(), api.ErrInvalidConfig, "entry %q", entry)
	}
}

func TestDenyRequest_UnparsableEntryRefusesEverything(t *testing.T) {
	// Belt to Validate's suspender: an engine built around a broken entry
	// must fail closed, never open.
	engine := NewEngine(&api.NetworkConfig{AllowedHosts: []string{"api.github.com"}, DenyRequests: []string{"broken"}})
	req := reqTo("GET", "api.github.com", "/anything", "")
	_, err := engine.OnRequest(req, "api.github.com")
	require.ErrorIs(t, err, api.ErrRequestDenied)
}
