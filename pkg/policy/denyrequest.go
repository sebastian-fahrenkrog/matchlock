package policy

import (
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/jingkaihe/matchlock/pkg/api"
)

// denyRequestRule is one compiled DenyRequests entry (patch 10): a request on
// an allowed host that is refused before any secret is put in.
type denyRequestRule struct {
	method string // upper-case, or "*" for any
	host   string // glob, as in the allowlist
	path   *regexp.Regexp
	raw    string
}

// compileDenyRequests turns the config's entries into rules. An entry that
// does not parse becomes a rule that refuses every request on every host: a
// broken deny must never read as no deny. Validate reports such entries up
// front, so this is the belt to that suspender.
func compileDenyRequests(entries []string) []denyRequestRule {
	rules := make([]denyRequestRule, 0, len(entries))
	for _, entry := range entries {
		method, host, re, err := api.ParseDenyRequest(entry)
		if err != nil {
			rules = append(rules, denyRequestRule{method: "*", host: "*", path: regexp.MustCompile(".*"), raw: entry + " (unparsable, refusing everything)"})
			continue
		}
		rules = append(rules, denyRequestRule{method: method, host: host, path: re, raw: entry})
	}
	return rules
}

// cleanRequestPath normalises the request path for matching: no query,
// dot segments resolved, lower-cased (GitHub's paths are case-insensitive, so
// /User/Keys must not slip past a rule for /user/keys).
func cleanRequestPath(req *http.Request) string {
	p := ""
	if req.URL != nil {
		p = req.URL.Path
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.ToLower(path.Clean(p))
}

func (r denyRequestRule) matches(method, host, cleanPath string) bool {
	if r.method != "*" && r.method != strings.ToUpper(method) {
		return false
	}
	if !matchGlob(r.host, host) {
		return false
	}
	return r.path.MatchString(cleanPath)
}

// deniedRequest returns the first rule that refuses req to host, or nil.
func (e *Engine) deniedRequest(req *http.Request, host string) *denyRequestRule {
	if len(e.denyRequests) == 0 {
		return nil
	}
	cleanPath := cleanRequestPath(req)
	for i := range e.denyRequests {
		if e.denyRequests[i].matches(req.Method, host, cleanPath) {
			return &e.denyRequests[i]
		}
	}
	return nil
}
