package policy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jingkaihe/matchlock/pkg/api"
)

type Engine struct {
	mu           sync.RWMutex
	config       *api.NetworkConfig
	placeholders map[string]string
	networkRules []compiledNetworkRule
	networkHook  networkHookInvoker

	// Eigener Mutex, weil OnRequest e.mu bereits als RLock hält.
	fileMu    sync.Mutex
	fileCache map[string]cachedSecret
}

// cachedSecret vermeidet, bei jedem Request die Platte anzufassen; die Datei
// wird nur neu gelesen, wenn sich mtime oder Größe geändert haben.
type cachedSecret struct {
	value   string
	modTime time.Time
	size    int64
}

func NewEngine(config *api.NetworkConfig) *Engine {
	if config == nil {
		config = &api.NetworkConfig{}
	}

	e := &Engine{
		config:       config,
		placeholders: make(map[string]string),
		networkRules: compileNetworkRules(config.Interception),
		networkHook:  newNetworkHookInvoker(config),
		fileCache:    make(map[string]cachedSecret),
	}

	for name, secret := range config.Secrets {
		if secret.Placeholder == "" {
			placeholder := generatePlaceholder()
			config.Secrets[name] = api.Secret{
				Value:       secret.Value,
				ValueFile:   secret.ValueFile,
				Placeholder: placeholder,
				Hosts:       secret.Hosts,
			}
		}
		e.placeholders[name] = config.Secrets[name].Placeholder
	}

	return e
}

// SetNetworkHookInvoker overrides the SDK-local network hook invoker.
// This is primarily intended for testing.
func (e *Engine) SetNetworkHookInvoker(invoker networkHookInvoker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.networkHook = invoker
}

func generatePlaceholder() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return api.GeneratedSecretPlaceholderPrefix + hex.EncodeToString(b)
}

func (e *Engine) GetPlaceholder(name string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.placeholders[name]
}

func (e *Engine) GetPlaceholders() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]string)
	for k, v := range e.placeholders {
		result[k] = v
	}
	return result
}

func (e *Engine) AddAllowedHosts(hosts ...string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config == nil {
		e.config = &api.NetworkConfig{}
	}

	existing := make(map[string]struct{}, len(e.config.AllowedHosts))
	for _, host := range e.config.AllowedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		existing[host] = struct{}{}
	}

	added := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, ok := existing[host]; ok {
			continue
		}
		e.config.AllowedHosts = append(e.config.AllowedHosts, host)
		existing[host] = struct{}{}
		added = append(added, host)
	}

	return added
}

func (e *Engine) RemoveAllowedHosts(hosts ...string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config == nil || len(e.config.AllowedHosts) == 0 {
		return nil
	}

	toRemove := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		toRemove[host] = struct{}{}
	}
	if len(toRemove) == 0 {
		return nil
	}

	next := make([]string, 0, len(e.config.AllowedHosts))
	removed := make([]string, 0, len(toRemove))
	removedSet := make(map[string]struct{}, len(toRemove))
	for _, host := range e.config.AllowedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, ok := toRemove[host]; ok {
			if _, seen := removedSet[host]; !seen {
				removed = append(removed, host)
				removedSet[host] = struct{}{}
			}
			continue
		}
		next = append(next, host)
	}
	e.config.AllowedHosts = next
	return removed
}

func (e *Engine) AllowedHosts() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.config == nil || len(e.config.AllowedHosts) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(e.config.AllowedHosts))
	for _, host := range e.config.AllowedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func (e *Engine) IsHostAllowed(host string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	host = strings.Split(host, ":")[0]

	if e.config.BlockPrivateIPs {
		if isPrivateIP(host) {
			return false
		}
	}

	if len(e.config.AllowedHosts) == 0 {
		return true
	}

	for _, pattern := range e.config.AllowedHosts {
		if matchGlob(pattern, host) {
			return true
		}
	}

	return false
}

func (e *Engine) OnRequest(req *http.Request, host string) (*http.Request, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	host = strings.Split(host, ":")[0]

	if err := e.applyBeforeNetworkRules(req, host); err != nil {
		return nil, err
	}

	for name, secret := range e.config.Secrets {
		if !e.isSecretAllowedForHost(name, host) {
			if e.requestContainsPlaceholder(req, secret.Placeholder) {
				return nil, api.ErrSecretLeak
			}
			continue
		}
		value := e.resolveValue(name, secret)
		if value == "" {
			// Lieber den Platzhalter rausgehen lassen und ein 401 kassieren als
			// still ein leeres Credential einzusetzen.
			continue
		}
		e.replaceInRequest(req, secret.Placeholder, value)
	}

	return req, nil
}

func (e *Engine) OnResponse(resp *http.Response, req *http.Request, host string) (*http.Response, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	host = strings.Split(host, ":")[0]
	return e.applyAfterNetworkRules(resp, req, host)
}

// resolveValue liefert den aktuellen Wert eines Secrets. Bei dateibasierten
// Secrets wird die Datei neu gelesen, sobald sie sich geändert hat — ein
// rotiertes Credential wirkt damit ohne Neustart der VM. Wird die Datei
// unlesbar, bleibt der zuletzt gelesene Wert stehen: ein kurzzeitig fehlender
// Pfad soll keinen laufenden Agenten abschiessen.
func (e *Engine) resolveValue(name string, secret api.Secret) string {
	if secret.ValueFile == "" {
		return secret.Value
	}

	e.fileMu.Lock()
	defer e.fileMu.Unlock()

	cached, hasCached := e.fileCache[name]

	info, err := os.Stat(secret.ValueFile)
	if err != nil {
		return cached.value
	}
	if hasCached && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
		return cached.value
	}

	content, err := os.ReadFile(secret.ValueFile)
	if err != nil {
		return cached.value
	}
	value := strings.TrimSpace(string(content))
	if value == "" {
		return cached.value
	}

	e.fileCache[name] = cachedSecret{value: value, modTime: info.ModTime(), size: info.Size()}
	return value
}

// Redact ersetzt jeden echten Secret-Wert durch seinen Platzhalter.
//
// Nötig für Mitschnitte: der Request geht mit dem echten Wert raus, und manche
// Antworten spiegeln ihn zurück (httpbin tut es, Fehlermeldungen tun es, Echo-
// Endpunkte sowieso). Ohne diesen Schritt wäre der Mitschnitt genau die Stelle,
// an der die Credentials doch auf der Platte landen.
func (e *Engine) Redact(s string) string {
	if s == "" {
		return s
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, secret := range e.config.Secrets {
		if secret.Placeholder == "" {
			continue
		}
		value := secret.Value
		if secret.ValueFile != "" {
			// Der aktuelle Wert steht in der Datei; ohne ihn wüssten wir nicht,
			// wonach wir suchen.
			if data, err := os.ReadFile(secret.ValueFile); err == nil {
				value = strings.TrimSpace(string(data))
			}
		}
		if value == "" {
			continue
		}
		s = strings.ReplaceAll(s, value, secret.Placeholder)
	}
	return s
}

func (e *Engine) isSecretAllowedForHost(secretName, host string) bool {
	secret, ok := e.config.Secrets[secretName]
	if !ok {
		return false
	}

	if len(secret.Hosts) == 0 {
		return true
	}

	for _, pattern := range secret.Hosts {
		if matchGlob(pattern, host) {
			return true
		}
	}

	return false
}

func (e *Engine) requestContainsPlaceholder(req *http.Request, placeholder string) bool {
	for _, values := range req.Header {
		for _, v := range values {
			if strings.Contains(v, placeholder) {
				return true
			}
			if basicValueContainsPlaceholder(v, placeholder) {
				return true
			}
		}
	}

	if req.URL != nil {
		if strings.Contains(req.URL.String(), placeholder) {
			return true
		}
	}

	return false
}

// replaceInRequest substitutes the placeholder with the real secret in headers
// and URL query params only. We intentionally skip the request body because the
// body is processed by the remote server's application layer, which may log or
// echo it back in responses — leaking the real secret into the VM.
func (e *Engine) replaceInRequest(req *http.Request, placeholder, value string) {
	for key, values := range req.Header {
		for i, v := range values {
			if strings.Contains(v, placeholder) {
				req.Header[key][i] = strings.ReplaceAll(v, placeholder, value)
				continue
			}
			if replaced, ok := replaceBasicAuthPlaceholder(v, placeholder, value); ok {
				req.Header[key][i] = replaced
			}
		}
	}

	if req.URL != nil {
		if strings.Contains(req.URL.RawQuery, placeholder) {
			req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, placeholder, value)
		}
	}

}

func basicValueContainsPlaceholder(value, placeholder string) bool {
	decoded, ok := decodeBasicAuthHeader(value)
	if !ok {
		return false
	}
	return strings.Contains(decoded, placeholder)
}

func replaceBasicAuthPlaceholder(value, placeholder, replacement string) (string, bool) {
	decoded, ok := decodeBasicAuthHeader(value)
	if !ok || !strings.Contains(decoded, placeholder) {
		return "", false
	}
	replaced := strings.ReplaceAll(decoded, placeholder, replacement)
	encoded := base64.StdEncoding.EncodeToString([]byte(replaced))
	return "Basic " + encoded, true
}

func decodeBasicAuthHeader(value string) (string, bool) {
	prefix, encoded, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(strings.TrimSpace(prefix), "Basic") {
		return "", false
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func matchGlob(pattern, str string) bool {
	if pattern == "*" {
		return true
	}

	// Simple prefix wildcard: *.example.com
	if strings.HasPrefix(pattern, "*.") && !strings.Contains(pattern[2:], "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(str, suffix)
	}

	// Simple suffix wildcard: example.*
	if strings.HasSuffix(pattern, ".*") && !strings.Contains(pattern[:len(pattern)-2], "*") {
		prefix := pattern[:len(pattern)-2]
		return strings.HasPrefix(str, prefix+".")
	}

	// General glob matching with * as wildcard
	if strings.Contains(pattern, "*") {
		return matchWildcard(pattern, str)
	}

	return pattern == str
}

// matchWildcard handles patterns with * wildcards anywhere
func matchWildcard(pattern, str string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == str
	}

	// Check prefix (before first *)
	if parts[0] != "" && !strings.HasPrefix(str, parts[0]) {
		return false
	}
	str = str[len(parts[0]):]

	// Check suffix (after last *)
	lastPart := parts[len(parts)-1]
	if lastPart != "" && !strings.HasSuffix(str, lastPart) {
		return false
	}
	if lastPart != "" {
		str = str[:len(str)-len(lastPart)]
	}

	// Check middle parts in order
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(str, parts[i])
		if idx < 0 {
			return false
		}
		str = str[idx+len(parts[i]):]
	}

	return true
}

func isPrivateIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
