package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Web holds the per-route HTTP options: redirect rules, an IP allowlist, extra headers, CORS, compression
// and HSTS. It is stored as JSON in routes.web. In the API a missing "web" keeps the current options.
type Web struct {
	// Redirects are checked in order before proxying; the first match answers with a redirect.
	Redirects []RedirectRule `json:"redirects,omitempty"`
	// AllowIPs limits the route to these client IPs/CIDRs (others get 403); empty = everyone.
	AllowIPs []string `json:"allow_ips,omitempty"`
	// ResponseHeaders are set on every response ("" value removes the header).
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	// RequestHeaders are set on the request to the backend ("" value removes the header).
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	// BackendHost replaces the site name the backend sees (Host header, and the TLS server name of an
	// HTTPS backend), e.g. when the other server's nginx knows the site under another name. Empty: the
	// client's host is passed on.
	BackendHost string `json:"backend_host,omitempty"`
	// AllowScannerPaths turns the scanner-path blocking off for this route: paths such as /wp-admin,
	// /wp-login.php or /phpmyadmin get a visitor blocked for a day on other routes, but an app that really
	// serves them (WordPress, phpMyAdmin) needs them reachable.
	AllowScannerPaths bool  `json:"allow_scanner_paths,omitempty"`
	CORS              *CORS `json:"cors,omitempty"`
	// Compress gzip-compresses text responses (HTML, CSS, JS, JSON, SVG, XML, plain text) when the client
	// accepts it and the backend did not compress them already.
	Compress bool `json:"compress,omitempty"`
	// HSTS sends Strict-Transport-Security with this max-age (seconds) on HTTPS responses; 0 = off.
	HSTS           int  `json:"hsts,omitempty"`
	HSTSSubdomains bool `json:"hsts_subdomains,omitempty"`
	HSTSPreload    bool `json:"hsts_preload,omitempty"`
	// StripPrefix removes the route's path prefix before proxying: route /api, request /api/users →
	// backend /users (feature "strip-prefix"). Ignored for the whole-host route "/".
	StripPrefix bool `json:"strip_prefix,omitempty"`
	// Wake: the backend may be scaled to zero (feature "wake"). When it refuses connections the gateway
	// calls Wake.URL once and holds the request until the backend answers (or Wake.Timeout passes).
	Wake *Wake `json:"wake,omitempty"`

	allow []netip.Prefix // parsed AllowIPs
}

// Wake is how a sleeping backend is woken up.
type Wake struct {
	URL     string `json:"url"`               // called with POST; e.g. the panel's internal wake endpoint
	Timeout int    `json:"timeout,omitempty"` // seconds to hold requests while it starts (default 60, at most 300)
}

// RedirectRule redirects one path (Prefix=false) or every path under it (Prefix=true).
type RedirectRule struct {
	From   string `json:"from"`             // path, e.g. /old or /blog
	To     string `json:"to"`               // absolute URL or a path on the same host
	Code   int    `json:"code,omitempty"`   // 301 (default), 302, 307, 308
	Prefix bool   `json:"prefix,omitempty"` // also match /from/… and keep the rest of the path
}

// CORS answers preflight requests and adds the CORS headers for allowed origins.
type CORS struct {
	Origins     []string `json:"origins"`               // exact origins (https://app.example.com) or "*"
	Methods     []string `json:"methods,omitempty"`     // default GET, POST, PUT, PATCH, DELETE, OPTIONS
	Headers     []string `json:"headers,omitempty"`     // allowed request headers; default: whatever the preflight asks
	Expose      []string `json:"expose,omitempty"`      // Access-Control-Expose-Headers
	Credentials bool     `json:"credentials,omitempty"` // Access-Control-Allow-Credentials (not with "*")
	MaxAge      int      `json:"max_age,omitempty"`     // preflight cache, seconds (default 600)
}

// IsZero reports whether no option is set.
func (w *Web) IsZero() bool {
	return w == nil || (len(w.Redirects) == 0 && len(w.AllowIPs) == 0 && len(w.ResponseHeaders) == 0 &&
		len(w.RequestHeaders) == 0 && w.BackendHost == "" && !w.AllowScannerPaths && w.CORS == nil && !w.Compress && w.HSTS == 0 && !w.StripPrefix && w.Wake == nil)
}

var headerNameRe = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")

// backendHostRe: a DNS name or an IPv4 address (optionally with a port, checked separately).
var backendHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// hop-by-hop and framing headers the gateway manages itself.
var reservedHeaders = []string{"Connection", "Content-Length", "Transfer-Encoding", "Upgrade", "Host", "Te", "Trailer", "Keep-Alive"}

// Normalize validates the options and parses the allowlist.
func (w *Web) Normalize() error {
	if w == nil {
		return nil
	}
	if len(w.Redirects) > 100 {
		return errors.New("web.redirects: at most 100 rules")
	}
	if w.Wake != nil {
		u, err := url.Parse(w.Wake.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("web.wake.url must be an http(s) URL")
		}
		switch {
		case w.Wake.Timeout == 0:
			w.Wake.Timeout = 60
		case w.Wake.Timeout < 5 || w.Wake.Timeout > 300:
			return errors.New("web.wake.timeout must be 5–300 seconds")
		}
	}
	for i := range w.Redirects {
		r := &w.Redirects[i]
		r.From, r.To = strings.TrimSpace(r.From), strings.TrimSpace(r.To)
		if !strings.HasPrefix(r.From, "/") || strings.ContainsAny(r.From, " ?#") {
			return fmt.Errorf("web.redirects[%d]: from must be a path like /old-page", i)
		}
		if len(r.From) > 1 {
			r.From = strings.TrimSuffix(r.From, "/")
		}
		if r.To == "" {
			return fmt.Errorf("web.redirects[%d]: to is required", i)
		}
		if !strings.HasPrefix(r.To, "/") {
			u, err := url.Parse(r.To)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("web.redirects[%d]: to must be a path (/new) or an absolute http(s) URL", i)
			}
		}
		switch r.Code {
		case 0:
			r.Code = http.StatusMovedPermanently
		case 301, 302, 307, 308:
		default:
			return fmt.Errorf("web.redirects[%d]: code must be 301, 302, 307 or 308", i)
		}
	}
	if len(w.AllowIPs) > 200 {
		return errors.New("web.allow_ips: at most 200 entries")
	}
	w.allow = w.allow[:0]
	for i, s := range w.AllowIPs {
		s = strings.TrimSpace(s)
		w.AllowIPs[i] = s
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("web.allow_ips: %q is not an IP address or CIDR", s)
		}
		w.allow = append(w.allow, p)
	}
	for _, hm := range []map[string]string{w.ResponseHeaders, w.RequestHeaders} {
		if len(hm) > 50 {
			return errors.New("web: at most 50 headers")
		}
		for k, v := range hm {
			if !headerNameRe.MatchString(k) {
				return fmt.Errorf("web: invalid header name %q", k)
			}
			if slices.ContainsFunc(reservedHeaders, func(h string) bool { return strings.EqualFold(h, k) }) {
				return fmt.Errorf("web: header %s is managed by the gateway", k)
			}
			if strings.ContainsAny(v, "\r\n") || len(v) > 4096 {
				return fmt.Errorf("web: invalid value for header %s", k)
			}
		}
	}
	if w.BackendHost != "" {
		w.BackendHost = strings.ToLower(strings.TrimSpace(w.BackendHost))
		h := w.BackendHost
		if hh, port, err := net.SplitHostPort(h); err == nil {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("web: backend_host %q has a bad port", w.BackendHost)
			}
			h = hh
		}
		if len(w.BackendHost) > 253 || !backendHostRe.MatchString(h) {
			return fmt.Errorf("web: backend_host %q is not a host name", w.BackendHost)
		}
	}
	if c := w.CORS; c != nil {
		if len(c.Origins) == 0 {
			return errors.New("web.cors: at least one origin (or \"*\")")
		}
		for i, o := range c.Origins {
			o = strings.TrimSuffix(strings.TrimSpace(o), "/")
			c.Origins[i] = o
			if o == "*" {
				if c.Credentials {
					return errors.New("web.cors: credentials cannot be used with origin \"*\"")
				}
				continue
			}
			u, err := url.Parse(o)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
				return fmt.Errorf("web.cors: origin %q must look like https://app.example.com", o)
			}
		}
		for i, m := range c.Methods {
			c.Methods[i] = strings.ToUpper(strings.TrimSpace(m))
			if !headerNameRe.MatchString(c.Methods[i]) {
				return fmt.Errorf("web.cors: invalid method %q", m)
			}
		}
		for _, list := range [][]string{c.Headers, c.Expose} {
			for _, h := range list {
				if h != "*" && !headerNameRe.MatchString(strings.TrimSpace(h)) {
					return fmt.Errorf("web.cors: invalid header name %q", h)
				}
			}
		}
		if c.MaxAge < 0 || c.MaxAge > 86400 {
			return errors.New("web.cors: max_age must be 0–86400")
		}
	}
	if w.HSTS < 0 || w.HSTS > 2*365*86400 {
		return errors.New("web.hsts: max-age must be 0–63072000 seconds")
	}
	if w.HSTSPreload && (w.HSTS < 365*86400 || !w.HSTSSubdomains) {
		return errors.New("web.hsts: preload needs a max-age of at least one year and include subdomains")
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Allowed reports whether a client IP may use the route.
func (w *Web) Allowed(ip string) bool {
	if w == nil || len(w.AllowIPs) == 0 {
		return true
	}
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range w.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// MatchRedirect returns the redirect for a request path, if a rule matches. A relative target keeps
// the request's host.
func (w *Web) MatchRedirect(path, rawQuery string) (target string, code int, ok bool) {
	if w == nil {
		return "", 0, false
	}
	for _, r := range w.Redirects {
		rest, hit := "", false
		switch {
		case path == r.From || (r.From != "/" && path == r.From+"/"):
			hit = true
		case r.Prefix && r.From == "/":
			hit, rest = true, strings.TrimPrefix(path, "/")
		case r.Prefix && strings.HasPrefix(path, r.From+"/"):
			hit, rest = true, strings.TrimPrefix(path, r.From+"/")
		}
		if !hit {
			continue
		}
		target = r.To
		if rest != "" {
			target = strings.TrimSuffix(target, "/") + "/" + rest
		}
		if rawQuery != "" && !strings.Contains(target, "?") {
			target += "?" + rawQuery
		}
		return target, r.Code, true
	}
	return "", 0, false
}

func encodeWeb(w *Web) string {
	if w.IsZero() {
		return ""
	}
	b, _ := json.Marshal(w)
	return string(b)
}

func decodeWeb(s string) *Web {
	if s == "" {
		return nil
	}
	w := &Web{}
	if err := json.Unmarshal([]byte(s), w); err != nil {
		return nil
	}
	_ = w.Normalize()
	return w
}
