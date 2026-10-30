package store

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Route maps a host (and optional path prefix) to a backend or a static directory.
type Route struct {
	ID          int64  `json:"id"`
	Domain      string `json:"domain"`      // exact host or wildcard "*.example.com"
	PathPrefix  string `json:"path_prefix"` // "/" = whole host; longest prefix wins
	Mode        string `json:"mode"`        // "proxy" | "static"
	TargetIP    string `json:"target_ip"`   // IP or DNS name (e.g. svc.ns.svc.cluster.local)
	TargetPort  int    `json:"target_port"`
	TargetHTTPS bool   `json:"target_https"` // connect to the backend over HTTPS
	StaticDir   string `json:"static_dir"`
	RateLimit   int    `json:"rate_limit"`  // max requests/sec per IP (0 = unlimited)
	HCEnabled   bool   `json:"hc_enabled"`  // health check enabled
	HCPath      string `json:"hc_path"`     // path to probe, e.g. /health
	HCInterval  int    `json:"hc_interval"` // seconds between checks
	HCType      string `json:"hc_type"`     // "status" | "contains" | "json"
	HCExpect    string `json:"hc_expect"`   // expectation, meaning depends on hc_type
	CertFile    string `json:"cert_file"`   // path to fullchain PEM; enables HTTPS for the domain
	KeyFile     string `json:"key_file"`    // path to private key PEM
	ForceSSL    bool   `json:"force_ssl"`   // redirect HTTP -> HTTPS
	// ManagedBy marks routes owned by an external controller (e.g. "nectar-apps"). Only that
	// controller (service token) may change them; the UI shows them read-only.
	ManagedBy string `json:"managed_by"`
	// Owner is a free-form reference used by the controller (e.g. "prj-shop/api/3").
	Owner string `json:"owner"`
	// Stored certificate (uploaded or issued by the built-in ACME client). The key never leaves the gateway.
	CertPEM      string `json:"-"`
	KeyPEM       string `json:"-"`
	CertSource   string `json:"cert_source"`    // "" | "file" | "upload" | "acme"
	CertNotAfter int64  `json:"cert_not_after"` // unix seconds, 0 = no stored cert
	ACME         bool   `json:"acme"`           // obtain and renew a Let's Encrypt certificate automatically
	Maintenance  bool   `json:"maintenance"`    // serve the maintenance page instead of proxying
	// BackendProtocol is "http1" (default) or "h2c" (cleartext HTTP/2, needed for gRPC backends).
	BackendProtocol string `json:"backend_protocol"`
	// TimeoutSeconds limits how long the backend may take to send response headers (0 = 60s default).
	// Streaming responses and WebSockets are not cut off once headers have arrived.
	TimeoutSeconds int `json:"timeout_seconds"`
	// MaxBodyMB limits request bodies (0 = unlimited); larger requests get 413.
	MaxBodyMB int `json:"max_body_mb"`
	// RedirectURL is the target for mode "redirect", e.g. "https://example.com". The request path and
	// query are appended unless the URL already has a path other than "/".
	RedirectURL  string `json:"redirect_url"`
	RedirectCode int    `json:"redirect_code"` // 301 (default), 302, 307 or 308
	// BasicAuth protects the route with HTTP basic auth: htpasswd lines "user:<bcrypt hash>".
	// Set it with basic_auth_users (plain passwords are hashed by the gateway); it is never sent back.
	BasicAuth      string     `json:"-"`
	BasicAuthUsers []AuthUser `json:"basic_auth_users,omitempty"`
	// BasicAuthHtpasswd sets BasicAuth from htpasswd lines with bcrypt hashes (write-only; used by
	// controllers that keep their own hashes, e.g. nectar-apps). Takes precedence over basic_auth_users.
	BasicAuthHtpasswd *string `json:"basic_auth_htpasswd,omitempty"`
	// AuthUsernames lists the users allowed by BasicAuth (read-only).
	AuthUsernames []string `json:"auth_usernames,omitempty"`
	// AuthFingerprint identifies the current BasicAuth content (first 16 hex chars of its SHA-256,
	// "" = no basic auth) so controllers can detect drift without seeing the hashes.
	AuthFingerprint string `json:"auth_fingerprint,omitempty"`
	UpdatedAt       int64  `json:"updated_at"`
	// CoveredBy / CoveredUntil (read-only, API responses only): the standalone certificate (e.g. a
	// wildcard) that serves this host because the route has no certificate of its own.
	CoveredBy    string `json:"covered_by,omitempty"`
	CoveredUntil int64  `json:"covered_until,omitempty"`
	// Web: redirect rules, IP allowlist, headers, CORS, compression, HSTS. Omitted in an update = keep.
	Web *Web `json:"web,omitempty"`
}

// AuthUser is a basic-auth user in API requests. An empty password keeps the user's current password.
type AuthUser struct {
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
}

// HasSSL reports whether the route has a certificate configured.
func (r Route) HasSSL() bool {
	return (r.CertFile != "" && r.KeyFile != "") || (r.CertPEM != "" && r.KeyPEM != "")
}

const routeCols = `id, domain, path_prefix, mode, target_ip, target_port, target_https, rate_limit, hc_enabled, hc_path,
	hc_interval, hc_type, hc_expect, static_dir, cert_file, key_file, force_ssl, managed_by, owner, cert_pem, key_pem,
	cert_source, cert_not_after, acme, maintenance, backend_protocol, timeout_seconds, max_body_mb, redirect_url,
	redirect_code, basic_auth, updated_at, web`

func scanRoute(sc interface{ Scan(...any) error }) (Route, error) {
	var r Route
	var web string
	err := sc.Scan(&r.ID, &r.Domain, &r.PathPrefix, &r.Mode, &r.TargetIP, &r.TargetPort, &r.TargetHTTPS, &r.RateLimit,
		&r.HCEnabled, &r.HCPath, &r.HCInterval, &r.HCType, &r.HCExpect, &r.StaticDir, &r.CertFile, &r.KeyFile, &r.ForceSSL,
		&r.ManagedBy, &r.Owner, &r.CertPEM, &r.KeyPEM, &r.CertSource, &r.CertNotAfter, &r.ACME, &r.Maintenance,
		&r.BackendProtocol, &r.TimeoutSeconds, &r.MaxBodyMB, &r.RedirectURL, &r.RedirectCode, &r.BasicAuth, &r.UpdatedAt, &web)
	r.Web = decodeWeb(web)
	r.AuthUsernames = authUsernames(r.BasicAuth)
	r.AuthFingerprint = AuthFingerprint(r.BasicAuth)
	return r, err
}

// AuthFingerprint returns the drift fingerprint of htpasswd text ("" when empty).
func AuthFingerprint(htpasswd string) string {
	if htpasswd == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(htpasswd))
	return hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------- lookup --

// routeTable indexes routes for the proxy hot path.
type routeTable struct {
	exact    map[string][]Route // host → routes, longest prefix first
	wildcard map[string][]Route // parent domain ("example.com" for "*.example.com") → routes
	byID     map[int64]Route
}

func buildTable(routes []Route) routeTable {
	t := routeTable{exact: map[string][]Route{}, wildcard: map[string][]Route{}, byID: map[int64]Route{}}
	for _, r := range routes {
		t.byID[r.ID] = r
		if parent, ok := strings.CutPrefix(r.Domain, "*."); ok {
			t.wildcard[parent] = append(t.wildcard[parent], r)
		} else {
			t.exact[r.Domain] = append(t.exact[r.Domain], r)
		}
	}
	for _, m := range []map[string][]Route{t.exact, t.wildcard} {
		for k := range m {
			sort.SliceStable(m[k], func(i, j int) bool { return len(m[k][i].PathPrefix) > len(m[k][j].PathPrefix) })
		}
	}
	return t
}

// hostRoutes returns the routes for a host: exact match, else the nearest wildcard.
func (t routeTable) hostRoutes(host string) []Route {
	if rs, ok := t.exact[host]; ok {
		return rs
	}
	// *.example.com matches a.example.com (one label), like TLS wildcard certificates
	if _, parent, ok := strings.Cut(host, "."); ok {
		return t.wildcard[parent]
	}
	return nil
}

func prefixMatches(prefix, path string) bool {
	if prefix == "/" || prefix == path {
		return true
	}
	p := strings.TrimSuffix(prefix, "/")
	return strings.HasPrefix(path, p+"/") || path == p
}

// Lookup returns the route for a host and request path (longest matching prefix).
func (s *Store) Lookup(host, path string) (Route, bool) {
	host = strings.ToLower(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.table.hostRoutes(host) {
		if prefixMatches(r.PathPrefix, path) {
			return r, true
		}
	}
	return Route{}, false
}

// KnownHost reports whether any route serves the host (used for unknown-domain handling).
func (s *Store) KnownHost(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.table.hostRoutes(strings.ToLower(host))) > 0
}

// WithCoverage fills CoveredBy/CoveredUntil of routes without a certificate of their own.
func (s *Store) WithCoverage(routes []Route) []Route {
	for i := range routes {
		if routes[i].HasSSL() {
			continue
		}
		if c, ok := s.CoveringCertificate(routes[i].Domain); ok {
			routes[i].CoveredBy, routes[i].CoveredUntil = c.Domain, c.NotAfter
		}
	}
	return routes
}

// CertRoute returns a route of the host that has a certificate (TLS works per host, not per path).
func (s *Store) CertRoute(host string) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.table.hostRoutes(strings.ToLower(host)) {
		if r.HasSSL() {
			return r, true
		}
	}
	return Route{}, false
}

// Get returns the route with the given id.
func (s *Store) Get(id int64) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.table.byID[id]
	return r, ok
}

// All returns every cached route (unordered).
func (s *Store) All() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Route, 0, len(s.table.byID))
	for _, r := range s.table.byID {
		out = append(out, r)
	}
	return out
}

func (s *Store) reload() error {
	rows, err := s.db.Query(`SELECT ` + routeCols + ` FROM routes`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var routes []Route
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return err
		}
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	t := buildTable(routes)
	s.mu.Lock()
	s.table = t
	s.mu.Unlock()
	return nil
}

// ------------------------------------------------------------------ CRUD --

// Filter selects routes in List.
type Filter struct {
	ManagedBy *string // nil = any; "" = unmanaged only
	Owner     string
}

// List returns routes ordered by domain and path, optionally filtered.
func (s *Store) List(f ...Filter) ([]Route, error) {
	q, args := `SELECT `+routeCols+` FROM routes WHERE 1=1`, []any{}
	if len(f) > 0 {
		if f[0].ManagedBy != nil {
			q += ` AND managed_by = ?`
			args = append(args, *f[0].ManagedBy)
		}
		if f[0].Owner != "" {
			q += ` AND owner = ?`
			args = append(args, f[0].Owner)
		}
	}
	rows, err := s.db.Query(q+` ORDER BY domain, path_prefix`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Route{}
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrConflict is returned when another route already serves the same host and path prefix.
var ErrConflict = errors.New("a route for this domain and path already exists")

func normalize(r *Route) error {
	r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
	r.TargetIP = strings.TrimSpace(r.TargetIP)
	r.StaticDir = strings.TrimSpace(r.StaticDir)
	r.PathPrefix = strings.TrimSpace(r.PathPrefix)
	if r.PathPrefix == "" {
		r.PathPrefix = "/"
	}
	if !strings.HasPrefix(r.PathPrefix, "/") {
		r.PathPrefix = "/" + r.PathPrefix
	}
	if len(r.PathPrefix) > 1 {
		r.PathPrefix = strings.TrimSuffix(r.PathPrefix, "/")
	}
	if r.Mode == "" {
		r.Mode = ModeProxy
	}
	if r.Domain == "" {
		return errors.New("domain is required")
	}
	if strings.ContainsAny(r.Domain, " /:") || (strings.Contains(r.Domain, "*") && !strings.HasPrefix(r.Domain, "*.")) || strings.Count(r.Domain, "*") > 1 {
		return errors.New("domain must be a host name like app.example.com or *.example.com")
	}
	switch r.Mode {
	case ModeProxy:
		if r.TargetIP == "" {
			return errors.New("target_ip is required for proxy mode")
		}
		if r.TargetPort <= 0 || r.TargetPort > 65535 {
			r.TargetPort = 80
		}
	case ModeStatic:
		if r.StaticDir == "" {
			return errors.New("static_dir is required for static mode")
		}
	case ModeRedirect:
		u, err := url.Parse(strings.TrimSpace(r.RedirectURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("redirect_url must be an absolute http(s) URL, e.g. https://example.com")
		}
		r.RedirectURL = strings.TrimSpace(r.RedirectURL)
		switch r.RedirectCode {
		case 0:
			r.RedirectCode = http.StatusMovedPermanently
		case 301, 302, 307, 308:
		default:
			return errors.New("redirect_code must be 301, 302, 307 or 308")
		}
	default:
		return errors.New("mode must be 'proxy', 'static' or 'redirect'")
	}
	switch r.BackendProtocol {
	case "":
		r.BackendProtocol = ProtoHTTP1
	case ProtoHTTP1, ProtoH2C:
	default:
		return errors.New("backend_protocol must be 'http1' or 'h2c'")
	}
	if r.BackendProtocol == ProtoH2C && r.TargetHTTPS {
		return errors.New("backend_protocol h2c is for plain-text backends; HTTPS backends negotiate HTTP/2 themselves")
	}
	if r.TimeoutSeconds < 0 || r.TimeoutSeconds > 3600 {
		return errors.New("timeout_seconds must be 0–3600")
	}
	if r.MaxBodyMB < 0 || r.MaxBodyMB > 100*1024 {
		return errors.New("max_body_mb must be 0–102400")
	}
	if err := applyAuthUsers(r); err != nil {
		return err
	}
	if err := r.Web.Normalize(); err != nil {
		return err
	}
	if r.Web.IsZero() {
		r.Web = nil
	}
	if r.RateLimit < 0 {
		r.RateLimit = 0
	}
	r.HCPath = strings.TrimSpace(r.HCPath)
	if r.HCPath == "" {
		r.HCPath = "/"
	} else if !strings.HasPrefix(r.HCPath, "/") {
		r.HCPath = "/" + r.HCPath
	}
	if r.HCInterval < 5 {
		r.HCInterval = 30
	}
	switch r.HCType {
	case "status", "contains", "json":
	default:
		r.HCType = "status"
	}
	r.CertFile = strings.TrimSpace(r.CertFile)
	r.KeyFile = strings.TrimSpace(r.KeyFile)
	if (r.CertFile == "") != (r.KeyFile == "") {
		return errors.New("cert_file and key_file must be set together")
	}
	if r.CertFile != "" && r.CertSource == "" {
		r.CertSource = "file"
	}
	if r.ForceSSL && !r.HasSSL() && !r.ACME {
		return errNeedCert
	}
	return nil
}

// errNeedCert: force_ssl without a certificate. Create/Update accept it when a standalone certificate
// (e.g. a wildcard) covers the host.
var errNeedCert = errors.New("force_ssl requires a certificate (cert files, an uploaded certificate, acme or a covering wildcard certificate)")

func (s *Store) normalizeRoute(r *Route) error {
	err := normalize(r)
	if errors.Is(err, errNeedCert) {
		if _, ok := s.CoveringCertificate(r.Domain); ok {
			return nil
		}
	}
	return err
}

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

// Create inserts a route.
func (s *Store) Create(r *Route) error {
	if err := s.normalizeRoute(r); err != nil {
		return err
	}
	r.UpdatedAt = time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO routes (domain, path_prefix, mode, target_ip, target_port, target_https, rate_limit,
		hc_enabled, hc_path, hc_interval, hc_type, hc_expect, static_dir, cert_file, key_file, force_ssl, managed_by, owner,
		cert_pem, key_pem, cert_source, cert_not_after, acme, maintenance, backend_protocol, timeout_seconds, max_body_mb,
		redirect_url, redirect_code, basic_auth, updated_at, web)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Domain, r.PathPrefix, r.Mode, r.TargetIP, r.TargetPort, r.TargetHTTPS, r.RateLimit, r.HCEnabled, r.HCPath,
		r.HCInterval, r.HCType, r.HCExpect, r.StaticDir, r.CertFile, r.KeyFile, r.ForceSSL, r.ManagedBy, r.Owner,
		r.CertPEM, r.KeyPEM, r.CertSource, r.CertNotAfter, r.ACME, r.Maintenance, r.BackendProtocol, r.TimeoutSeconds,
		r.MaxBodyMB, r.RedirectURL, r.RedirectCode, r.BasicAuth, r.UpdatedAt, encodeWeb(r.Web))
	if isUnique(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return s.reload()
}

// Update replaces a route's settings. Stored certificates are kept unless the caller changes them
// with SetCert (the JSON API never sends PEMs).
func (s *Store) Update(r *Route) error {
	if old, ok := s.Get(r.ID); ok {
		// basic_auth_users omitted → keep the current users; present → passwords of listed users
		// without a new password are kept (applyAuthUsers looks them up in r.BasicAuth)
		r.BasicAuth = old.BasicAuth
		if r.Web == nil {
			r.Web = old.Web // "web" omitted → keep the current options
		}
	}
	if old, ok := s.Get(r.ID); ok && r.CertPEM == "" && r.KeyPEM == "" {
		r.CertPEM, r.KeyPEM = old.CertPEM, old.KeyPEM
		if r.CertSource == "" || r.CertSource == old.CertSource {
			r.CertSource, r.CertNotAfter = old.CertSource, old.CertNotAfter
		}
	}
	if err := s.normalizeRoute(r); err != nil {
		return err
	}
	r.UpdatedAt = time.Now().Unix()
	res, err := s.db.Exec(`UPDATE routes SET domain=?, path_prefix=?, mode=?, target_ip=?, target_port=?, target_https=?,
		rate_limit=?, hc_enabled=?, hc_path=?, hc_interval=?, hc_type=?, hc_expect=?, static_dir=?, cert_file=?, key_file=?,
		force_ssl=?, managed_by=?, owner=?, cert_pem=?, key_pem=?, cert_source=?, cert_not_after=?, acme=?, maintenance=?,
		backend_protocol=?, timeout_seconds=?, max_body_mb=?, redirect_url=?, redirect_code=?, basic_auth=?,
		updated_at=?, web=? WHERE id=?`,
		r.Domain, r.PathPrefix, r.Mode, r.TargetIP, r.TargetPort, r.TargetHTTPS, r.RateLimit, r.HCEnabled, r.HCPath,
		r.HCInterval, r.HCType, r.HCExpect, r.StaticDir, r.CertFile, r.KeyFile, r.ForceSSL, r.ManagedBy, r.Owner,
		r.CertPEM, r.KeyPEM, r.CertSource, r.CertNotAfter, r.ACME, r.Maintenance, r.BackendProtocol, r.TimeoutSeconds,
		r.MaxBodyMB, r.RedirectURL, r.RedirectCode, r.BasicAuth, r.UpdatedAt, encodeWeb(r.Web), r.ID)
	if isUnique(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return s.reload()
}

// Delete removes a route.
func (s *Store) Delete(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM routes WHERE id=?`, id); err != nil {
		return err
	}
	return s.reload()
}

// ParseCertPair validates a PEM certificate chain + private key and returns the leaf's expiry
// and the DNS names it covers.
func ParseCertPair(certPEM, keyPEM string) (notAfter time.Time, names []string, err error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("invalid certificate or key: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return time.Time{}, nil, errors.New("invalid certificate PEM")
		}
		if leaf, err = x509.ParseCertificate(block.Bytes); err != nil {
			return time.Time{}, nil, err
		}
	}
	return leaf.NotAfter, leaf.DNSNames, nil
}

// SetCert stores a certificate on every route of the route's host (TLS is per host).
func (s *Store) SetCert(id int64, certPEM, keyPEM, source string) (Route, error) {
	r, ok := s.Get(id)
	if !ok {
		return Route{}, sql.ErrNoRows
	}
	notAfter, names, err := ParseCertPair(certPEM, keyPEM)
	if err != nil {
		return Route{}, err
	}
	if !certCovers(names, r.Domain) {
		return Route{}, fmt.Errorf("certificate does not cover %s (it is for %s)", r.Domain, strings.Join(names, ", "))
	}
	_, err = s.db.Exec(`UPDATE routes SET cert_pem=?, key_pem=?, cert_source=?, cert_not_after=?, cert_file='', key_file='', updated_at=? WHERE domain=?`,
		certPEM, keyPEM, source, notAfter.Unix(), time.Now().Unix(), r.Domain)
	if err != nil {
		return Route{}, err
	}
	if err := s.reload(); err != nil {
		return Route{}, err
	}
	r, _ = s.Get(id)
	return r, nil
}

// ClearCert removes stored certificates from the route's host.
func (s *Store) ClearCert(id int64) error {
	r, ok := s.Get(id)
	if !ok {
		return sql.ErrNoRows
	}
	if _, err := s.db.Exec(`UPDATE routes SET cert_pem='', key_pem='', cert_source='', cert_not_after=0, force_ssl=0, updated_at=? WHERE domain=?`,
		time.Now().Unix(), r.Domain); err != nil {
		return err
	}
	return s.reload()
}

func certCovers(names []string, host string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if parent, ok := strings.CutPrefix(n, "*."); ok {
			if _, rest, ok := strings.Cut(host, "."); ok && rest == parent && !strings.HasPrefix(host, "*.") {
				return true
			}
			if host == n {
				return true
			}
		}
	}
	return false
}

// ------------------------------------------------------------ basic auth --

func authUsernames(htpasswd string) []string {
	var out []string
	for _, line := range strings.Split(htpasswd, "\n") {
		if u, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && u != "" {
			out = append(out, u)
		}
	}
	return out
}

func authLookup(htpasswd, user string) (string, bool) {
	for _, line := range strings.Split(htpasswd, "\n") {
		if u, h, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && u == user {
			return h, true
		}
	}
	return "", false
}

// applyAuthUsers turns BasicAuthUsers (if given) into the htpasswd text in BasicAuth.
// nil BasicAuthUsers keeps BasicAuth; an empty list removes basic auth.
func applyAuthUsers(r *Route) error {
	defer func() { r.AuthUsernames, r.AuthFingerprint = authUsernames(r.BasicAuth), AuthFingerprint(r.BasicAuth) }()
	if r.BasicAuthHtpasswd != nil {
		var lines []string
		for _, line := range strings.Split(*r.BasicAuthHtpasswd, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			u, h, ok := strings.Cut(line, ":")
			if !ok || u == "" || strings.ContainsAny(u, " \t") || !(strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$")) {
				return errors.New("basic_auth_htpasswd: every line must be user:<bcrypt hash>")
			}
			if _, err := bcrypt.Cost([]byte(h)); err != nil {
				return fmt.Errorf("basic_auth_htpasswd: user %s: %v", u, err)
			}
			lines = append(lines, u+":"+h)
		}
		if len(lines) > 50 {
			return errors.New("at most 50 basic-auth users")
		}
		r.BasicAuth = strings.Join(lines, "\n")
		r.BasicAuthHtpasswd, r.BasicAuthUsers = nil, nil
		return nil
	}
	if r.BasicAuthUsers == nil {
		return nil
	}
	if len(r.BasicAuthUsers) > 50 {
		return errors.New("at most 50 basic-auth users")
	}
	var lines []string
	seen := map[string]bool{}
	for _, u := range r.BasicAuthUsers {
		name := strings.TrimSpace(u.User)
		if name == "" || strings.ContainsAny(name, ": \n\t") || len(name) > 64 {
			return fmt.Errorf("invalid basic-auth user name %q", u.User)
		}
		if seen[name] {
			return fmt.Errorf("duplicate basic-auth user %q", name)
		}
		seen[name] = true
		var hash string
		if u.Password == "" {
			h, ok := authLookup(r.BasicAuth, name)
			if !ok {
				return fmt.Errorf("basic-auth user %q needs a password", name)
			}
			hash = h
		} else {
			if len(u.Password) < 8 || len(u.Password) > 72 {
				return fmt.Errorf("basic-auth password for %q must be 8–72 characters", name)
			}
			b, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			hash = string(b)
		}
		lines = append(lines, name+":"+hash)
	}
	r.BasicAuth = strings.Join(lines, "\n")
	r.BasicAuthUsers = nil
	return nil
}

// CheckBasicAuth verifies a user/password against htpasswd text (bcrypt hashes only).
func CheckBasicAuth(htpasswd, user, password string) bool {
	h, ok := authLookup(htpasswd, user)
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil
}
