package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/metrics"
	"nectar_gateway/internal/nginx"
	"nectar_gateway/internal/settings"
	"nectar_gateway/internal/store"
)

const sessionCookie = "nectar_session"
const sessionTTL = 24 * time.Hour

// APIVersion is the major version of the admin API (bumped only on breaking changes).
const APIVersion = 1

// ManagedBy values that controllers use; routes with a non-empty managed_by are read-only for humans.
const managedReadOnly = "this route is managed by %s — change it there"

type Server struct {
	store    *store.Store
	user     string
	pass     string
	ui       fs.FS // nil = headless (API only)
	certbot  certbot.Config
	health   *health.Checker
	apiToken string // service token for controllers such as nectar-apps ("" = disabled)
	version  string
	issuer   CertIssuer // built-in ACME (nil = certbot only)
	metrics  *metrics.Recorder
	settings *settings.Settings // runtime settings (fallback upstream, …)
	mu       sync.Mutex
	sessions map[string]time.Time // web cookie session token -> expiry
	access   map[string]time.Time // mobile access token -> expiry
	limiter  *loginLimiter
}

// CertIssuer obtains certificates (implemented by the built-in ACME client).
type CertIssuer interface {
	Issue(ctx context.Context, domain string) (certPEM, keyPEM string, err error)
}

// Options are optional settings for New.
type Options struct {
	APIToken string     // GATEWAY_API_TOKEN
	Version  string     // build version
	Issuer   CertIssuer // built-in ACME client
	Metrics  *metrics.Recorder
	Settings *settings.Settings
}

func New(s *store.Store, user, pass string, ui fs.FS, cb certbot.Config, hc *health.Checker, opt ...Options) *Server {
	srv := &Server{
		store: s, user: user, pass: pass, ui: ui, certbot: cb, health: hc,
		sessions: map[string]time.Time{},
		access:   map[string]time.Time{},
		limiter:  newLoginLimiter(),
		version:  "dev",
	}
	if len(opt) > 0 {
		srv.apiToken, srv.issuer, srv.metrics, srv.settings = opt[0].APIToken, opt[0].Issuer, opt[0].Metrics, opt[0].Settings
		if opt[0].Version != "" {
			srv.version = opt[0].Version
		}
	}
	return srv
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("POST /api/auth/login", s.tokenLogin)
	mux.HandleFunc("POST /api/auth/refresh", s.tokenRefresh)
	mux.HandleFunc("POST /api/auth/logout", s.tokenLogout)
	mux.HandleFunc("GET /api/me", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"user": s.user})
	}))
	mux.HandleFunc("GET /api/routes", s.requireAuth(s.listRoutes))
	mux.HandleFunc("POST /api/routes", s.requireAuth(s.createRoute))
	mux.HandleFunc("PUT /api/routes/{id}", s.requireAuth(s.updateRoute))
	mux.HandleFunc("DELETE /api/routes/{id}", s.requireAuth(s.deleteRoute))
	mux.HandleFunc("POST /api/import/nginx", s.requireAuth(s.importNginx))
	mux.HandleFunc("POST /api/routes/{id}/cert", s.requireAuth(s.issueCert))
	mux.HandleFunc("GET /api/health", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.health.Snapshot())
	}))
	mux.HandleFunc("GET /api/blocked", s.requireAuth(s.listBlocked))
	mux.HandleFunc("DELETE /api/blocked/{ip}", s.requireAuth(s.unblockIP))
	mux.HandleFunc("POST /api/blocked", s.requireAuth(s.blockIP))
	mux.HandleFunc("GET /api/fallback-hits", s.requireAuth(s.getFallbackHits))
	mux.HandleFunc("DELETE /api/fallback-hits", s.requireAuth(s.resetFallbackHits))
	mux.HandleFunc("PUT /api/routes/{id}/cert", s.requireAuth(s.uploadCert))
	mux.HandleFunc("DELETE /api/routes/{id}/cert", s.requireAuth(s.deleteCert))
	mux.HandleFunc("GET /api/metrics", s.requireAuth(s.getMetrics))
	mux.HandleFunc("GET /api/access-log", s.requireAuth(s.getAccessLog))
	mux.HandleFunc("GET /api/settings", s.requireAuth(s.getSettings))
	mux.HandleFunc("PUT /api/settings", s.requireAuth(s.putSettings))
	mux.HandleFunc("GET /api/certificates", s.requireAuth(s.listCertificates))
	mux.HandleFunc("POST /api/certificates", s.requireAuth(s.createCertificate))
	mux.HandleFunc("PUT /api/certificates/{id}", s.requireAuth(s.uploadCertificatePair))
	mux.HandleFunc("POST /api/certificates/{id}/renew", s.requireAuth(s.renewCertificate))
	mux.HandleFunc("DELETE /api/certificates/{id}", s.requireAuth(s.deleteCertificate))

	// unauthenticated: probes and version discovery
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(); err != nil {
			http.Error(w, "database: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"version": s.version, "api_version": APIVersion, "headless": s.ui == nil, "features": s.features()})
	})

	if s.ui != nil {
		mux.Handle("/", s.uiHandler())
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "headless mode: the admin UI is disabled (ADMIN_UI=false)"})
		})
	}
	return mux
}

// ---- auth ----

// isService reports whether the request carries the controller service token.
func (s *Server) isService(r *http.Request) bool {
	tok, ok := bearerToken(r)
	return ok && s.apiToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.apiToken)) == 1
}

func (s *Server) authed(r *http.Request) bool {
	if s.isService(r) {
		return true
	}
	if s.user == "" {
		// no admin user: open only when no service token is configured either (legacy local setups);
		// with a token (headless/in-cluster) the token is the only way in
		return s.apiToken == ""
	}
	if tok, ok := bearerToken(r); ok { // mobile app
		return s.validAccess(tok)
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientHost(r)
	if !s.limiter.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts, try again later"})
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if s.user == "" || subtle.ConstantTimeCompare([]byte(creds.Username), []byte(s.user)) != 1 ||
		subtle.ConstantTimeCompare([]byte(creds.Password), []byte(s.pass)) != 1 {
		s.limiter.fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	s.limiter.reset(ip)
	buf := make([]byte, 32)
	rand.Read(buf)
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	for t, exp := range s.sessions { // prune expired
		if time.Now().After(exp) {
			delete(s.sessions, t)
		}
	}
	s.sessions[token] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"user": creds.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// ---- UI ----

func (s *Server) uiHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := s.ui.Open(path); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// ---- routes CRUD ----

// Features lists optional API parts, so controllers can tell what this gateway build supports.
func (s *Server) features() []string {
	f := []string{"certificates", "rate-limit-429"} // standalone / wildcard certificates; rate limits answer 429
	if ci := s.certIssuer(); ci != nil {
		f = append(f, "acme")
		if ci.HasDNS() {
			f = append(f, "dns-01")
		}
	}
	return f
}

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	var f store.Filter
	if q := r.URL.Query(); q.Has("managed_by") {
		m := q.Get("managed_by")
		f.ManagedBy = &m
	}
	f.Owner = r.URL.Query().Get("owner")
	routes, err := s.store.List(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.store.WithCoverage(routes))
}

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) {
	var rt store.Route
	if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if rt.ManagedBy != "" && !s.isService(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "managed routes can only be created with the service token"})
		return
	}
	if err := s.store.Create(&rt); err != nil {
		writeErr(w, routeErrStatus(err), err)
		return
	}
	s.autoIssue(rt)
	writeJSON(w, http.StatusCreated, s.store.WithCoverage([]store.Route{rt})[0])
}

func routeErrStatus(err error) int {
	if errors.Is(err, store.ErrConflict) {
		return http.StatusConflict
	}
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// guardManaged rejects changes to managed routes unless the caller is that controller.
func (s *Server) guardManaged(w http.ResponseWriter, r *http.Request, id int64) (store.Route, bool) {
	rt, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
		return rt, false
	}
	if rt.ManagedBy != "" && !s.isService(r) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf(managedReadOnly, rt.ManagedBy)})
		return rt, false
	}
	return rt, true
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, ok := s.guardManaged(w, r, id); !ok {
		return
	}
	var rt store.Route
	if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rt.ID = id
	if rt.ManagedBy != "" && !s.isService(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the service token can mark routes as managed"})
		return
	}
	if err := s.store.Update(&rt); err != nil {
		writeErr(w, routeErrStatus(err), err)
		return
	}
	s.autoIssue(rt)
	writeJSON(w, http.StatusOK, s.store.WithCoverage([]store.Route{rt})[0])
}

// importNginx parses an nginx config. With dry_run=true it only returns the
// preview; otherwise it creates the parsed routes (existing domains are skipped).
func (s *Server) importNginx(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
		DryRun bool   `json:"dry_run"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res, err := nginx.Parse(req.Config)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.DryRun {
		writeJSON(w, http.StatusOK, res)
		return
	}
	imported := []store.Route{}
	for i := range res.Routes {
		rt := res.Routes[i]
		if err := s.store.Create(&rt); err != nil {
			res.Skipped = append(res.Skipped, rt.Domain+": "+err.Error())
			continue
		}
		imported = append(imported, rt)
	}
	res.Routes = imported
	writeJSON(w, http.StatusOK, res)
}

// issueCert obtains a Let's Encrypt certificate for the route's domain via
// certbot (HTTP-01 webroot challenge) and stores the cert paths on the route.
func (s *Server) issueCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rt, ok := s.guardManaged(w, r, id)
	if !ok {
		return
	}
	if s.issuer != nil {
		log.Printf("acme: obtaining certificate for %s", rt.Domain)
		certPEM, keyPEM, err := s.issuer.Issue(r.Context(), rt.Domain)
		if err != nil {
			log.Printf("acme: %s: %v", rt.Domain, err)
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		updated, err := s.store.SetCert(id, certPEM, keyPEM, "acme")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		log.Printf("acme: issued certificate for %s", rt.Domain)
		writeJSON(w, http.StatusOK, updated)
		return
	}
	log.Printf("certbot: obtaining certificate for %s", rt.Domain)
	certFile, keyFile, err := s.certbot.Obtain(r.Context(), rt.Domain)
	if err != nil {
		log.Printf("certbot: %s: %v", rt.Domain, err)
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	log.Printf("certbot: issued certificate for %s", rt.Domain)
	rt.CertFile = certFile
	rt.KeyFile = keyFile
	if err := s.store.Update(&rt); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rt)
}

func (s *Server) listBlocked(w http.ResponseWriter, r *http.Request) {
	list := s.store.ListBlocked()
	sort.Slice(list, func(i, j int) bool { return list[i].BlockedAt.After(list[j].BlockedAt) })
	writeJSON(w, http.StatusOK, list)
}

// blockIP adds a block (used when importing a standalone gateway's blocklist, or by an admin).
// Body: {"ip": "1.2.3.4", "reason": "…", "ttl_seconds": 86400}; ttl_seconds 0 = 10 years.
func (s *Server) blockIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP         string `json:"ip"`
		Reason     string `json:"reason"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ip := net.ParseIP(strings.TrimSpace(in.IP))
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip must be an IPv4 or IPv6 address"})
		return
	}
	ttl := time.Duration(in.TTLSeconds) * time.Second
	if in.TTLSeconds <= 0 {
		ttl = 10 * 365 * 24 * time.Hour
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		reason = "blocked by an administrator"
	}
	if err := s.store.Block(ip.String(), reason, ttl); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getFallbackHits lists hosts served by the fallback upstream / TLS passthrough (migration soak).
func (s *Server) getFallbackHits(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"hosts": orEmpty(s.metrics.FallbackHits())})
}

func (s *Server) resetFallbackHits(w http.ResponseWriter, r *http.Request) {
	s.metrics.ResetFallbackHits()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unblockIP(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Unblock(r.PathValue("ip")); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, ok := s.guardManaged(w, r, id); !ok {
		return
	}
	if err := s.store.Delete(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// uploadCert stores a PEM certificate + key for the route's host (G11).
func (s *Server) uploadCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, ok := s.guardManaged(w, r, id); !ok {
		return
	}
	var in struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rt, err := s.store.SetCert(id, in.CertPEM, in.KeyPEM, "upload")
	if err != nil {
		writeErr(w, routeErrStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, rt)
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, ok := s.guardManaged(w, r, id); !ok {
		return
	}
	if err := s.store.ClearCert(id); err != nil {
		writeErr(w, routeErrStatus(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// autoIssue starts a background certificate request for routes with acme=true and no valid cert.
func (s *Server) autoIssue(rt store.Route) {
	if s.issuer == nil || !rt.ACME {
		return
	}
	if ci := s.certIssuer(); strings.HasPrefix(rt.Domain, "*.") && (ci == nil || !ci.HasDNS()) {
		return
	}
	if existing, ok := s.store.CertRoute(rt.Domain); ok && existing.CertNotAfter > time.Now().Add(30*24*time.Hour).Unix() {
		return
	}
	// a wildcard (or exact) certificate already serves the host: no order of its own
	if c, ok := s.store.CoveringCertificate(rt.Domain); ok && c.NotAfter > time.Now().Add(30*24*time.Hour).Unix() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		certPEM, keyPEM, err := s.issuer.Issue(ctx, rt.Domain)
		if err != nil {
			log.Printf("acme: %s: %v", rt.Domain, err)
			return
		}
		if _, err := s.store.SetCert(rt.ID, certPEM, keyPEM, "acme"); err != nil {
			log.Printf("acme: store %s: %v", rt.Domain, err)
			return
		}
		log.Printf("acme: issued certificate for %s", rt.Domain)
	}()
}

// ---- metrics / access log (G14) ----

func (s *Server) getMetrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minutes, _ := strconv.Atoi(q.Get("minutes"))
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.metrics != nil,
		"domains": orEmpty(s.metrics.Summaries(minutes, q.Get("domain"), q.Get("series") == "1")),
	})
}

func orEmpty[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func (s *Server) getAccessLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit > 1000 {
		limit = 1000
	}
	status := 0
	switch v := strings.ToLower(q.Get("status")); {
	case len(v) == 3 && strings.HasSuffix(v, "xx"):
		status = int(v[0] - '0')
	case v != "":
		status, _ = strconv.Atoi(v)
	}
	writeJSON(w, http.StatusOK, orEmpty(s.metrics.Log(metrics.LogQuery{Domain: q.Get("domain"), Status: status, IP: q.Get("ip"), Limit: limit})))
}

// ---- runtime settings (G10 fallback) ----

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settings.Get().Public())
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "settings are not available"})
		return
	}
	v := s.settings.Get() // fields left out keep their value; dns_api_token is write-only
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.settings.Set(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	log.Printf("settings: fallback_http=%q fallback_tls=%q acme_email=%q dns_provider=%q rate_limit_block_minutes=%d", v.FallbackHTTP, v.FallbackTLS, v.ACMEEmail, v.DNSProvider, v.RateLimitBlockMinutes)
	writeJSON(w, http.StatusOK, s.settings.Get().Public())
}
