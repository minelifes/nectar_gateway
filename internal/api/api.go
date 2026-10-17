package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/nginx"
	"nectar_gateway/internal/store"
)

const sessionCookie = "nectar_session"
const sessionTTL = 24 * time.Hour

type Server struct {
	store    *store.Store
	user     string
	pass     string
	ui       fs.FS
	certbot  certbot.Config
	health   *health.Checker
	mu       sync.Mutex
	sessions map[string]time.Time // web cookie session token -> expiry
	access   map[string]time.Time // mobile access token -> expiry
	limiter  *loginLimiter
}

func New(s *store.Store, user, pass string, ui fs.FS, cb certbot.Config, hc *health.Checker) *Server {
	return &Server{
		store: s, user: user, pass: pass, ui: ui, certbot: cb, health: hc,
		sessions: map[string]time.Time{},
		access:   map[string]time.Time{},
		limiter:  newLoginLimiter(),
	}
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
	mux.Handle("/", s.uiHandler())
	return mux
}

// ---- auth ----

func (s *Server) authed(r *http.Request) bool {
	if s.user == "" { // auth disabled
		return true
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
	if subtle.ConstantTimeCompare([]byte(creds.Username), []byte(s.user)) != 1 ||
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

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, routes)
}

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) {
	var rt store.Route
	if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.Create(&rt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, rt)
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var rt store.Route
	if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rt.ID = id
	if err := s.store.Update(&rt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, rt)
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
	rt, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
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
	if err := s.store.Delete(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
