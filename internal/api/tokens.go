package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Token auth for the mobile app.
//
//   - access token:  random, 15 min, kept in memory, sent as "Authorization: Bearer".
//   - refresh token: random, 30 days sliding expiry, only its SHA-256 is stored
//     in SQLite (survives restarts). It is NOT rotated on use, so the app's
//     foreground and background isolates can refresh concurrently without
//     invalidating each other.
const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 30 * 24 * time.Hour
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return hex.EncodeToString(b)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds until the access token expires
	TokenType    string `json:"token_type"`
}

func (s *Server) newAccessToken() string {
	tok := randomToken()
	now := time.Now()
	s.mu.Lock()
	for t, exp := range s.access { // prune expired
		if now.After(exp) {
			delete(s.access, t)
		}
	}
	s.access[tok] = now.Add(accessTTL)
	s.mu.Unlock()
	return tok
}

func (s *Server) validAccess(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.access[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.access, tok)
		return false
	}
	return true
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	return "", false
}

// POST /api/auth/login {username, password}
func (s *Server) tokenLogin(w http.ResponseWriter, r *http.Request) {
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

	refresh := randomToken()
	if err := s.store.CreateRefreshToken(hashToken(refresh), refreshTTL); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  s.newAccessToken(),
		RefreshToken: refresh,
		ExpiresIn:    int(accessTTL.Seconds()),
		TokenType:    "Bearer",
	})
}

// POST /api/auth/refresh {refresh_token}
// 401 means the refresh token is invalid/expired (the app must log in again);
// any other status is a transient failure and must NOT log the user out.
func (s *Server) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token required"})
		return
	}
	ok, err := s.store.TouchRefreshToken(hashToken(req.RefreshToken), refreshTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  s.newAccessToken(),
		RefreshToken: req.RefreshToken,
		ExpiresIn:    int(accessTTL.Seconds()),
		TokenType:    "Bearer",
	})
}

// POST /api/auth/logout {refresh_token}
func (s *Server) tokenLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.RefreshToken != "" {
		_ = s.store.DeleteRefreshToken(hashToken(req.RefreshToken))
	}
	if tok, ok := bearerToken(r); ok {
		s.mu.Lock()
		delete(s.access, tok)
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- failed-login limiter (shared by web and mobile login) ----

const (
	maxLoginFailures = 10
	loginFailWindow  = 15 * time.Minute
)

type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*failWindow
}

type failWindow struct {
	count int
	start time.Time
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{fails: map[string]*failWindow{}} }

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	if f == nil {
		return true
	}
	if time.Since(f.start) > loginFailWindow {
		delete(l.fails, ip)
		return true
	}
	return f.count < maxLoginFailures
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 10000 { // keep the map bounded
		for k, f := range l.fails {
			if time.Since(f.start) > loginFailWindow {
				delete(l.fails, k)
			}
		}
	}
	f := l.fails[ip]
	if f == nil || time.Since(f.start) > loginFailWindow {
		l.fails[ip] = &failWindow{count: 1, start: time.Now()}
		return
	}
	f.count++
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.fails, ip)
	l.mu.Unlock()
}

func clientHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
