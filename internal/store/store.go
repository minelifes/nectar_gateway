package store

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	ModeProxy  = "proxy"
	ModeStatic = "static"
)

type Route struct {
	ID         int64  `json:"id"`
	Domain     string `json:"domain"`
	Mode       string `json:"mode"` // "proxy" | "static"
	TargetIP    string `json:"target_ip"`
	TargetPort  int    `json:"target_port"`
	TargetHTTPS bool   `json:"target_https"` // connect to the backend over HTTPS
	StaticDir  string `json:"static_dir"`
	RateLimit  int    `json:"rate_limit"` // max requests/sec per IP (0 = unlimited)
	CertFile   string `json:"cert_file"` // path to fullchain PEM; enables HTTPS for the domain
	KeyFile    string `json:"key_file"`  // path to private key PEM
	ForceSSL   bool   `json:"force_ssl"` // redirect HTTP -> HTTPS
}

// HasSSL reports whether the route has a certificate configured.
func (r Route) HasSSL() bool { return r.CertFile != "" && r.KeyFile != "" }

type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Store struct {
	db      *sql.DB
	mu      sync.RWMutex
	cache   map[string]Route     // domain -> route
	blocked map[string]BlockedIP // ip -> block
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS routes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		mode TEXT NOT NULL DEFAULT 'proxy',
		target_ip TEXT NOT NULL DEFAULT '',
		target_port INTEGER NOT NULL DEFAULT 80,
		target_https INTEGER NOT NULL DEFAULT 0,
		rate_limit INTEGER NOT NULL DEFAULT 0,
		static_dir TEXT NOT NULL DEFAULT '',
		cert_file TEXT NOT NULL DEFAULT '',
		key_file TEXT NOT NULL DEFAULT '',
		force_ssl INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return nil, err
	}
	// migrations for older DBs (errors ignored if columns exist)
	db.Exec(`ALTER TABLE routes ADD COLUMN mode TEXT NOT NULL DEFAULT 'proxy'`)
	db.Exec(`ALTER TABLE routes ADD COLUMN static_dir TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE routes ADD COLUMN cert_file TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE routes ADD COLUMN key_file TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE routes ADD COLUMN force_ssl INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE routes ADD COLUMN target_https INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE routes ADD COLUMN rate_limit INTEGER NOT NULL DEFAULT 0`)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS blocked_ips (
		ip TEXT PRIMARY KEY,
		reason TEXT NOT NULL DEFAULT '',
		blocked_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	)`); err != nil {
		return nil, err
	}
	s := &Store{db: db, cache: map[string]Route{}, blocked: map[string]BlockedIP{}}
	if err := s.reload(); err != nil {
		return nil, err
	}
	if err := s.loadBlocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// ---- IP blocklist ----

func (s *Store) loadBlocked() error {
	s.db.Exec(`DELETE FROM blocked_ips WHERE expires_at < ?`, time.Now().Unix())
	rows, err := s.db.Query(`SELECT ip, reason, blocked_at, expires_at FROM blocked_ips`)
	if err != nil {
		return err
	}
	defer rows.Close()
	blocked := map[string]BlockedIP{}
	for rows.Next() {
		var b BlockedIP
		var at, exp int64
		if err := rows.Scan(&b.IP, &b.Reason, &at, &exp); err != nil {
			return err
		}
		b.BlockedAt, b.ExpiresAt = time.Unix(at, 0), time.Unix(exp, 0)
		blocked[b.IP] = b
	}
	s.mu.Lock()
	s.blocked = blocked
	s.mu.Unlock()
	return nil
}

// IsBlocked reports whether the IP is currently blocked.
func (s *Store) IsBlocked(ip string) bool {
	s.mu.RLock()
	b, ok := s.blocked[ip]
	s.mu.RUnlock()
	return ok && time.Now().Before(b.ExpiresAt)
}

// Block blocks an IP for the given duration.
func (s *Store) Block(ip, reason string, d time.Duration) error {
	now := time.Now()
	b := BlockedIP{IP: ip, Reason: reason, BlockedAt: now, ExpiresAt: now.Add(d)}
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at) VALUES (?, ?, ?, ?)`,
		b.IP, b.Reason, b.BlockedAt.Unix(), b.ExpiresAt.Unix()); err != nil {
		return err
	}
	s.mu.Lock()
	s.blocked[ip] = b
	s.mu.Unlock()
	return nil
}

// Unblock removes an IP from the blocklist.
func (s *Store) Unblock(ip string) error {
	if _, err := s.db.Exec(`DELETE FROM blocked_ips WHERE ip = ?`, ip); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.blocked, ip)
	s.mu.Unlock()
	return nil
}

// ListBlocked returns currently active blocks and prunes expired ones.
func (s *Store) ListBlocked() []BlockedIP {
	now := time.Now()
	s.db.Exec(`DELETE FROM blocked_ips WHERE expires_at < ?`, now.Unix())
	s.mu.Lock()
	out := make([]BlockedIP, 0, len(s.blocked))
	for ip, b := range s.blocked {
		if now.After(b.ExpiresAt) {
			delete(s.blocked, ip)
			continue
		}
		out = append(out, b)
	}
	s.mu.Unlock()
	return out
}

func (s *Store) reload() error {
	rows, err := s.db.Query(`SELECT id, domain, mode, target_ip, target_port, target_https, rate_limit, static_dir, cert_file, key_file, force_ssl FROM routes`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cache := map[string]Route{}
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.Domain, &r.Mode, &r.TargetIP, &r.TargetPort, &r.TargetHTTPS, &r.RateLimit, &r.StaticDir, &r.CertFile, &r.KeyFile, &r.ForceSSL); err != nil {
			return err
		}
		cache[r.Domain] = r
	}
	s.mu.Lock()
	s.cache = cache
	s.mu.Unlock()
	return nil
}

// Lookup returns the route for a domain (case-insensitive), if any.
func (s *Store) Lookup(domain string) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cache[strings.ToLower(domain)]
	return r, ok
}

// Get returns the route with the given id.
func (s *Store) Get(id int64) (Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.cache {
		if r.ID == id {
			return r, true
		}
	}
	return Route{}, false
}

func (s *Store) List() ([]Route, error) {
	rows, err := s.db.Query(`SELECT id, domain, mode, target_ip, target_port, target_https, rate_limit, static_dir, cert_file, key_file, force_ssl FROM routes ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Route{}
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.Domain, &r.Mode, &r.TargetIP, &r.TargetPort, &r.TargetHTTPS, &r.RateLimit, &r.StaticDir, &r.CertFile, &r.KeyFile, &r.ForceSSL); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func normalize(r *Route) error {
	r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
	r.TargetIP = strings.TrimSpace(r.TargetIP)
	r.StaticDir = strings.TrimSpace(r.StaticDir)
	if r.Mode == "" {
		r.Mode = ModeProxy
	}
	if r.Domain == "" {
		return errors.New("domain is required")
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
	default:
		return errors.New("mode must be 'proxy' or 'static'")
	}
	if r.RateLimit < 0 {
		r.RateLimit = 0
	}
	r.CertFile = strings.TrimSpace(r.CertFile)
	r.KeyFile = strings.TrimSpace(r.KeyFile)
	if (r.CertFile == "") != (r.KeyFile == "") {
		return errors.New("cert_file and key_file must be set together")
	}
	if r.ForceSSL && !r.HasSSL() {
		return errors.New("force_ssl requires cert_file and key_file")
	}
	return nil
}

func (s *Store) Create(r *Route) error {
	if err := normalize(r); err != nil {
		return err
	}
	res, err := s.db.Exec(`INSERT INTO routes (domain, mode, target_ip, target_port, target_https, rate_limit, static_dir, cert_file, key_file, force_ssl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Domain, r.Mode, r.TargetIP, r.TargetPort, r.TargetHTTPS, r.RateLimit, r.StaticDir, r.CertFile, r.KeyFile, r.ForceSSL)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return s.reload()
}

func (s *Store) Update(r *Route) error {
	if err := normalize(r); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE routes SET domain=?, mode=?, target_ip=?, target_port=?, target_https=?, rate_limit=?, static_dir=?, cert_file=?, key_file=?, force_ssl=? WHERE id=?`,
		r.Domain, r.Mode, r.TargetIP, r.TargetPort, r.TargetHTTPS, r.RateLimit, r.StaticDir, r.CertFile, r.KeyFile, r.ForceSSL, r.ID)
	if err != nil {
		return err
	}
	return s.reload()
}

func (s *Store) Delete(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM routes WHERE id=?`, id); err != nil {
		return err
	}
	return s.reload()
}
