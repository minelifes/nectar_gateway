package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	ModeProxy    = "proxy"
	ModeStatic   = "static"
	ModeRedirect = "redirect" // answer with a redirect to RedirectURL (www ↔ apex, moved sites)
)

// Backend protocols.
const (
	ProtoHTTP1 = "http1" // HTTP/1.1 to the backend (default; WebSocket works)
	ProtoH2C   = "h2c"   // cleartext HTTP/2 to the backend (gRPC)
)

// BlockedIP is a temporarily blocked client address.
type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store is the gateway database plus in-memory caches used on the hot path.
type Store struct {
	db      *sql.DB
	mu      sync.RWMutex
	table   routeTable           // host → routes (longest path prefix first)
	blocked map[string]BlockedIP // ip -> block
}

// schemaVersion is stored in PRAGMA user_version.
const schemaVersion = 3

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; avoids SQLITE_BUSY between our goroutines
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	s := &Store{db: db, blocked: map[string]BlockedIP{}}
	if err := s.reload(); err != nil {
		return nil, err
	}
	if err := s.loadBlocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// Ping checks the database (readiness).
func (s *Store) Ping() error { return s.db.Ping() }

const routesTable = `CREATE TABLE routes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT NOT NULL,
	path_prefix TEXT NOT NULL DEFAULT '/',
	mode TEXT NOT NULL DEFAULT 'proxy',
	target_ip TEXT NOT NULL DEFAULT '',
	target_port INTEGER NOT NULL DEFAULT 80,
	target_https INTEGER NOT NULL DEFAULT 0,
	rate_limit INTEGER NOT NULL DEFAULT 0,
	hc_enabled INTEGER NOT NULL DEFAULT 0,
	hc_path TEXT NOT NULL DEFAULT '/',
	hc_interval INTEGER NOT NULL DEFAULT 30,
	hc_type TEXT NOT NULL DEFAULT 'status',
	hc_expect TEXT NOT NULL DEFAULT '',
	static_dir TEXT NOT NULL DEFAULT '',
	cert_file TEXT NOT NULL DEFAULT '',
	key_file TEXT NOT NULL DEFAULT '',
	force_ssl INTEGER NOT NULL DEFAULT 0,
	managed_by TEXT NOT NULL DEFAULT '',
	owner TEXT NOT NULL DEFAULT '',
	cert_pem TEXT NOT NULL DEFAULT '',
	key_pem TEXT NOT NULL DEFAULT '',
	cert_source TEXT NOT NULL DEFAULT '',
	cert_not_after INTEGER NOT NULL DEFAULT 0,
	acme INTEGER NOT NULL DEFAULT 0,
	maintenance INTEGER NOT NULL DEFAULT 0,
	backend_protocol TEXT NOT NULL DEFAULT 'http1',
	timeout_seconds INTEGER NOT NULL DEFAULT 0,
	max_body_mb INTEGER NOT NULL DEFAULT 0,
	redirect_url TEXT NOT NULL DEFAULT '',
	redirect_code INTEGER NOT NULL DEFAULT 0,
	basic_auth TEXT NOT NULL DEFAULT '',
	updated_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE (domain, path_prefix)
)`

// migrate brings any older database (v0: no version, unique domain) to the current schema.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	var hasRoutes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='routes'`).Scan(&hasRoutes); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	switch {
	case hasRoutes == 0:
		if _, err := tx.Exec(routesTable); err != nil {
			return err
		}
	case version < 2:
		// v0/v1 had UNIQUE(domain) and fewer columns: rebuild the table, keeping every route.
		// Older databases may lack some columns (they were added one by one), so add them first.
		for _, col := range []string{
			`mode TEXT NOT NULL DEFAULT 'proxy'`, `static_dir TEXT NOT NULL DEFAULT ''`,
			`cert_file TEXT NOT NULL DEFAULT ''`, `key_file TEXT NOT NULL DEFAULT ''`,
			`force_ssl INTEGER NOT NULL DEFAULT 0`, `target_https INTEGER NOT NULL DEFAULT 0`,
			`rate_limit INTEGER NOT NULL DEFAULT 0`, `hc_enabled INTEGER NOT NULL DEFAULT 0`,
			`hc_path TEXT NOT NULL DEFAULT '/'`, `hc_interval INTEGER NOT NULL DEFAULT 30`,
			`hc_type TEXT NOT NULL DEFAULT 'status'`, `hc_expect TEXT NOT NULL DEFAULT ''`,
		} {
			tx.Exec(`ALTER TABLE routes ADD COLUMN ` + col) // error = column exists
		}
		if _, err := tx.Exec(strings.Replace(routesTable, "CREATE TABLE routes", "CREATE TABLE routes_v2", 1)); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO routes_v2 (id, domain, mode, target_ip, target_port, target_https, rate_limit,
			hc_enabled, hc_path, hc_interval, hc_type, hc_expect, static_dir, cert_file, key_file, force_ssl)
			SELECT id, domain, mode, target_ip, target_port, target_https, rate_limit,
			hc_enabled, hc_path, hc_interval, hc_type, hc_expect, static_dir, cert_file, key_file, force_ssl FROM routes`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DROP TABLE routes`); err != nil {
			return err
		}
		if _, err := tx.Exec(`ALTER TABLE routes_v2 RENAME TO routes`); err != nil {
			return err
		}
	}
	if hasRoutes > 0 && version == 2 {
		// v3: per-route protocol, timeouts, body limit, redirects, basic auth
		for _, col := range []string{
			`backend_protocol TEXT NOT NULL DEFAULT 'http1'`, `timeout_seconds INTEGER NOT NULL DEFAULT 0`,
			`max_body_mb INTEGER NOT NULL DEFAULT 0`, `redirect_url TEXT NOT NULL DEFAULT ''`,
			`redirect_code INTEGER NOT NULL DEFAULT 0`, `basic_auth TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := tx.Exec(`ALTER TABLE routes ADD COLUMN ` + col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return err
			}
		}
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			hash TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			ip TEXT PRIMARY KEY,
			reason TEXT NOT NULL DEFAULT '',
			blocked_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)`, // e.g. the ACME account key
		fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion),
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetKV / SetKV store small blobs (ACME account key, …).
func (s *Store) GetKV(key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

func (s *Store) SetKV(key string, value []byte) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)`, key, value)
	return err
}

// ---- mobile refresh tokens (only SHA-256 hashes are stored) ----

func (s *Store) CreateRefreshToken(hash string, ttl time.Duration) error {
	now := time.Now()
	s.db.Exec(`DELETE FROM refresh_tokens WHERE expires_at < ?`, now.Unix())
	_, err := s.db.Exec(`INSERT INTO refresh_tokens (hash, created_at, expires_at) VALUES (?, ?, ?)`,
		hash, now.Unix(), now.Add(ttl).Unix())
	return err
}

// TouchRefreshToken validates the token and slides its expiry forward.
func (s *Store) TouchRefreshToken(hash string, ttl time.Duration) (bool, error) {
	now := time.Now()
	res, err := s.db.Exec(`UPDATE refresh_tokens SET expires_at = ? WHERE hash = ? AND expires_at > ?`,
		now.Add(ttl).Unix(), hash, now.Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) DeleteRefreshToken(hash string) error {
	_, err := s.db.Exec(`DELETE FROM refresh_tokens WHERE hash = ?`, hash)
	return err
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
