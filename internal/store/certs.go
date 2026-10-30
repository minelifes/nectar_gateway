package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Certificate is a certificate that is not tied to one route: typically a wildcard
// ("*.apps.example.com", issued over ACME DNS-01) that serves every host it covers. A route's own
// certificate wins; hosts without one get the most specific covering certificate.
type Certificate struct {
	ID     int64  `json:"id"`
	Domain string `json:"domain"` // "*.example.com" or an exact host
	// IncludeApex adds the parent domain to a wildcard certificate (*.example.com + example.com).
	IncludeApex bool   `json:"include_apex"`
	ACME        bool   `json:"acme"`   // issued and renewed by the built-in ACME client
	Source      string `json:"source"` // "" (not issued yet) | "acme" | "upload"
	NotAfter    int64  `json:"not_after"`
	// LastError is the reason of the last failed ACME attempt ("" after a success).
	LastError   string `json:"last_error"`
	LastAttempt int64  `json:"last_attempt"`
	// ManagedBy / Owner work like on routes: a controller's certificates are read-only for humans.
	ManagedBy string `json:"managed_by"`
	Owner     string `json:"owner"`
	CertPEM   string `json:"-"`
	KeyPEM    string `json:"-"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// Names are the DNS names the certificate is (to be) issued for.
func (c Certificate) Names() []string {
	names := []string{c.Domain}
	if parent, ok := strings.CutPrefix(c.Domain, "*."); ok && c.IncludeApex {
		names = append(names, parent)
	}
	return names
}

// Valid reports whether the certificate has a key pair that has not expired.
func (c Certificate) Valid(now time.Time) bool {
	return c.CertPEM != "" && c.KeyPEM != "" && c.NotAfter > now.Unix()
}

// ErrCertConflict: a certificate for this domain exists already.
var ErrCertConflict = errors.New("a certificate for this domain already exists")

const certificatesTable = `CREATE TABLE IF NOT EXISTS certificates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT NOT NULL UNIQUE,
	include_apex INTEGER NOT NULL DEFAULT 0,
	acme INTEGER NOT NULL DEFAULT 0,
	source TEXT NOT NULL DEFAULT '',
	not_after INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	last_attempt INTEGER NOT NULL DEFAULT 0,
	managed_by TEXT NOT NULL DEFAULT '',
	owner TEXT NOT NULL DEFAULT '',
	cert_pem TEXT NOT NULL DEFAULT '',
	key_pem TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL DEFAULT 0
)`

const certCols = `id, domain, include_apex, acme, source, not_after, last_error, last_attempt, managed_by, owner, cert_pem, key_pem, created_at, updated_at`

func scanCert(sc interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	err := sc.Scan(&c.ID, &c.Domain, &c.IncludeApex, &c.ACME, &c.Source, &c.NotAfter, &c.LastError, &c.LastAttempt,
		&c.ManagedBy, &c.Owner, &c.CertPEM, &c.KeyPEM, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (s *Store) reloadCerts() error {
	rows, err := s.db.Query(`SELECT ` + certCols + ` FROM certificates ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[int64]Certificate{}
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return err
		}
		m[c.ID] = c
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.certs = m
	s.mu.Unlock()
	return nil
}

// Certificates returns every standalone certificate, ordered by domain.
func (s *Store) Certificates() []Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Certificate, 0, len(s.certs))
	for _, c := range s.certs {
		out = append(out, c)
	}
	sortCerts(out)
	return out
}

func sortCerts(cs []Certificate) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j].Domain < cs[j-1].Domain; j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

// Certificate returns one certificate.
func (s *Store) Certificate(id int64) (Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.certs[id]
	return c, ok
}

// NormalizeCertDomain checks a certificate domain ("*.example.com" or a host name).
func NormalizeCertDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	host := strings.TrimPrefix(d, "*.")
	if host == "" || strings.Contains(host, "*") || strings.ContainsAny(d, " /:") || !strings.Contains(host, ".") {
		return "", errors.New("domain must be a host name like app.example.com or a wildcard like *.example.com")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain %q", d)
		}
	}
	return d, nil
}

// CreateCertificate adds a certificate entry (issued later by ACME, or with an uploaded pair).
func (s *Store) CreateCertificate(c *Certificate) error {
	d, err := NormalizeCertDomain(c.Domain)
	if err != nil {
		return err
	}
	c.Domain = d
	if !strings.HasPrefix(d, "*.") {
		c.IncludeApex = false
	}
	if c.CertPEM != "" || c.KeyPEM != "" {
		notAfter, names, err := ParseCertPair(c.CertPEM, c.KeyPEM)
		if err != nil {
			return err
		}
		for _, n := range c.Names() {
			if !certCovers(names, n) {
				return fmt.Errorf("certificate does not cover %s (it is for %s)", n, strings.Join(names, ", "))
			}
		}
		c.NotAfter, c.Source = notAfter.Unix(), "upload"
	}
	now := time.Now().Unix()
	c.CreatedAt, c.UpdatedAt = now, now
	res, err := s.db.Exec(`INSERT INTO certificates (domain, include_apex, acme, source, not_after, managed_by, owner, cert_pem, key_pem, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.Domain, c.IncludeApex, c.ACME, c.Source, c.NotAfter, c.ManagedBy, c.Owner,
		c.CertPEM, c.KeyPEM, c.CreatedAt, c.UpdatedAt)
	if isUnique(err) {
		return ErrCertConflict
	}
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return s.reloadCerts()
}

// SetCertificatePair stores an issued or uploaded key pair (it must cover every name).
func (s *Store) SetCertificatePair(id int64, certPEM, keyPEM, source string) (Certificate, error) {
	c, ok := s.Certificate(id)
	if !ok {
		return Certificate{}, sql.ErrNoRows
	}
	notAfter, names, err := ParseCertPair(certPEM, keyPEM)
	if err != nil {
		return Certificate{}, err
	}
	for _, n := range c.Names() {
		if !certCovers(names, n) {
			return Certificate{}, fmt.Errorf("certificate does not cover %s (it is for %s)", n, strings.Join(names, ", "))
		}
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(`UPDATE certificates SET cert_pem=?, key_pem=?, source=?, not_after=?, last_error='', last_attempt=?, updated_at=? WHERE id=?`,
		certPEM, keyPEM, source, notAfter.Unix(), now, now, id); err != nil {
		return Certificate{}, err
	}
	if err := s.reloadCerts(); err != nil {
		return Certificate{}, err
	}
	c, _ = s.Certificate(id)
	return c, nil
}

// SetCertificateError records a failed ACME attempt.
func (s *Store) SetCertificateError(id int64, msg string) error {
	now := time.Now().Unix()
	if _, err := s.db.Exec(`UPDATE certificates SET last_error=?, last_attempt=?, updated_at=? WHERE id=?`, msg, now, now, id); err != nil {
		return err
	}
	return s.reloadCerts()
}

// DeleteCertificate removes a certificate.
func (s *Store) DeleteCertificate(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM certificates WHERE id=?`, id); err != nil {
		return err
	}
	return s.reloadCerts()
}

// CoveringCertificate returns the valid certificate that serves host: an exact certificate first, then
// the wildcard of its parent domain (*.example.com covers a.example.com, not a.b.example.com).
func (s *Store) CoveringCertificate(host string) (Certificate, bool) {
	host = strings.ToLower(host)
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var wild Certificate
	found := false
	for _, c := range s.certs {
		if !c.Valid(now) {
			continue
		}
		for _, n := range c.Names() {
			if n == host {
				if !strings.HasPrefix(n, "*.") {
					return c, true // exact
				}
			}
			if certCovers([]string{n}, host) && !found {
				wild, found = c, true
			}
		}
	}
	return wild, found
}

// HasTLS reports whether HTTPS works for host: a route certificate or a covering certificate.
func (s *Store) HasTLS(host string) bool {
	if _, ok := s.CertRoute(host); ok {
		return true
	}
	_, ok := s.CoveringCertificate(host)
	return ok
}
