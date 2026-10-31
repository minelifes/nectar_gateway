package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Snapshot is the state an edge replica copies from the primary gateway: every route and certificate
// (with keys) as raw table rows, plus the primary's IP blocks. Rows are copied column by column, so the
// replica must run the same schema version (the panel keeps both on the same image).
type Snapshot struct {
	Schema       int              `json:"schema"`
	Routes       []map[string]any `json:"routes"`
	Certificates []map[string]any `json:"certificates"`
	Blocked      []BlockedIP      `json:"blocked"`
	Settings     json.RawMessage  `json:"settings,omitempty"`
}

// ETag identifies the snapshot's content (a changed route, certificate, block or setting changes it).
func (s Snapshot) ETag() string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:12]) + `"`
}

func (s *Store) tableRows(table string) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT * FROM ` + table + ` ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				vals[i] = string(b)
			}
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ExportSnapshot returns the replicated state.
func (s *Store) ExportSnapshot(settings []byte) (Snapshot, error) {
	snap := Snapshot{Schema: schemaVersion, Blocked: []BlockedIP{}}
	var err error
	if snap.Routes, err = s.tableRows("routes"); err != nil {
		return snap, err
	}
	if snap.Certificates, err = s.tableRows("certificates"); err != nil {
		return snap, err
	}
	now := time.Now()
	for _, b := range s.ListBlocked() {
		if b.ExpiresAt.After(now) {
			// seconds precision (what is stored), so the ETag stays the same between calls
			b.BlockedAt, b.ExpiresAt = time.Unix(b.BlockedAt.Unix(), 0).UTC(), time.Unix(b.ExpiresAt.Unix(), 0).UTC()
			snap.Blocked = append(snap.Blocked, b)
		}
	}
	sort.Slice(snap.Blocked, func(i, j int) bool { return snap.Blocked[i].IP < snap.Blocked[j].IP })
	if len(settings) > 0 {
		snap.Settings = settings
	}
	return snap, nil
}

// ImportSnapshot replaces routes and certificates with the snapshot's and applies the primary's IP
// blocks: blocks the primary had in the previous snapshot but no longer has are lifted, the replica's
// own rate-limit blocks stay.
func (s *Store) ImportSnapshot(snap Snapshot, previous []BlockedIP) error {
	if snap.Schema != schemaVersion {
		return fmt.Errorf("the primary gateway uses database schema %d, this one %d: run the same version on both", snap.Schema, schemaVersion)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range []struct {
		name string
		rows []map[string]any
	}{{"routes", snap.Routes}, {"certificates", snap.Certificates}} {
		if _, err := tx.Exec(`DELETE FROM ` + t.name); err != nil {
			return err
		}
		for _, row := range t.rows {
			cols := make([]string, 0, len(row))
			for c := range row {
				if !validColumn(c) {
					return fmt.Errorf("%s: bad column %q", t.name, c)
				}
				cols = append(cols, c)
			}
			sort.Strings(cols)
			args := make([]any, len(cols))
			for i, c := range cols {
				args[i] = jsonValue(row[c])
			}
			q := `INSERT INTO ` + t.name + ` (` + strings.Join(cols, ", ") + `) VALUES (?` + strings.Repeat(", ?", len(cols)-1) + `)`
			if _, err := tx.Exec(q, args...); err != nil {
				return fmt.Errorf("%s: %w", t.name, err)
			}
		}
	}
	keep := map[string]bool{}
	for _, b := range snap.Blocked {
		keep[b.IP] = true
		if _, err := tx.Exec(`INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at) VALUES (?, ?, ?, ?)`,
			b.IP, b.Reason, b.BlockedAt.Unix(), b.ExpiresAt.Unix()); err != nil {
			return err
		}
	}
	for _, b := range previous {
		if !keep[b.IP] {
			if _, err := tx.Exec(`DELETE FROM blocked_ips WHERE ip = ?`, b.IP); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return errors.Join(s.reload(), s.reloadCerts(), s.loadBlocked())
}

func validColumn(c string) bool {
	if c == "" || len(c) > 64 {
		return false
	}
	for _, r := range c {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// jsonValue turns JSON-decoded numbers back into integers (every numeric column is an INTEGER).
func jsonValue(v any) any {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
		f, _ := n.Float64()
		return f
	case float64:
		if n == float64(int64(n)) {
			return int64(n)
		}
	}
	return v
}
