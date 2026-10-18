package proxy

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"nectar_gateway/internal/store"
)

// authCache remembers successful basic-auth checks for a few minutes: bcrypt costs ~50 ms per check,
// far too slow to run on every request of a page with dozens of assets.
type authCache struct {
	mu sync.Mutex
	ok map[[32]byte]time.Time
}

const authCacheTTL = 5 * time.Minute

func newAuthCache() *authCache { return &authCache{ok: map[[32]byte]time.Time{}} }

func (c *authCache) check(route store.Route, user, pass string) bool {
	// the key changes when the route (and so its users) changes
	key := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s\x00%s", route.ID, route.UpdatedAt, user, pass)))
	now := time.Now()
	c.mu.Lock()
	exp, hit := c.ok[key]
	c.mu.Unlock()
	if hit && now.Before(exp) {
		return true
	}
	if !store.CheckBasicAuth(route.BasicAuth, user, pass) {
		return false
	}
	c.mu.Lock()
	if len(c.ok) > 10000 {
		for k, e := range c.ok {
			if now.After(e) {
				delete(c.ok, k)
			}
		}
	}
	c.ok[key] = now.Add(authCacheTTL)
	c.mu.Unlock()
	return true
}
