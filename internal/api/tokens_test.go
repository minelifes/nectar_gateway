package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"nectar_gateway/internal/certbot"
)

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < maxLoginFailures; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("blocked too early after %d failures", i)
		}
		l.fail("1.2.3.4")
	}
	if l.allow("1.2.3.4") {
		t.Fatal("should be blocked after max failures")
	}
	if !l.allow("5.6.7.8") {
		t.Fatal("other IPs must be unaffected")
	}
	l.reset("1.2.3.4")
	if !l.allow("1.2.3.4") {
		t.Fatal("reset (successful login) should unblock")
	}
}

func TestBearerToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer abc123")
	if tok, ok := bearerToken(r); !ok || tok != "abc123" {
		t.Fatalf("got %q, %v", tok, ok)
	}
	r.Header.Set("Authorization", "bearer lower")
	if tok, ok := bearerToken(r); !ok || tok != "lower" {
		t.Fatalf("scheme must be case-insensitive, got %q, %v", tok, ok)
	}
	r.Header.Set("Authorization", "Basic abc")
	if _, ok := bearerToken(r); ok {
		t.Fatal("Basic must not parse as Bearer")
	}
}

func TestAccessTokenLifecycle(t *testing.T) {
	s := New(nil, "u", "p", nil, certbot.Config{}, nil)

	tok := s.newAccessToken()
	if !s.validAccess(tok) {
		t.Fatal("fresh token must be valid")
	}
	if s.validAccess("nope") {
		t.Fatal("unknown token must be invalid")
	}

	// force expiry
	s.mu.Lock()
	s.access[tok] = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if s.validAccess(tok) {
		t.Fatal("expired token must be invalid")
	}

	// authed() honours Bearer tokens
	tok2 := s.newAccessToken()
	r := httptest.NewRequest("GET", "/api/routes", nil)
	r.Header.Set("Authorization", "Bearer "+tok2)
	if !s.authed(r) {
		t.Fatal("request with valid bearer token must be authed")
	}
	r.Header.Set("Authorization", "Bearer wrong")
	if s.authed(r) {
		t.Fatal("request with wrong bearer token must not be authed")
	}
}

func TestHashTokenStable(t *testing.T) {
	if hashToken("x") != hashToken("x") || hashToken("x") == hashToken("y") {
		t.Fatal("hashToken must be deterministic and collision-free for different inputs")
	}
	if len(hashToken("x")) != 64 {
		t.Fatal("expected hex sha256")
	}
}
