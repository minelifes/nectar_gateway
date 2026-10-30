// Package settings holds runtime settings changed through the admin API and stored in the database.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Values are the settings.
type Values struct {
	// FallbackHTTP is "host:port" of an upstream that serves plain HTTP requests for hosts without a
	// route (e.g. the previous ingress controller during a migration). "" = answer 410.
	FallbackHTTP string `json:"fallback_http"`
	// FallbackTLS is "host:port" that receives the raw TLS stream (SNI passthrough) for HTTPS
	// connections whose host has no certificate here. "" = terminate TLS here (handshake fails).
	FallbackTLS string `json:"fallback_tls"`
	// ACMEEmail is the Let's Encrypt account contact ("" = no contact). Defaults to ACME_EMAIL.
	ACMEEmail string `json:"acme_email"`
	// DNSProvider answers ACME DNS-01 challenges (needed for wildcard certificates): "" | "cloudflare".
	DNSProvider string `json:"dns_provider"`
	// DNSAPIToken is the provider credential (Cloudflare: an API token with Zone:Read and DNS:Edit).
	// Write-only: the admin API never returns it (see Public).
	DNSAPIToken string `json:"dns_api_token,omitempty"`
}

// DNSProviders are the supported DNS-01 providers.
var DNSProviders = []string{"cloudflare"}

// PublicValues is what the admin API returns: the values without secrets.
type PublicValues struct {
	Values
	DNSTokenSet bool `json:"dns_token_set"`
}

// Public hides the DNS token.
func (v Values) Public() PublicValues {
	p := PublicValues{Values: v, DNSTokenSet: v.DNSAPIToken != ""}
	p.DNSAPIToken = ""
	return p
}

// KV is the storage (implemented by store.Store).
type KV interface {
	GetKV(key string) ([]byte, error)
	SetKV(key string, value []byte) error
}

const key = "settings"

// Settings is the live, persisted settings object. Safe for concurrent use.
type Settings struct {
	kv KV
	mu sync.RWMutex
	v  Values

	hooks []func(Values)
}

// OnChange registers fn to run after every successful Set (e.g. to update the ACME account contact).
func (s *Settings) OnChange(fn func(Values)) {
	s.mu.Lock()
	s.hooks = append(s.hooks, fn)
	s.mu.Unlock()
}

// Load reads the stored settings; defaults (e.g. from env vars) apply to fields never set via the API.
func Load(kv KV, defaults Values) (*Settings, error) {
	s := &Settings{kv: kv, v: defaults}
	b, err := kv.GetKV(key)
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		var stored map[string]json.RawMessage
		if err := json.Unmarshal(b, &stored); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
		cur, _ := json.Marshal(s.v)
		merged := map[string]json.RawMessage{}
		_ = json.Unmarshal(cur, &merged)
		for k, v := range stored {
			merged[k] = v
		}
		mb, _ := json.Marshal(merged)
		if err := json.Unmarshal(mb, &s.v); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
	}
	return s, s.v.Validate()
}

// Get returns the current values.
func (s *Settings) Get() Values {
	if s == nil {
		return Values{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}

// Set validates, stores and applies new values.
func (s *Settings) Set(v Values) error {
	v.FallbackHTTP, v.FallbackTLS = strings.TrimSpace(v.FallbackHTTP), strings.TrimSpace(v.FallbackTLS)
	v.ACMEEmail = strings.TrimSpace(v.ACMEEmail)
	v.DNSProvider, v.DNSAPIToken = strings.ToLower(strings.TrimSpace(v.DNSProvider)), strings.TrimSpace(v.DNSAPIToken)
	if v.DNSProvider == "" {
		v.DNSAPIToken = ""
	}
	if err := v.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(v)
	if err := s.kv.SetKV(key, b); err != nil {
		return err
	}
	s.mu.Lock()
	s.v = v
	hooks := append([]func(Values){}, s.hooks...)
	s.mu.Unlock()
	for _, fn := range hooks {
		fn(v)
	}
	return nil
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Validate checks the values.
func (v Values) Validate() error {
	if v.ACMEEmail != "" && !emailRe.MatchString(v.ACMEEmail) {
		return errors.New("acme_email must be an email address")
	}
	if v.DNSProvider != "" {
		known := false
		for _, p := range DNSProviders {
			known = known || p == v.DNSProvider
		}
		if !known {
			return fmt.Errorf("dns_provider must be one of %s (or empty)", strings.Join(DNSProviders, ", "))
		}
		if v.DNSAPIToken == "" {
			return errors.New("dns_api_token is required for the DNS provider")
		}
	}
	for name, hp := range map[string]string{"fallback_http": v.FallbackHTTP, "fallback_tls": v.FallbackTLS} {
		if hp == "" {
			continue
		}
		if strings.Contains(hp, "://") {
			return fmt.Errorf("%s must be host:port (no scheme), e.g. traefik.kube-system.svc.cluster.local:80", name)
		}
		host, port, err := net.SplitHostPort(hp)
		if err != nil || host == "" {
			return fmt.Errorf("%s must be host:port: %v", name, err)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New(name + ": invalid port")
		}
	}
	return nil
}
