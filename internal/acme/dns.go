package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DNSProvider creates and removes the TXT records of DNS-01 challenges.
type DNSProvider interface {
	// Present creates a TXT record fqdn → value ("_acme-challenge.example.com." without the dot).
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes it again (best effort).
	CleanUp(ctx context.Context, fqdn, value string) error
}

// NewDNSProvider returns the provider for a settings value ("" = none).
func NewDNSProvider(kind, token string) (DNSProvider, error) {
	switch kind {
	case "":
		return nil, nil
	case "cloudflare":
		if token == "" {
			return nil, errors.New("cloudflare: an API token is required")
		}
		return &Cloudflare{Token: token}, nil
	}
	return nil, fmt.Errorf("unknown DNS provider %q", kind)
}

// ------------------------------------------------------------- Cloudflare --

// CloudflareAPI is the Cloudflare API base URL.
const CloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare is a DNSProvider for zones hosted at Cloudflare (API token with Zone:Read and DNS:Edit).
type Cloudflare struct {
	Token string
	API   string       // default CloudflareAPI (tests)
	HTTP  *http.Client // default: 30 s timeout
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	api := c.API
	if api == "" {
		api = CloudflareAPI
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, api+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	var r cfResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("cloudflare: %s: unexpected answer (HTTP %d)", path, resp.StatusCode)
	}
	if !r.Success {
		msgs := []string{}
		for _, e := range r.Errors {
			msgs = append(msgs, fmt.Sprintf("%s (%d)", e.Message, e.Code))
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			msgs = append(msgs, "check that the token has Zone:Read and DNS:Edit for this zone")
		}
		return fmt.Errorf("cloudflare: %s", strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// zone finds the zone id of fqdn: the longest suffix that is a zone of the account.
func (c *Cloudflare) zone(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil, &zones); err != nil {
			return "", err
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, name) {
				return z.ID, nil
			}
		}
	}
	return "", fmt.Errorf("cloudflare: no zone of this token contains %s", strings.TrimPrefix(fqdn, "_acme-challenge."))
}

// Present implements DNSProvider.
func (c *Cloudflare) Present(ctx context.Context, fqdn, value string) error {
	zone, err := c.zone(ctx, fqdn)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records",
		map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 60, "comment": "ACME challenge (nectar-gateway)"}, nil)
}

// CleanUp implements DNSProvider.
func (c *Cloudflare) CleanUp(ctx context.Context, fqdn, value string) error {
	zone, err := c.zone(ctx, fqdn)
	if err != nil {
		return err
	}
	var recs []struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?type=TXT&name="+url.QueryEscape(fqdn), nil, &recs); err != nil {
		return err
	}
	for _, r := range recs {
		if strings.Trim(r.Content, `"`) == value {
			if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// ------------------------------------------------------------ propagation --

// TXTLookup returns the TXT records of a name.
type TXTLookup func(ctx context.Context, name string) ([]string, error)

// PublicTXT asks public resolvers (Cloudflare, Google), which is what the CA sees, not a local cache.
func PublicTXT(servers ...string) TXTLookup {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return func(ctx context.Context, name string) ([]string, error) {
		var lastErr error
		for _, srv := range servers {
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv)
			}}
			txt, err := r.LookupTXT(ctx, name)
			if err == nil {
				return txt, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// waitTXT polls until value is visible (or the deadline); the CA is asked anyway afterwards, so a
// resolver that cannot be reached only costs the wait.
func waitTXT(ctx context.Context, lookup TXTLookup, fqdn, value string, timeout, every time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if txt, err := lookup(ctx, fqdn); err == nil {
			for _, t := range txt {
				if t == value {
					return true
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}
	}
}
