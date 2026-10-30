// Package acme is the gateway's built-in Let's Encrypt client. It replaces shelling out to certbot
// inside containers: certificates and the account key live in the gateway database, HTTP-01
// challenges are answered by the proxy itself, DNS-01 challenges (wildcard certificates) through a
// DNS provider's API, and renewal runs in-process.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"

	"nectar_gateway/internal/store"
)

// LetsEncrypt and LetsEncryptStaging are ACME directory URLs.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	accountKeyKV       = "acme_account_key"
	renewBefore        = 30 * 24 * time.Hour
)

// Issuer obtains and renews certificates.
type Issuer struct {
	store     *store.Store
	email     string
	directory string

	mu     sync.Mutex
	client *xacme.Client
	tokens sync.Map // HTTP-01 token → key authorization

	inflight sync.Map // names → struct{} (one order per name set at a time)

	dns       DNSProvider // nil = no DNS-01 (no wildcard certificates)
	lookup    TXTLookup   // propagation check (default: public resolvers)
	propagate time.Duration
	kick      chan struct{} // renew soon (after a DNS settings change)
}

// New creates an issuer. directory "" = Let's Encrypt production.
func New(st *store.Store, email, directory string) *Issuer {
	if directory == "" {
		directory = LetsEncrypt
	}
	return &Issuer{store: st, email: email, directory: directory, lookup: PublicTXT(), propagate: 2 * time.Minute, kick: make(chan struct{}, 1)}
}

// SetDNS sets the DNS-01 provider ("" removes it). Certificates that failed are retried soon.
func (i *Issuer) SetDNS(kind, token string) error {
	p, err := NewDNSProvider(kind, token)
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.dns = p
	i.mu.Unlock()
	select {
	case i.kick <- struct{}{}:
	default:
	}
	return nil
}

// SetDNSProvider sets the provider and the propagation check directly (tests, other providers).
func (i *Issuer) SetDNSProvider(p DNSProvider, lookup TXTLookup, wait time.Duration) {
	i.mu.Lock()
	i.dns, i.lookup, i.propagate = p, lookup, wait
	i.mu.Unlock()
}

// HasDNS reports whether DNS-01 (wildcard certificates) is available.
func (i *Issuer) HasDNS() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.dns != nil
}

func (i *Issuer) dnsConfig() (DNSProvider, TXTLookup, time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.dns, i.lookup, i.propagate
}

// SetEmail changes the account contact. An already registered account is updated at Let's Encrypt
// (best effort, in the background); otherwise the email is used at registration.
func (i *Issuer) SetEmail(email string) {
	i.mu.Lock()
	if email == i.email {
		i.mu.Unlock()
		return
	}
	i.email = email
	c := i.client
	i.mu.Unlock()
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		acct := &xacme.Account{Contact: []string{}}
		if email != "" {
			acct.Contact = []string{"mailto:" + email}
		}
		if _, err := c.UpdateReg(ctx, acct); err != nil {
			log.Printf("acme: update account contact: %v", err)
		} else {
			log.Printf("acme: account contact set to %q", email)
		}
	}()
}

// Email returns the current account contact.
func (i *Issuer) Email() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.email
}

// ChallengeResponse returns the key authorization for an HTTP-01 token (served by the proxy at
// /.well-known/acme-challenge/<token>).
func (i *Issuer) ChallengeResponse(token string) (string, bool) {
	v, ok := i.tokens.Load(token)
	if !ok {
		return "", false
	}
	return v.(string), true
}

// clientFor returns a registered ACME client (account key persisted in the database).
func (i *Issuer) clientFor(ctx context.Context) (*xacme.Client, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.client != nil {
		return i.client, nil
	}
	key, err := i.accountKey()
	if err != nil {
		return nil, err
	}
	c := &xacme.Client{Key: key, DirectoryURL: i.directory, UserAgent: "nectar-gateway"}
	acct := &xacme.Account{}
	if i.email != "" {
		acct.Contact = []string{"mailto:" + i.email}
	}
	if _, err := c.Register(ctx, acct, xacme.AcceptTOS); err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("acme register: %w", err)
	}
	i.client = c
	return c, nil
}

func (i *Issuer) accountKey() (crypto.Signer, error) {
	raw, err := i.store.GetKV(accountKeyKV)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("acme: stored account key is not PEM")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := i.store.SetKV(accountKeyKV, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

// Issue obtains a certificate for one domain: HTTP-01 (the domain must point to this gateway), or
// DNS-01 for a wildcard (needs a DNS provider).
func (i *Issuer) Issue(ctx context.Context, domain string) (certPEM, keyPEM string, err error) {
	return i.IssueNames(ctx, []string{domain})
}

// ErrNoDNS: a wildcard certificate needs DNS-01, which needs a DNS provider.
var ErrNoDNS = errors.New("wildcard certificates need the DNS-01 challenge: set a DNS provider (dns_provider, dns_api_token in the settings)")

// IssueNames obtains one certificate for all names. Orders with a wildcard are validated over DNS-01
// for every name (Let's Encrypt allows only DNS-01 for wildcards); others over HTTP-01.
func (i *Issuer) IssueNames(ctx context.Context, names []string) (certPEM, keyPEM string, err error) {
	if len(names) == 0 {
		return "", "", errors.New("no names")
	}
	wildcard := false
	for k, n := range names {
		names[k] = strings.ToLower(strings.TrimSpace(n))
		wildcard = wildcard || strings.HasPrefix(names[k], "*.")
	}
	dns, lookup, wait := i.dnsConfig()
	if wildcard && dns == nil {
		return "", "", ErrNoDNS
	}
	key := strings.Join(names, ",")
	if _, busy := i.inflight.LoadOrStore(key, struct{}{}); busy {
		return "", "", errors.New("a certificate request for this domain is already running")
	}
	defer i.inflight.Delete(key)

	c, err := i.clientFor(ctx)
	if err != nil {
		return "", "", err
	}
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(names...))
	if err != nil {
		return "", "", fmt.Errorf("acme order: %w", err)
	}
	var cleanups []func()
	defer func() {
		for _, f := range cleanups {
			f()
		}
	}()
	for _, zurl := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, zurl)
		if err != nil {
			return "", "", err
		}
		if z.Status == xacme.StatusValid {
			continue
		}
		typ := "http-01"
		if wildcard {
			typ = "dns-01"
		}
		var chal *xacme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == typ {
				chal = ch
				break
			}
		}
		if chal == nil {
			return "", "", fmt.Errorf("acme: the CA offered no %s challenge for %s", typ, z.Identifier.Value)
		}
		host := strings.TrimPrefix(z.Identifier.Value, "*.")
		if typ == "dns-01" {
			rec, err := c.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				return "", "", err
			}
			fqdn := "_acme-challenge." + host
			if err := dns.Present(ctx, fqdn, rec); err != nil {
				return "", "", fmt.Errorf("dns-01 for %s: %w", z.Identifier.Value, err)
			}
			cleanups = append(cleanups, func() {
				cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := dns.CleanUp(cctx, fqdn, rec); err != nil {
					log.Printf("acme: remove TXT %s: %v", fqdn, err)
				}
			})
			if !waitTXT(ctx, lookup, fqdn, rec, wait, 5*time.Second) {
				log.Printf("acme: TXT %s not visible yet after %s, asking the CA anyway", fqdn, wait)
			}
		} else {
			resp, err := c.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return "", "", err
			}
			i.tokens.Store(chal.Token, resp)
			defer i.tokens.Delete(chal.Token)
		}
		if _, err := c.Accept(ctx, chal); err != nil {
			return "", "", fmt.Errorf("acme accept: %w", err)
		}
		if _, err := c.WaitAuthorization(ctx, z.URI); err != nil {
			if typ == "dns-01" {
				return "", "", fmt.Errorf("acme dns-01 validation for %s failed (is the TXT record _acme-challenge.%s visible?): %w", z.Identifier.Value, host, err)
			}
			return "", "", fmt.Errorf("acme validation for %s failed (does the domain point to this server and is port 80 open?): %w", z.Identifier.Value, err)
		}
	}
	if order, err = c.WaitOrder(ctx, order.URI); err != nil {
		return "", "", fmt.Errorf("acme order: %w", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
	}, key2)
	if err != nil {
		return "", "", err
	}
	chain, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", "", fmt.Errorf("acme finalize: %w", err)
	}
	var b strings.Builder
	for _, der := range chain {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	kder, err := x509.MarshalECPrivateKey(key2)
	if err != nil {
		return "", "", err
	}
	return b.String(), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})), nil
}

// IssueCertificate issues (or renews) a standalone certificate and records the result.
func (i *Issuer) IssueCertificate(ctx context.Context, id int64) error {
	c, ok := i.store.Certificate(id)
	if !ok {
		return errors.New("certificate not found")
	}
	certPEM, keyPEM, err := i.IssueNames(ctx, c.Names())
	if err != nil {
		_ = i.store.SetCertificateError(id, err.Error())
		return err
	}
	if _, err := i.store.SetCertificatePair(id, certPEM, keyPEM, "acme"); err != nil {
		_ = i.store.SetCertificateError(id, err.Error())
		return err
	}
	log.Printf("acme: certificate for %s issued/renewed", strings.Join(c.Names(), ", "))
	return nil
}

// RunRenewals renews ACME certificates that expire within 30 days and issues missing ones (routes with
// acme=true and standalone certificates). It runs until ctx is cancelled.
func (i *Issuer) RunRenewals(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		i.renewOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-i.kick:
		}
	}
}

// retryAfter spaces out failed attempts (Let's Encrypt limits failed validations per hour).
const retryAfter = time.Hour

func (i *Issuer) renewOnce(ctx context.Context) {
	now := time.Now()
	// standalone certificates first: they may cover the routes below
	for _, c := range i.store.Certificates() {
		if !c.ACME || c.NotAfter > now.Add(renewBefore).Unix() {
			continue
		}
		if c.LastError != "" && now.Sub(time.Unix(c.LastAttempt, 0)) < retryAfter {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		if err := i.IssueCertificate(cctx, c.ID); err != nil {
			log.Printf("acme: %s: %v", c.Domain, err)
		}
		cancel()
	}
	done := map[string]bool{}
	for _, r := range i.store.All() {
		if done[r.Domain] {
			continue
		}
		wants := r.ACME || r.CertSource == "acme"
		if !wants || r.CertSource == "upload" || r.CertSource == "file" {
			continue
		}
		if r.CertNotAfter > now.Add(renewBefore).Unix() {
			continue
		}
		if strings.HasPrefix(r.Domain, "*.") && !i.HasDNS() {
			continue
		}
		// a wildcard certificate already serves this host: no order of its own (rate limits, port 80)
		if cov, ok := i.store.CoveringCertificate(r.Domain); ok && cov.NotAfter > now.Add(renewBefore).Unix() && r.CertNotAfter == 0 {
			continue
		}
		done[r.Domain] = true
		cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		certPEM, keyPEM, err := i.Issue(cctx, r.Domain)
		cancel()
		if err != nil {
			log.Printf("acme: renew %s: %v", r.Domain, err)
			continue
		}
		if _, err := i.store.SetCert(r.ID, certPEM, keyPEM, "acme"); err != nil {
			log.Printf("acme: store %s: %v", r.Domain, err)
			continue
		}
		log.Printf("acme: certificate for %s issued/renewed", r.Domain)
	}
}
