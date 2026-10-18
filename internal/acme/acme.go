// Package acme is the gateway's built-in Let's Encrypt client (HTTP-01 challenge). It replaces
// shelling out to certbot inside containers: certificates and the account key live in the
// gateway database, challenges are answered by the proxy itself, and renewal runs in-process.
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

	inflight sync.Map // domain → struct{} (one order per domain at a time)
}

// New creates an issuer. directory "" = Let's Encrypt production.
func New(st *store.Store, email, directory string) *Issuer {
	if directory == "" {
		directory = LetsEncrypt
	}
	return &Issuer{store: st, email: email, directory: directory}
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

// Issue obtains a certificate for domain via HTTP-01. The domain must already point to this gateway.
func (i *Issuer) Issue(ctx context.Context, domain string) (certPEM, keyPEM string, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if strings.HasPrefix(domain, "*.") {
		return "", "", errors.New("wildcard certificates need the DNS-01 challenge (not supported yet)")
	}
	if _, busy := i.inflight.LoadOrStore(domain, struct{}{}); busy {
		return "", "", errors.New("a certificate request for this domain is already running")
	}
	defer i.inflight.Delete(domain)

	c, err := i.clientFor(ctx)
	if err != nil {
		return "", "", err
	}
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		return "", "", fmt.Errorf("acme order: %w", err)
	}
	for _, zurl := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, zurl)
		if err != nil {
			return "", "", err
		}
		if z.Status == xacme.StatusValid {
			continue
		}
		var chal *xacme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == "http-01" {
				chal = ch
				break
			}
		}
		if chal == nil {
			return "", "", errors.New("acme: the CA offered no http-01 challenge")
		}
		resp, err := c.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return "", "", err
		}
		i.tokens.Store(chal.Token, resp)
		defer i.tokens.Delete(chal.Token)
		if _, err := c.Accept(ctx, chal); err != nil {
			return "", "", fmt.Errorf("acme accept: %w", err)
		}
		if _, err := c.WaitAuthorization(ctx, z.URI); err != nil {
			return "", "", fmt.Errorf("acme validation for %s failed (does the domain point to this server and is port 80 open?): %w", domain, err)
		}
	}
	if order, err = c.WaitOrder(ctx, order.URI); err != nil {
		return "", "", fmt.Errorf("acme order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
	}, key)
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
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return b.String(), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})), nil
}

// RunRenewals renews ACME certificates that expire within 30 days and issues missing ones for routes
// with acme=true. It runs until ctx is cancelled.
func (i *Issuer) RunRenewals(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		i.renewOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (i *Issuer) renewOnce(ctx context.Context) {
	done := map[string]bool{}
	for _, r := range i.store.All() {
		if done[r.Domain] || strings.HasPrefix(r.Domain, "*.") {
			continue
		}
		wants := r.ACME || r.CertSource == "acme"
		if !wants || r.CertSource == "upload" || r.CertSource == "file" {
			continue
		}
		if r.CertNotAfter > time.Now().Add(renewBefore).Unix() {
			continue
		}
		done[r.Domain] = true
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
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
