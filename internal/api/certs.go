package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nectar_gateway/internal/store"
)

// CertificateIssuer issues standalone certificates (implemented by the built-in ACME client).
type CertificateIssuer interface {
	IssueCertificate(ctx context.Context, id int64) error
	HasDNS() bool
}

func (s *Server) certIssuer() CertificateIssuer {
	ci, _ := s.issuer.(CertificateIssuer)
	return ci
}

func certID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return 0, false
	}
	return id, true
}

// certView is a certificate as the API shows it (no key, plus the hosts it currently serves).
type certView struct {
	store.Certificate
	Names  []string `json:"names"`
	Serves []string `json:"serves"` // route hosts without a certificate of their own that use it
	Status string   `json:"status"` // pending | valid | expiring | expired | failed
}

func (s *Server) view(c store.Certificate) certView {
	v := certView{Certificate: c, Names: c.Names(), Serves: []string{}}
	now := time.Now()
	switch {
	case c.CertPEM == "" && c.LastError != "":
		v.Status = "failed"
	case c.CertPEM == "":
		v.Status = "pending"
	case c.NotAfter <= now.Unix():
		v.Status = "expired"
	case c.NotAfter <= now.Add(14*24*time.Hour).Unix():
		v.Status = "expiring"
	default:
		v.Status = "valid"
	}
	seen := map[string]bool{}
	for _, r := range s.store.WithCoverage(s.store.All()) {
		if r.CoveredBy == c.Domain && !seen[r.Domain] {
			seen[r.Domain] = true
			v.Serves = append(v.Serves, r.Domain)
		}
	}
	return v
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	out := []certView{}
	for _, c := range s.store.Certificates() {
		if m := r.URL.Query(); m.Has("managed_by") && m.Get("managed_by") != c.ManagedBy {
			continue
		}
		out = append(out, s.view(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createCertificate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain      string `json:"domain"`
		IncludeApex bool   `json:"include_apex"`
		ACME        *bool  `json:"acme"` // default true when no PEM pair is given
		CertPEM     string `json:"cert_pem"`
		KeyPEM      string `json:"key_pem"`
		ManagedBy   string `json:"managed_by"`
		Owner       string `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if in.ManagedBy != "" && !s.isService(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "managed certificates can only be created with the service token"})
		return
	}
	c := store.Certificate{Domain: in.Domain, IncludeApex: in.IncludeApex, CertPEM: in.CertPEM, KeyPEM: in.KeyPEM,
		ManagedBy: in.ManagedBy, Owner: in.Owner, ACME: in.CertPEM == ""}
	if in.ACME != nil {
		c.ACME = *in.ACME
	}
	if c.ACME {
		ci := s.certIssuer()
		switch {
		case ci == nil:
			writeJSON(w, http.StatusConflict, map[string]string{"error": "the built-in Let's Encrypt client is off (set acme_email in the settings or ACME=true)"})
			return
		case strings.HasPrefix(strings.TrimSpace(in.Domain), "*.") && !ci.HasDNS():
			writeJSON(w, http.StatusConflict, map[string]string{"error": "wildcard certificates need a DNS provider for the DNS-01 challenge: set dns_provider and dns_api_token in the settings first"})
			return
		}
	}
	if !c.ACME && c.CertPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "give cert_pem and key_pem, or use acme"})
		return
	}
	if err := s.store.CreateCertificate(&c); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrCertConflict) {
			status = http.StatusConflict
		}
		writeErr(w, status, err)
		return
	}
	if c.ACME {
		s.issueInBackground(c)
	}
	writeJSON(w, http.StatusCreated, s.view(c))
}

// issueInBackground runs the ACME order (DNS-01 can take a few minutes) and records the outcome on the
// certificate; GET /api/certificates shows it.
func (s *Server) issueInBackground(c store.Certificate) {
	ci := s.certIssuer()
	if ci == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		log.Printf("acme: obtaining certificate for %s", strings.Join(c.Names(), ", "))
		if err := ci.IssueCertificate(ctx, c.ID); err != nil {
			log.Printf("acme: %s: %v", c.Domain, err)
		}
	}()
}

func (s *Server) guardCert(w http.ResponseWriter, r *http.Request) (store.Certificate, bool) {
	id, ok := certID(w, r)
	if !ok {
		return store.Certificate{}, false
	}
	c, found := s.store.Certificate(id)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return c, false
	}
	if c.ManagedBy != "" && !s.isService(r) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("this certificate is managed by %s — change it there", c.ManagedBy)})
		return c, false
	}
	return c, true
}

// renewCertificate starts a new ACME order now (e.g. after fixing the DNS token).
func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.guardCert(w, r)
	if !ok {
		return
	}
	if !c.ACME || s.certIssuer() == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "this certificate is not issued by the built-in ACME client"})
		return
	}
	s.issueInBackground(c)
	writeJSON(w, http.StatusAccepted, s.view(c))
}

// uploadCertificatePair replaces the key pair (an uploaded certificate is not renewed automatically).
func (s *Server) uploadCertificatePair(w http.ResponseWriter, r *http.Request) {
	c, ok := s.guardCert(w, r)
	if !ok {
		return
	}
	var in struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	updated, err := s.store.SetCertificatePair(c.ID, in.CertPEM, in.KeyPEM, "upload")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.view(updated))
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.guardCert(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteCertificate(c.ID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
