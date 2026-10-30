package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nectar_gateway/internal/acme"
)

// DNS records: the gateway manages A/AAAA records of names with the DNS provider from the settings
// (the token stays here). Controllers point new domains at the server with PUT /api/dns/records.

var dnsNameRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// newDNSRecords is replaced in tests.
var newDNSRecords = acme.NewDNSRecords

func (s *Server) dnsRecords() (acme.DNSRecords, error) {
	if s.settings == nil {
		return nil, errors.New("settings are not available")
	}
	v := s.settings.Get()
	if v.DNSProvider == "" {
		return nil, nil
	}
	return newDNSRecords(v.DNSProvider, v.DNSAPIToken)
}

func dnsName(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return name, dnsNameRe.MatchString(name)
}

func (s *Server) dnsSetup(w http.ResponseWriter) (acme.DNSRecords, bool) {
	p, err := s.dnsRecords()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	if p == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no DNS provider: set dns_provider and dns_api_token in the settings"})
		return nil, false
	}
	return p, true
}

func (s *Server) listDNSRecords(w http.ResponseWriter, r *http.Request) {
	name, ok := dnsName(r.URL.Query().Get("name"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a domain like app.example.com"})
		return
	}
	p, ok := s.dnsSetup(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	zone, recs, err := p.ListAddresses(ctx, name)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "zone": zone, "records": recs})
}

func (s *Server) putDNSRecords(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string   `json:"name"`
		IPs  []string `json:"ips"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	name, ok := dnsName(in.Name)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a domain like app.example.com"})
		return
	}
	if len(in.IPs) == 0 || len(in.IPs) > 20 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ips: 1–20 addresses"})
		return
	}
	for _, ip := range in.IPs {
		if net.ParseIP(strings.TrimSpace(ip)) == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address " + ip})
			return
		}
	}
	p, ok := s.dnsSetup(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := p.EnsureAddresses(ctx, name, in.IPs)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if res.Created+res.Deleted > 0 {
		log.Printf("dns: %s → %s (%d created, %d deleted)", name, strings.Join(in.IPs, ", "), res.Created, res.Deleted)
	}
	status := http.StatusOK
	if res.Conflict != "" {
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}

func (s *Server) deleteDNSRecords(w http.ResponseWriter, r *http.Request) {
	name, ok := dnsName(r.URL.Query().Get("name"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a domain like app.example.com"})
		return
	}
	p, ok := s.dnsSetup(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	n, err := p.DeleteAddresses(ctx, name)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if n > 0 {
		log.Printf("dns: deleted %d record(s) of %s", n, name)
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": n})
}
