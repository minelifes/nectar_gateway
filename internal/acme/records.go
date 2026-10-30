package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// RecordComment marks DNS records created by the gateway; only those are changed or deleted.
const RecordComment = "managed by nectar-gateway"

// DNSRecord is an address record of a name.
type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"` // A | AAAA | CNAME
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	Managed bool   `json:"managed"` // created by the gateway
}

// RecordResult is what EnsureAddresses did.
type RecordResult struct {
	Zone    string      `json:"zone"`
	Records []DNSRecord `json:"records"`
	Created int         `json:"created"`
	Deleted int         `json:"deleted"`
	// Conflict: the name already has records the gateway did not create; they are left alone.
	Conflict string `json:"conflict,omitempty"`
}

// DNSRecords manages the address records of names (A/AAAA) at the DNS provider.
type DNSRecords interface {
	ListAddresses(ctx context.Context, name string) (zone string, recs []DNSRecord, err error)
	EnsureAddresses(ctx context.Context, name string, ips []string) (RecordResult, error)
	DeleteAddresses(ctx context.Context, name string) (deleted int, err error)
}

// NewDNSRecords returns the record manager for a settings value (nil, nil = no provider).
func NewDNSRecords(kind, token string) (DNSRecords, error) {
	p, err := NewDNSProvider(kind, token)
	if err != nil || p == nil {
		return nil, err
	}
	r, ok := p.(DNSRecords)
	if !ok {
		return nil, fmt.Errorf("DNS provider %q cannot manage records", kind)
	}
	return r, nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

func (c *Cloudflare) records(ctx context.Context, zone, name string) ([]cfRecord, error) {
	var recs []cfRecord
	err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?per_page=100&name="+url.QueryEscape(name), nil, &recs)
	out := recs[:0]
	for _, r := range recs {
		if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
			out = append(out, r)
		}
	}
	return out, err
}

func toRecord(r cfRecord) DNSRecord {
	return DNSRecord{ID: r.ID, Type: r.Type, Name: r.Name, Content: r.Content, Proxied: r.Proxied, Managed: r.Comment == RecordComment}
}

// ListAddresses implements DNSRecords.
func (c *Cloudflare) ListAddresses(ctx context.Context, name string) (string, []DNSRecord, error) {
	zone, err := c.zone(ctx, name)
	if err != nil {
		return "", nil, err
	}
	recs, err := c.records(ctx, zone, name)
	if err != nil {
		return "", nil, err
	}
	out := make([]DNSRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, toRecord(r))
	}
	return zone, out, nil
}

// EnsureAddresses makes the gateway's A/AAAA records of name exactly ips: missing ones are created,
// stale ones deleted. Records someone else created are never touched; if any exist (or a CNAME),
// nothing is changed and Conflict says why.
func (c *Cloudflare) EnsureAddresses(ctx context.Context, name string, ips []string) (RecordResult, error) {
	res := RecordResult{Records: []DNSRecord{}}
	want := map[string]string{} // ip → type
	for _, s := range ips {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return res, fmt.Errorf("invalid IP address %q", s)
		}
		if ip.To4() != nil {
			want[ip.String()] = "A"
		} else {
			want[ip.String()] = "AAAA"
		}
	}
	if len(want) == 0 {
		return res, errors.New("no addresses to point the name to")
	}
	zone, err := c.zone(ctx, name)
	if err != nil {
		return res, err
	}
	res.Zone = zone
	recs, err := c.records(ctx, zone, name)
	if err != nil {
		return res, err
	}
	var foreign []string
	for _, r := range recs {
		if r.Comment != RecordComment {
			foreign = append(foreign, r.Type+" "+r.Content)
		}
	}
	if len(foreign) > 0 {
		for _, r := range recs {
			res.Records = append(res.Records, toRecord(r))
		}
		res.Conflict = name + " already has records the gateway did not create (" + strings.Join(foreign, ", ") + "); change them by hand or delete them first"
		return res, nil
	}
	have := map[string]bool{}
	for _, r := range recs {
		ip := net.ParseIP(r.Content)
		if ip != nil && want[ip.String()] == r.Type {
			have[ip.String()] = true
			res.Records = append(res.Records, toRecord(r))
			continue
		}
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil); err != nil {
			return res, err
		}
		res.Deleted++
	}
	keys := make([]string, 0, len(want))
	for ip := range want {
		keys = append(keys, ip)
	}
	slices.Sort(keys)
	for _, ip := range keys {
		if have[ip] {
			continue
		}
		var created cfRecord
		if err := c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records",
			map[string]any{"type": want[ip], "name": name, "content": ip, "ttl": 1, "proxied": false, "comment": RecordComment}, &created); err != nil {
			return res, err
		}
		res.Created++
		res.Records = append(res.Records, toRecord(created))
	}
	return res, nil
}

// DeleteAddresses removes the address records of name that the gateway created.
func (c *Cloudflare) DeleteAddresses(ctx context.Context, name string) (int, error) {
	zone, err := c.zone(ctx, name)
	if err != nil {
		return 0, err
	}
	recs, err := c.records(ctx, zone, name)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range recs {
		if r.Comment != RecordComment {
			continue
		}
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
