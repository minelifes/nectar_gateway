// Package metrics keeps in-memory request statistics per domain (last 60 minutes, per minute)
// and a ring buffer of recent requests (access log). Nothing is persisted: the panel samples it.
package metrics

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Latency bucket upper bounds in milliseconds (the last bucket is everything above).
var bucketsMS = [...]int64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

const (
	nBuckets   = len(bucketsMS) + 1
	window     = 60 // minutes kept per domain
	maxDomains = 5000
	// Unknown aggregates requests for hosts without a route.
	Unknown = "(unknown)"
	// Fallback aggregates requests passed to the fallback upstream.
	Fallback = "(fallback)"
)

type minute struct {
	at       int64 // unix minute (seconds / 60)
	requests int64
	status   [6]int64 // index = status / 100 (1xx..5xx)
	bytesOut int64
	bytesIn  int64
	latency  [nBuckets]int64
}

type domain struct {
	minutes [window]minute
	last    int64 // unix seconds of the last request
}

// Entry is one access-log line.
type Entry struct {
	Time      time.Time `json:"time"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	BytesOut  int64     `json:"bytes_out"`
	BytesIn   int64     `json:"bytes_in"`
	MS        int64     `json:"ms"`
	UserAgent string    `json:"user_agent,omitempty"`
	Domain    string    `json:"domain"` // matched route domain (or "(unknown)")
}

// Recorder collects statistics. It is safe for concurrent use; the zero value is not usable.
type Recorder struct {
	mu      sync.Mutex
	domains map[string]*domain
	log     []Entry
	next    int // ring position
	full    bool
	now     func() time.Time

	fallback      map[string]*FallbackHit // host -> long-lived fallback counters
	fallbackDirty bool
}

// New returns a recorder keeping logSize access-log entries.
func New(logSize int) *Recorder {
	if logSize <= 0 {
		logSize = 1000
	}
	return &Recorder{domains: map[string]*domain{}, log: make([]Entry, logSize), now: time.Now}
}

func bucket(ms int64) int {
	for i, b := range bucketsMS {
		if ms <= b {
			return i
		}
	}
	return nBuckets - 1
}

// Record adds one finished request.
func (r *Recorder) Record(e Entry) {
	if r == nil {
		return
	}
	if len(e.Path) > 300 {
		e.Path = e.Path[:300]
	}
	if len(e.UserAgent) > 200 {
		e.UserAgent = e.UserAgent[:200]
	}
	if e.Domain == "" {
		e.Domain = Unknown
	}
	now := r.now()
	if e.Time.IsZero() {
		e.Time = now
	}
	m := now.Unix() / 60
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.domains[e.Domain]
	if !ok {
		if len(r.domains) >= maxDomains {
			r.evictLocked(now.Unix())
		}
		d = &domain{}
		r.domains[e.Domain] = d
	}
	slot := &d.minutes[m%window]
	if slot.at != m {
		*slot = minute{at: m}
	}
	slot.requests++
	if s := e.Status / 100; s >= 1 && s <= 5 {
		slot.status[s]++
	}
	slot.bytesOut += e.BytesOut
	slot.bytesIn += e.BytesIn
	slot.latency[bucket(e.MS)]++
	d.last = now.Unix()
	if e.Domain == Fallback {
		r.recordFallbackLocked(e.Host, FallbackKindHTTP, now)
	}

	r.log[r.next] = e
	r.next = (r.next + 1) % len(r.log)
	if r.next == 0 {
		r.full = true
	}
}

// evictLocked drops domains idle for more than the window (or the oldest one).
func (r *Recorder) evictLocked(now int64) {
	var oldest string
	var oldestAt int64 = 1<<63 - 1
	for k, d := range r.domains {
		if now-d.last > window*60 {
			delete(r.domains, k)
		} else if d.last < oldestAt {
			oldest, oldestAt = k, d.last
		}
	}
	if len(r.domains) >= maxDomains {
		delete(r.domains, oldest)
	}
}

// Point is one minute of a series.
type Point struct {
	Time     time.Time `json:"time"`
	Requests int64     `json:"requests"`
	Errors   int64     `json:"errors"` // 5xx
	BytesOut int64     `json:"bytes_out"`
	P50MS    int64     `json:"p50_ms"`
	P95MS    int64     `json:"p95_ms"`
}

// Summary describes a domain over the requested period.
type Summary struct {
	Domain    string    `json:"domain"`
	Minutes   int       `json:"minutes"`
	Requests  int64     `json:"requests"`
	RPS       float64   `json:"rps"`
	Status    StatusMix `json:"status"`
	ErrorRate float64   `json:"error_rate"` // share of 5xx
	BytesOut  int64     `json:"bytes_out"`
	BytesIn   int64     `json:"bytes_in"`
	P50MS     int64     `json:"p50_ms"`
	P95MS     int64     `json:"p95_ms"`
	P99MS     int64     `json:"p99_ms"`
	LastSeen  time.Time `json:"last_seen"`
	Series    []Point   `json:"series,omitempty"`
}

// StatusMix counts responses by class.
type StatusMix struct {
	S2xx int64 `json:"2xx"`
	S3xx int64 `json:"3xx"`
	S4xx int64 `json:"4xx"`
	S5xx int64 `json:"5xx"`
}

// percentile returns the upper bound (ms) of the bucket containing quantile q.
func percentile(h [nBuckets]int64, q float64) int64 {
	var total int64
	for _, c := range h {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := int64(float64(total)*q + 0.999999)
	var acc int64
	for i, c := range h {
		acc += c
		if acc >= target {
			if i < len(bucketsMS) {
				return bucketsMS[i]
			}
			return bucketsMS[len(bucketsMS)-1] * 2 // "more than 10s"
		}
	}
	return 0
}

// Summaries returns statistics for the last `minutes` minutes (1–60), busiest domains first.
// If domainFilter is set only that domain is returned; withSeries adds per-minute points.
func (r *Recorder) Summaries(minutes int, domainFilter string, withSeries bool) []Summary {
	if r == nil {
		return nil
	}
	if minutes <= 0 || minutes > window {
		minutes = window
	}
	nowMin := r.now().Unix() / 60
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Summary{}
	for name, d := range r.domains {
		if domainFilter != "" && !strings.EqualFold(name, domainFilter) {
			continue
		}
		s := Summary{Domain: name, Minutes: minutes, LastSeen: time.Unix(d.last, 0).UTC()}
		var hist [nBuckets]int64
		for i := minutes - 1; i >= 0; i-- {
			m := nowMin - int64(i)
			slot := d.minutes[m%window]
			p := Point{Time: time.Unix(m*60, 0).UTC()}
			if slot.at == m {
				s.Requests += slot.requests
				s.Status.S2xx += slot.status[2]
				s.Status.S3xx += slot.status[3]
				s.Status.S4xx += slot.status[4]
				s.Status.S5xx += slot.status[5]
				s.BytesOut += slot.bytesOut
				s.BytesIn += slot.bytesIn
				for b := range hist {
					hist[b] += slot.latency[b]
				}
				p.Requests, p.Errors, p.BytesOut = slot.requests, slot.status[5], slot.bytesOut
				p.P50MS, p.P95MS = percentile(slot.latency, 0.50), percentile(slot.latency, 0.95)
			}
			if withSeries {
				s.Series = append(s.Series, p)
			}
		}
		if s.Requests == 0 && domainFilter == "" {
			continue
		}
		s.RPS = float64(s.Requests) / float64(minutes*60)
		if s.Requests > 0 {
			s.ErrorRate = float64(s.Status.S5xx) / float64(s.Requests)
		}
		s.P50MS, s.P95MS, s.P99MS = percentile(hist, 0.50), percentile(hist, 0.95), percentile(hist, 0.99)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

// LogQuery filters the access log.
type LogQuery struct {
	Domain string // matched route domain or request host
	Status int    // exact status, or 2..5 for a class (e.g. 5 = 5xx); 0 = any
	IP     string
	Limit  int // default 100, max = log size
}

// Log returns matching access-log entries, newest first.
func (r *Recorder) Log(q LogQuery) []Entry {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if q.Limit <= 0 {
		q.Limit = 100
	}
	n := r.next
	if r.full {
		n = len(r.log)
	}
	out := []Entry{}
	for i := 0; i < n && len(out) < q.Limit; i++ {
		e := r.log[(r.next-1-i+len(r.log))%len(r.log)]
		if q.Domain != "" && !strings.EqualFold(e.Domain, q.Domain) && !strings.EqualFold(e.Host, q.Domain) {
			continue
		}
		if q.Status >= 1 && q.Status <= 5 && e.Status/100 != q.Status {
			continue
		}
		if q.Status > 5 && e.Status != q.Status {
			continue
		}
		if q.IP != "" && e.IP != q.IP {
			continue
		}
		out = append(out, e)
	}
	return out
}
