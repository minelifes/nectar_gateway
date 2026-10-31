package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"nectar_gateway/internal/replica"
)

// Edge replicas (several gateways on several nodes; see package replica).

// replicaSnapshot: GET /api/replica/snapshot (service token) — what replicas copy.
func (s *Server) replicaSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.isService(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "the service token is required"})
		return
	}
	if s.follower != nil {
		writeErr(w, http.StatusConflict, replica.ErrReplica)
		return
	}
	var cfg []byte
	if s.settings != nil {
		v := s.settings.Get()
		v.DNSAPIToken = "" // replicas never use it
		cfg, _ = json.Marshal(v)
	}
	snap, err := s.store.ExportSnapshot(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	etag := snap.ETag()
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.replicas.Seen(r.Header.Get(replica.HeaderNode), host, r.Header.Get(replica.HeaderVersion), r.Header.Get(replica.HeaderError))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// replicaChallenge: GET /api/replica/challenge/{token} (service token) — ACME HTTP-01 answers for replicas.
func (s *Server) replicaChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.isService(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "the service token is required"})
		return
	}
	if s.challenge == nil {
		http.NotFound(w, r)
		return
	}
	resp, ok := s.challenge(r.PathValue("token"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(resp))
}

// listReplicas: GET /api/replicas — on the primary the replicas that pulled in the last hour; on a
// replica its own sync status.
func (s *Server) listReplicas(w http.ResponseWriter, r *http.Request) {
	if s.follower != nil {
		writeJSON(w, http.StatusOK, map[string]any{"role": "replica", "status": s.follower.Status()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": "primary", "replicas": s.replicas.List()})
}

// replicaReadOnly refuses changes on a replica (they would be overwritten by the next sync).
func (s *Server) replicaReadOnly(next http.Handler) http.Handler {
	if s.follower == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/api/") &&
			!strings.HasPrefix(r.URL.Path, "/api/auth/") && r.URL.Path != "/api/login" && r.URL.Path != "/api/logout" {
			writeErr(w, http.StatusConflict, replica.ErrReplica)
			return
		}
		next.ServeHTTP(w, r)
	})
}
