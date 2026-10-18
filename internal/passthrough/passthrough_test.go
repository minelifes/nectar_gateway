package passthrough

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func cert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS runs an HTTPS server answering "<name>" on ln with a certificate for name.
func serveTLS(t *testing.T, ln net.Listener, name string) {
	t.Helper()
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, name) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert(t, name)}},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
}

func fetch(t *testing.T, addr, sni string) (string, string) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial %s: %v", sni, err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(conn)
	peer := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	return peer, string(b)
}

func TestSNIRouting(t *testing.T) {
	// the "old proxy" with its own certificate
	oldLn, _ := net.Listen("tcp", "127.0.0.1:0")
	serveTLS(t, oldLn, "legacy.example.com")

	// the gateway: terminates new.example.com, passes everything else through
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	pl := Wrap(raw, func(sni string) string {
		if sni == "new.example.com" {
			return ""
		}
		return oldLn.Addr().String()
	})
	serveTLS(t, pl, "new.example.com")

	if peer, body := fetch(t, raw.Addr().String(), "new.example.com"); peer != "new.example.com" || !strings.Contains(body, "new.example.com") {
		t.Fatalf("local: cert %s body %q", peer, body)
	}
	if peer, body := fetch(t, raw.Addr().String(), "legacy.example.com"); peer != "legacy.example.com" || !strings.Contains(body, "legacy.example.com") {
		t.Fatalf("passthrough: cert %s body %q", peer, body)
	}
	pl.Close()
}

func TestPeekSNIOnGarbage(t *testing.T) {
	a, b := net.Pipe()
	go func() { a.Write([]byte("GET / HTTP/1.1\r\n\r\n")); a.Close() }()
	if sni, peeked, err := PeekSNI(b); err == nil || sni != "" || len(peeked) == 0 {
		t.Fatalf("garbage: %q %d %v", sni, len(peeked), err)
	}
}
