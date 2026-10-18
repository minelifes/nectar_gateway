// Package passthrough lets the HTTPS listener hand whole TLS connections to another server based on
// the SNI host name (without decrypting them). It is used during a migration from an existing proxy:
// hosts with a certificate here are terminated here, everything else is forwarded untouched, so the
// old proxy keeps serving its own certificates.
package passthrough

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Decide returns the upstream "host:port" for an SNI name, or "" to terminate TLS locally.
type Decide func(serverName string) string

// Listener wraps a TCP listener. Accept returns only the connections to terminate locally.
type Listener struct {
	net.Listener
	decide  Decide
	conns   chan net.Conn
	errs    chan error
	once    sync.Once
	closed  chan struct{}
	Timeout time.Duration // ClientHello read timeout (default 5s)
}

// Wrap starts accepting on l.
func Wrap(l net.Listener, decide Decide) *Listener {
	pl := &Listener{Listener: l, decide: decide, conns: make(chan net.Conn), errs: make(chan error, 1),
		closed: make(chan struct{}), Timeout: 5 * time.Second}
	go pl.loop()
	return pl
}

func (l *Listener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			select {
			case l.errs <- err:
			case <-l.closed:
			}
			return
		}
		go l.route(c)
	}
}

// Accept implements net.Listener.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func (l *Listener) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(l.Timeout))
	sni, peeked, err := PeekSNI(c)
	_ = c.SetReadDeadline(time.Time{})
	pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(peeked), c)}
	target := ""
	if err == nil {
		target = l.decide(sni)
	}
	if target == "" {
		select {
		case l.conns <- pc:
		case <-l.closed:
			c.Close()
		}
		return
	}
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("passthrough %s → %s: %v", sni, target, err)
		c.Close()
		return
	}
	pipe(pc, up)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(b, a)
	go cp(a, b)
	<-done
	<-done
	a.Close()
	b.Close()
}

// prefixConn replays bytes already read from the connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// CloseWrite half-closes the underlying TCP connection.
func (p *prefixConn) CloseWrite() error {
	if tc, ok := p.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

var errPeeked = errors.New("peeked")

// PeekSNI reads the TLS ClientHello from c and returns the server name and the bytes read.
// It uses crypto/tls to parse the hello and aborts the handshake right after.
func PeekSNI(c net.Conn) (string, []byte, error) {
	var buf bytes.Buffer
	var sni string
	err := tls.Server(readOnly{r: io.TeeReader(c, &buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errPeeked
		},
	}).Handshake()
	if sni != "" || errors.Is(err, errPeeked) {
		return sni, buf.Bytes(), nil
	}
	return "", buf.Bytes(), err
}

// readOnly is a net.Conn that only reads (writes are dropped: the peek never answers the client).
type readOnly struct{ r io.Reader }

func (c readOnly) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (readOnly) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnly) Close() error                       { return nil }
func (readOnly) LocalAddr() net.Addr                { return nil }
func (readOnly) RemoteAddr() net.Addr               { return nil }
func (readOnly) SetDeadline(t time.Time) error      { return nil }
func (readOnly) SetReadDeadline(t time.Time) error  { return nil }
func (readOnly) SetWriteDeadline(t time.Time) error { return nil }
