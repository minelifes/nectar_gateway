// Package nginx parses nginx configuration files and converts
// server blocks into nectar_gateway routes.
package nginx

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"nectar_gateway/internal/store"
)

// Directive is one nginx directive, optionally with a { } block.
type Directive struct {
	Name  string
	Args  []string
	Block []Directive // nil if simple "name args;" directive
}

// ImportResult is what a parsed nginx config translates to.
type ImportResult struct {
	Routes  []store.Route `json:"routes"`
	Skipped []string      `json:"skipped"` // human-readable reasons
}

// Parse converts nginx config text into routes.
func Parse(config string) (*ImportResult, error) {
	dirs, err := parseBlock(newLexer(config))
	if err != nil {
		return nil, err
	}
	res := &ImportResult{Routes: []store.Route{}, Skipped: []string{}}
	upstreams := map[string]string{} // name -> host:port
	collectUpstreams(dirs, upstreams)
	forceSSL := map[string]bool{} // domains with an http->https redirect block
	collectServers(dirs, upstreams, forceSSL, res)
	// apply force_ssl collected from redirect-only server blocks
	matched := map[string]bool{}
	for i := range res.Routes {
		if forceSSL[res.Routes[i].Domain] && res.Routes[i].HasSSL() {
			res.Routes[i].ForceSSL = true
			matched[res.Routes[i].Domain] = true
		}
	}
	for d := range forceSSL {
		if !matched[d] {
			res.Skipped = append(res.Skipped, d+": https-redirect block without matching ssl server block")
		}
	}
	return res, nil
}

// ---- lexer ----

type lexer struct {
	src []rune
	pos int
}

func newLexer(s string) *lexer { return &lexer{src: []rune(s)} }

func (l *lexer) skipSpaceAndComments() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '#' {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		} else if unicode.IsSpace(c) {
			l.pos++
		} else {
			return
		}
	}
}

// next returns the next token: a word, quoted string, "{", "}" or ";".
// ok=false at end of input.
func (l *lexer) next() (tok string, ok bool) {
	l.skipSpaceAndComments()
	if l.pos >= len(l.src) {
		return "", false
	}
	c := l.src[l.pos]
	switch c {
	case '{', '}', ';':
		l.pos++
		return string(c), true
	case '"', '\'':
		quote := c
		l.pos++
		start := l.pos
		var b strings.Builder
		for l.pos < len(l.src) && l.src[l.pos] != quote {
			if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
				b.WriteString(string(l.src[start:l.pos]))
				l.pos++
				start = l.pos
			}
			l.pos++
		}
		b.WriteString(string(l.src[start:l.pos]))
		l.pos++ // closing quote
		return b.String(), true
	default:
		start := l.pos
		for l.pos < len(l.src) {
			c := l.src[l.pos]
			if unicode.IsSpace(c) || c == '{' || c == '}' || c == ';' || c == '#' {
				break
			}
			l.pos++
		}
		return string(l.src[start:l.pos]), true
	}
}

// ---- parser ----

func parseBlock(l *lexer) ([]Directive, error) {
	var dirs []Directive
	var current []string
	for {
		tok, ok := l.next()
		if !ok {
			if len(current) > 0 {
				return nil, fmt.Errorf("unexpected end of config after %q", strings.Join(current, " "))
			}
			return dirs, nil
		}
		switch tok {
		case ";":
			if len(current) == 0 {
				continue
			}
			dirs = append(dirs, Directive{Name: current[0], Args: current[1:]})
			current = nil
		case "{":
			if len(current) == 0 {
				return nil, fmt.Errorf("unexpected '{'")
			}
			block, err := parseBlock(l)
			if err != nil {
				return nil, err
			}
			dirs = append(dirs, Directive{Name: current[0], Args: current[1:], Block: block})
			current = nil
		case "}":
			if len(current) > 0 {
				return nil, fmt.Errorf("missing ';' before '}' near %q", strings.Join(current, " "))
			}
			return dirs, nil
		default:
			current = append(current, tok)
		}
	}
}

// ---- extraction ----

func collectUpstreams(dirs []Directive, out map[string]string) {
	for _, d := range dirs {
		if d.Name == "upstream" && len(d.Args) > 0 && d.Block != nil {
			for _, s := range d.Block {
				if s.Name == "server" && len(s.Args) > 0 {
					out[d.Args[0]] = s.Args[0] // first backend wins
					break
				}
			}
		}
		if d.Block != nil {
			collectUpstreams(d.Block, out)
		}
	}
}

func collectServers(dirs []Directive, upstreams map[string]string, forceSSL map[string]bool, res *ImportResult) {
	for _, d := range dirs {
		if d.Name == "server" && d.Block != nil {
			extractServer(d.Block, upstreams, forceSSL, res)
			continue
		}
		if d.Block != nil {
			collectServers(d.Block, upstreams, forceSSL, res)
		}
	}
}

func extractServer(block []Directive, upstreams map[string]string, forceSSL map[string]bool, res *ImportResult) {
	var names []string
	var rootDir string
	var proxyPass string
	var certFile, keyFile string
	var httpsRedirect bool

	// server-level directives
	for _, d := range block {
		switch d.Name {
		case "server_name":
			names = append(names, d.Args...)
		case "root":
			if len(d.Args) > 0 && rootDir == "" {
				rootDir = d.Args[0]
			}
		case "proxy_pass":
			if len(d.Args) > 0 && proxyPass == "" {
				proxyPass = d.Args[0]
			}
		case "ssl_certificate":
			if len(d.Args) > 0 && certFile == "" {
				certFile = d.Args[0]
			}
		case "ssl_certificate_key":
			if len(d.Args) > 0 && keyFile == "" {
				keyFile = d.Args[0]
			}
		case "return":
			// e.g. "return 301 https://$host$request_uri;"
			if len(d.Args) >= 2 && strings.HasPrefix(d.Args[1], "https://") {
				httpsRedirect = true
			}
		}
	}
	// redirect inside "location /" counts too
	for _, d := range block {
		if d.Name != "location" || d.Block == nil {
			continue
		}
		for _, ld := range d.Block {
			if ld.Name == "return" && len(ld.Args) >= 2 && strings.HasPrefix(ld.Args[1], "https://") {
				httpsRedirect = true
			}
		}
	}

	// location blocks: prefer "location /", otherwise first match
	var locRoot, locProxy string
	var rootFromSlash, proxyFromSlash bool
	for _, d := range block {
		if d.Name != "location" || d.Block == nil {
			continue
		}
		isSlash := len(d.Args) > 0 && d.Args[len(d.Args)-1] == "/"
		for _, ld := range d.Block {
			switch ld.Name {
			case "proxy_pass":
				if len(ld.Args) > 0 && (locProxy == "" || (isSlash && !proxyFromSlash)) {
					locProxy = ld.Args[0]
					proxyFromSlash = isSlash
				}
			case "root", "alias":
				if len(ld.Args) > 0 && (locRoot == "" || (isSlash && !rootFromSlash)) {
					locRoot = ld.Args[0]
					rootFromSlash = isSlash
				}
			}
		}
	}
	if proxyPass == "" {
		proxyPass = locProxy
	}
	if rootDir == "" || rootFromSlash {
		if locRoot != "" {
			rootDir = locRoot
		}
	}

	if len(names) == 0 {
		res.Skipped = append(res.Skipped, "server block without server_name skipped")
		return
	}

	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		switch {
		case name == "" || name == "_" || name == "default_server":
			continue
		case strings.ContainsAny(name, "*~^$"):
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: wildcard/regex server_name not supported", name))
			continue
		}
		// redirect-only block (typical port-80 -> https shim): remember and move on
		if httpsRedirect && proxyPass == "" && rootDir == "" {
			forceSSL[name] = true
			continue
		}
		route := store.Route{Domain: name, CertFile: certFile, KeyFile: keyFile}
		switch {
		case proxyPass != "":
			ip, port, err := resolveProxyPass(proxyPass, upstreams)
			if err != nil {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			route.Mode = store.ModeProxy
			route.TargetIP = ip
			route.TargetPort = port
		case rootDir != "":
			route.Mode = store.ModeStatic
			route.StaticDir = rootDir
		default:
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: no proxy_pass or root found", name))
			continue
		}
		res.Routes = append(res.Routes, route)
	}
}

func resolveProxyPass(raw string, upstreams map[string]string) (string, int, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, fmt.Errorf("cannot parse proxy_pass %q", raw)
	}
	host, portStr := u.Hostname(), u.Port()

	// upstream reference?
	if target, ok := upstreams[host]; ok {
		h, p, err := net.SplitHostPort(target)
		if err != nil {
			return target, 80, nil
		}
		port, _ := strconv.Atoi(p)
		return h, port, nil
	}

	port := 80
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	} else if u.Scheme == "https" {
		port = 443
	}
	return host, port, nil
}
