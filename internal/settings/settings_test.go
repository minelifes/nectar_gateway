package settings

import "testing"

type memKV map[string][]byte

func (m memKV) GetKV(k string) ([]byte, error) { return m[k], nil }
func (m memKV) SetKV(k string, v []byte) error { m[k] = v; return nil }

func TestACMEEmailAndHooks(t *testing.T) {
	kv := memKV{}
	s, err := Load(kv, Values{ACMEEmail: "env@example.com"})
	if err != nil || s.Get().ACMEEmail != "env@example.com" {
		t.Fatalf("default: %+v %v", s.Get(), err)
	}
	var seen []string
	s.OnChange(func(v Values) { seen = append(seen, v.ACMEEmail) })
	if err := s.Set(Values{ACMEEmail: "not-an-email"}); err == nil {
		t.Fatal("invalid email accepted")
	}
	if err := s.Set(Values{ACMEEmail: "  ops@example.com "}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "ops@example.com" {
		t.Fatalf("hook: %v", seen)
	}
	// the stored value wins over the env default after a restart
	s2, err := Load(kv, Values{ACMEEmail: "env@example.com", FallbackHTTP: "x:80"})
	if err != nil || s2.Get().ACMEEmail != "ops@example.com" {
		t.Fatalf("reload: %+v %v", s2.Get(), err)
	}
	if err := s.Set(Values{}); err != nil || s.Get().ACMEEmail != "" {
		t.Fatalf("clear: %+v %v", s.Get(), err)
	}
}

func TestAllowIPs(t *testing.T) {
	kv := memKV{}
	s, _ := Load(kv, Values{})
	if s.Allowed("203.0.113.7") {
		t.Fatal("empty allowlist allows")
	}
	for _, bad := range [][]string{{"not-an-ip"}, {"0.0.0.0/0"}, {"::/0"}, {"10.0.0.0/33"}} {
		if err := s.Set(Values{AllowIPs: bad}); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	if err := s.Set(Values{AllowIPs: []string{" 203.0.113.7 ", "198.51.100.0/24", "2001:db8::/32", "203.0.113.7", ""}}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get().AllowIPs; len(got) != 3 {
		t.Fatalf("normalized: %v", got)
	}
	for ip, want := range map[string]bool{"203.0.113.7": true, "203.0.113.8": false, "198.51.100.200": true, "::ffff:198.51.100.9": true,
		"2001:db8:1::5": true, "2001:db9::1": false, "garbage": false} {
		if s.Allowed(ip) != want {
			t.Errorf("Allowed(%s) != %v", ip, want)
		}
	}
	// kept across a restart
	s2, err := Load(kv, Values{})
	if err != nil || !s2.Allowed("198.51.100.1") {
		t.Fatalf("reload: %v", err)
	}
	if (*Settings)(nil).Allowed("198.51.100.1") {
		t.Fatal("nil settings allow")
	}
}
