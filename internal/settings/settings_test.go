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
