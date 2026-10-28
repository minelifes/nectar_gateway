package acme

import "testing"

func TestSetEmailBeforeRegistration(t *testing.T) {
	i := New(nil, "a@example.com", "")
	i.SetEmail("b@example.com")
	if i.Email() != "b@example.com" {
		t.Fatalf("email: %q", i.Email())
	}
	i.SetEmail("b@example.com") // no-op
}
