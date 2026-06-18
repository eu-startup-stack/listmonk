package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthentikTrustedRequest(t *testing.T) {
	cases := []struct {
		name     string
		cfg      AuthentikConfig
		remote   string
		secret   string
		expected bool
	}{
		{"empty config fails closed", AuthentikConfig{Enabled: true}, "1.2.3.4:5678", "", false},
		{"exact IP match", AuthentikConfig{Enabled: true, TrustedIPs: []string{"10.0.0.5"}}, "10.0.0.5:1234", "", true},
		{"CIDR match", AuthentikConfig{Enabled: true, TrustedIPs: []string{"10.0.0.0/8"}}, "10.0.0.5:1234", "", true},
		{"IP mismatch", AuthentikConfig{Enabled: true, TrustedIPs: []string{"10.0.0.0/8"}}, "192.168.1.1:1234", "", false},
		{"secret match", AuthentikConfig{Enabled: true, TrustedSecret: "s3cr3t"}, "1.2.3.4:5678", "s3cr3t", true},
		{"secret mismatch", AuthentikConfig{Enabled: true, TrustedSecret: "s3cr3t"}, "1.2.3.4:5678", "wrong", false},
		{"secret empty header", AuthentikConfig{Enabled: true, TrustedSecret: "s3cr3t"}, "1.2.3.4:5678", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAuthentik(tc.cfg, nil, nil)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.secret != "" {
				r.Header.Set("X-Authentik-Trusted-Secret", tc.secret)
			}
			if got := a.trustedRequest(r); got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestAuthentikIdentityFromHeaders(t *testing.T) {
	a := NewAuthentik(AuthentikConfig{Enabled: true}, nil, nil)

	// Present.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-authentik-username", "alice")
	r.Header.Set("X-authentik-email", "Alice@Example.COM")
	r.Header.Set("X-authentik-name", "Alice Smith")
	r.Header.Set("X-authentik-groups", "listmonk-admin|devs|listmonk-editors")
	id, ok := a.identityFromHeaders(r)
	if !ok {
		t.Fatal("expected ok")
	}
	if id.Username != "alice" || id.Email != "alice@example.com" || id.Name != "Alice Smith" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if len(id.Groups) != 3 || id.Groups[0] != "listmonk-admin" {
		t.Fatalf("unexpected groups: %v", id.Groups)
	}

	// Missing username.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-authentik-email", "a@b.com")
	if _, ok := a.identityFromHeaders(r2); ok {
		t.Fatal("expected not ok for missing username")
	}

	// Missing email.
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.Header.Set("X-authentik-username", "alice")
	if _, ok := a.identityFromHeaders(r3); ok {
		t.Fatal("expected not ok for missing email")
	}
}

func TestAuthentikStripHeaders(t *testing.T) {
	a := NewAuthentik(AuthentikConfig{Enabled: true}, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-authentik-username", "alice")
	r.Header.Set("X-authentik-email", "a@b.com")
	r.Header.Set("X-Authentik-Groups", "g1")
	r.Header.Set("Content-Type", "application/json")
	a.stripAuthentikHeaders(r)
	for k := range r.Header {
		if len(k) >= 12 && k[:12] == "X-Authentik-" {
			t.Fatalf("authentik header %q not stripped", k)
		}
	}
	if r.Header.Get("Content-Type") == "" {
		t.Fatal("non-authentik header was stripped")
	}
}

func TestAuthentikRoleFromGroups(t *testing.T) {
	a := NewAuthentik(AuthentikConfig{Enabled: true, GroupPrefix: "listmonk"}, nil, nil)

	// No prefixed group → deny (roleID=0, hasRole=false, no error).
	roleID, hasRole, err := a.roleFromGroups([]string{"devs", "admins"})
	if err != nil || hasRole || roleID != 0 {
		t.Fatalf("expected deny (0, false, nil), got (%d, %v, %v)", roleID, hasRole, err)
	}

	// superadmin → SuperAdminRoleID (1). Does not need the role cache.
	roleID, hasRole, err = a.roleFromGroups([]string{"devs", "listmonk-superadmin"})
	if err != nil || !hasRole || roleID != 1 {
		t.Fatalf("expected (1, true, nil), got (%d, %v, %v)", roleID, hasRole, err)
	}

	// admin variant → 1.
	roleID, hasRole, err = a.roleFromGroups([]string{"listmonk-admin"})
	if err != nil || !hasRole || roleID != 1 {
		t.Fatalf("expected (1, true, nil), got (%d, %v, %v)", roleID, hasRole, err)
	}

	// super-admin variant → 1.
	roleID, hasRole, err = a.roleFromGroups([]string{"listmonk-super-admin"})
	if err != nil || !hasRole || roleID != 1 {
		t.Fatalf("expected (1, true, nil), got (%d, %v, %v)", roleID, hasRole, err)
	}

	// Case-insensitive prefix.
	roleID, hasRole, err = a.roleFromGroups([]string{"Listmonk-Admin"})
	if err != nil || !hasRole || roleID != 1 {
		t.Fatalf("expected (1, true, nil) for case-insensitive, got (%d, %v, %v)", roleID, hasRole, err)
	}
}
