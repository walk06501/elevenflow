package webview2bridge

import "testing"

// TestHomeproxyParseProxy guards against the exact bug caught live 2026-08-22:
// fmt.Sscanf("%[^:]...") silently failed on every real proxy string (Go's
// fmt package has no C-style scanset verb) — this would have kept failing
// forever without a test, since the failure mode LOOKS like a data/vendor
// problem ("unexpected proxy field") rather than a parser bug.
func TestHomeproxyParseProxy(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		// Real strings observed live from homeproxy.vn's rotatev2 API.
		{"183.80.177.52:53097:eulaliawatsi980:K6fHTGJ4TiY8qYgEv4-91w", false},
		{"14.187.152.21:51153:elnajones502:20-elRSAlWoepIBq0liRrA", false},
		{"42.113.198.50:59734:lilaolson958:cXStCuGX7kV5xwHXXXVaiw", false},
		{"", true},
		{"onlyhost", true},
		{"host:port", true}, // missing user/pass
	}
	for _, c := range cases {
		got, err := homeproxyParseProxy(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("homeproxyParseProxy(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("homeproxyParseProxy(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got == "" {
			t.Errorf("homeproxyParseProxy(%q) returned empty URL", c.in)
		}
	}
}
