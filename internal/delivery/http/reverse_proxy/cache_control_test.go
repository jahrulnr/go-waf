package http_reverseproxy_handler

import "testing"

func TestIsExternallyCacheable(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"public, max-age=3600", true},
		{"public, max-age=86400, must-revalidate", true},
		{"must-revalidate, no-cache, private", false},
		{"private, max-age=0", false},
		{"no-store", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := isExternallyCacheable(tc.header); got != tc.want {
			t.Fatalf("isExternallyCacheable(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}
