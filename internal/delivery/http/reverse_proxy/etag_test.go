package http_reverseproxy_handler

import (
	"net/http"
	"testing"
)

func TestComputeETag(t *testing.T) {
	etag := computeETag([]byte("hello"))
	if etag == "" {
		t.Fatal("expected etag")
	}

	if computeETag(nil) != "" {
		t.Fatal("empty body should not produce etag")
	}
}

func TestEtagMatches(t *testing.T) {
	etag := `"abc123"`

	if !etagMatches(`"abc123"`, etag) {
		t.Fatal("exact match should pass")
	}

	if !etagMatches(`W/"abc123"`, etag) {
		t.Fatal("weak etag should match strong etag")
	}

	if !etagMatches(`"other", "abc123"`, etag) {
		t.Fatal("list match should pass")
	}

	if etagMatches(`"other"`, etag) {
		t.Fatal("different etag should not match")
	}
}

func TestResolveETagUsesBackendHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("ETag", `"backend"`)

	if got := resolveETag(headers, []byte("body")); got != `"backend"` {
		t.Fatalf("expected backend etag, got %s", got)
	}
}

func TestApplyETagSetsHeaderWhenMissing(t *testing.T) {
	h := &Handler{}
	headers := http.Header{}

	etag := h.applyETag(headers, []byte("payload"))
	if etag == "" {
		t.Fatal("expected generated etag")
	}

	if headers.Get("ETag") != etag {
		t.Fatalf("expected header %s, got %s", etag, headers.Get("ETag"))
	}
}
