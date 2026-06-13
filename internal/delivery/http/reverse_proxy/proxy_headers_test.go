package http_reverseproxy_handler

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBackendRequestHeadersStripsForwardedProto(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(nil)
	c.Request = &http.Request{
		Header: http.Header{
			"X-Forwarded-Proto": {"https"},
			"X-Forwarded-Port":  {"443"},
			"Forwarded":         {`for=1.2.3.4;proto=https`},
			"Host":              {"bangunsoft.com"},
		},
	}

	headers := backendRequestHeaders(c)
	if headers.Get("X-Forwarded-Proto") != "" {
		t.Fatalf("expected X-Forwarded-Proto to be stripped, got %q", headers.Get("X-Forwarded-Proto"))
	}
	if headers.Get("X-Forwarded-Port") != "" {
		t.Fatalf("expected X-Forwarded-Port to be stripped")
	}
	if headers.Get("Forwarded") != "" {
		t.Fatalf("expected Forwarded to be stripped")
	}
	if headers.Get("Host") != "bangunsoft.com" {
		t.Fatalf("expected Host header to be preserved")
	}
}

func TestPublicSchemeUsesForwardedProto(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(nil)
	c.Request = &http.Request{
		Header: http.Header{
			"X-Forwarded-Proto": {"https"},
		},
	}

	if got := publicScheme(c); got != "https" {
		t.Fatalf("expected https, got %q", got)
	}
}
