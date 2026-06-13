package http_reverseproxy_handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func publicScheme(c *gin.Context) string {
	if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
		return proto
	}

	if c.Request.URL.Scheme != "" {
		return c.Request.URL.Scheme
	}

	return "http"
}

func backendRequestHeaders(c *gin.Context) http.Header {
	headers := c.Request.Header.Clone()
	headers.Del("X-Forwarded-Proto")
	headers.Del("X-Forwarded-Port")
	headers.Del("Forwarded")
	return headers
}
