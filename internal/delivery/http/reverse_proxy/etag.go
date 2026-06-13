package http_reverseproxy_handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

func computeETag(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func resolveETag(headers http.Header, body []byte) string {
	if etag := headers.Get("ETag"); etag != "" {
		return etag
	}

	return computeETag(body)
}

func normalizeETag(etag string) string {
	return strings.TrimPrefix(strings.TrimSpace(etag), "W/")
}

func etagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" || etag == "" {
		return false
	}

	target := normalizeETag(etag)
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || normalizeETag(candidate) == target {
			return true
		}
	}

	return false
}

func (h *Handler) applyETag(headers http.Header, body []byte) string {
	etag := resolveETag(headers, body)
	if etag != "" && headers.Get("ETag") == "" {
		headers.Set("ETag", etag)
	}

	return etag
}
