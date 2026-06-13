package http_reverseproxy_handler

import "strings"

func isExternallyCacheable(cacheControl string) bool {
	if cacheControl == "" {
		return false
	}

	lower := strings.ToLower(cacheControl)
	if strings.Contains(lower, "no-store") || strings.Contains(lower, "no-cache") || strings.Contains(lower, "private") {
		return false
	}

	return strings.Contains(lower, "public") || strings.Contains(lower, "max-age")
}
