package http_reverseproxy_handler

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jahrulnr/go-waf/pkg/logger"
)

// FetchData fetches data from the remote server and caches the response.
func (h *Handler) FetchData(c *gin.Context) {
	remote, err := url.Parse(h.config.HOST_DESTINATION)
	if err != nil {
		logger.Logger("[error] Failed to parse remote URL: ", err).Error()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	host := h.config.HOST
	if host == "" {
		host = c.Request.Host
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Director = func(req *http.Request) {
		req.Header = c.Request.Header
		req.Host = host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.URL.Path = c.Param("path")
		req.Header.Del("Accept-Encoding")
	}

	proxy.ModifyResponse = func(r *http.Response) error {
		if r.StatusCode != http.StatusOK {
			return nil // No need to cache non-200 responses
		}

		var bodyBuffer bytes.Buffer
		defer r.Body.Close()

		if _, err := io.Copy(&bodyBuffer, r.Body); err != nil {
			logger.Logger("[error] Failed to copy response body: ", err).Error()
			return err
		}

		body := bodyBuffer.Bytes()
		scheme := c.Request.URL.Scheme
		if scheme == "" {
			scheme = "http"
		}

		body = bytes.ReplaceAll(body, []byte(h.config.HOST_DESTINATION), []byte(fmt.Sprintf("%s://%s", scheme, c.Request.Host)))

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))

		if h.config.ENABLE_GZIP {
			r.Header.Del("Accept-Encoding")
			r.Header.Del("Vary")
		}

		// Cache the response if applicable
		if h.config.USE_CACHE && (c.Request.Method == "GET" || c.Request.Method == "HEAD") && !strings.Contains(r.Header.Get("Cache-Control"), "no-cache") {
			h.cacheResponse(c, r.Request.URL.String(), r.Header, body)
			r.Header.Set("X-Cache", "MISS")
		}

		return nil
	}

	proxy.Transport = h.backendTransport()

	start := time.Now()
	proxy.ServeHTTP(c.Writer, c.Request)
	if duration := time.Since(start); duration.Milliseconds() > 500 {
		logger.Logger("Backend too slow: ", duration.String(), c.Request.RequestURI).Warn()
	}
}

func (h *Handler) fetchAndCache(c *gin.Context, backendURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, backendURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header = c.Request.Header.Clone()
	req.Header.Del("Accept-Encoding")

	host := h.config.HOST
	if host == "" {
		host = c.Request.Host
	}
	req.Host = host

	client := &http.Client{Transport: h.backendTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	if strings.Contains(resp.Header.Get("Cache-Control"), "no-cache") {
		return nil, fmt.Errorf("backend response is not cacheable")
	}

	var bodyBuffer bytes.Buffer
	if _, err := io.Copy(&bodyBuffer, resp.Body); err != nil {
		return nil, err
	}

	body := bodyBuffer.Bytes()
	scheme := c.Request.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	body = bytes.ReplaceAll(body, []byte(h.config.HOST_DESTINATION), []byte(fmt.Sprintf("%s://%s", scheme, c.Request.Host)))

	headers := resp.Header.Clone()
	if h.config.ENABLE_GZIP {
		headers.Del("Accept-Encoding")
		headers.Del("Vary")
	}

	data := h.cacheResponse(c, backendURL, headers, body)
	if len(data) == 0 {
		return nil, fmt.Errorf("failed to store cache entry")
	}

	return data, nil
}

func (h *Handler) backendTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: h.config.IGNORE_SSL_VERIFY,
			MinVersion:         tls.VersionTLS10,
		},
	}
}
