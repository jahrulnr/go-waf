package http_reverseproxy_handler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func (h *Handler) fetchBackendGETBody(c *gin.Context, backendURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, backendURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header = backendRequestHeaders(c)
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

	var bodyBuffer bytes.Buffer
	if _, err := io.Copy(&bodyBuffer, resp.Body); err != nil {
		return nil, err
	}

	body := bodyBuffer.Bytes()
	scheme := publicScheme(c)
	return bytes.ReplaceAll(body, []byte(h.config.HOST_DESTINATION), []byte(fmt.Sprintf("%s://%s", scheme, c.Request.Host))), nil
}

func (h *Handler) backendURL(c *gin.Context, remote *url.URL) string {
	path := c.Param("path")
	if path == "" {
		path = c.Request.URL.Path
	}

	return remote.Scheme + "://" + remote.Host + path
}
