package http_reverseproxy_handler

import (
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/jahrulnr/go-waf/config"
	"github.com/jahrulnr/go-waf/internal/interface/service"
	"golang.org/x/sync/singleflight"
)

type Handler struct {
	config          *config.Config
	cacheDriver     service.CacheInterface
	mu              sync.Mutex
	cacheBuildGroup singleflight.Group
}

type CacheHandler struct {
	CacheURL     string              `json:"url"`
	CacheHeaders map[string][]string `json:"headers"`
	CacheData    []byte              `json:"data"`
	CacheETag    string              `json:"etag"`
}

// NewHttpHandler initializes a new HTTP handler with the given configuration and cache driver.
func NewHttpHandler(config *config.Config, handler *gin.Engine, cacheDriver service.CacheInterface) *Handler {
	return &Handler{
		config:      config,
		cacheDriver: cacheDriver,
	}
}

// ReverseProxy handles the reverse proxy logic, using cache if applicable.
func (h *Handler) ReverseProxy(c *gin.Context) {
	if h.config.USE_CACHE && (c.Request.Method == "GET" || c.Request.Method == "HEAD") {
		h.UseCache(c)
	} else {
		h.FetchData(c)
	}
}

// getDeviceKey retrieves the device key from the request context.
func (h *Handler) getDeviceKey(c *gin.Context) string {
	if deviceKey := c.GetHeader("X-Device"); deviceKey != "" && h.config.DETECT_DEVICE && h.config.SPLIT_CACHE_BY_DEVICE {
		return deviceKey
	}
	return ""
}
