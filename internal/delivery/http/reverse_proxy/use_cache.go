package http_reverseproxy_handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jahrulnr/go-waf/pkg/logger"
	"github.com/vmihailenco/msgpack"
)

// cacheResponse caches the response data using MessagePack.
func (h *Handler) cacheResponse(c *gin.Context, url string, headers http.Header, body []byte) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.applyCacheDeviceKey(c)

	etag := h.applyETag(headers, body)

	cacheData := &CacheHandler{
		CacheURL:     url,
		CacheHeaders: headers,
		CacheData:    body,
		CacheETag:    etag,
	}
	data, err := msgpack.Marshal(cacheData)
	if err != nil {
		logger.Logger("[error] Failed to marshal cache data: ", err).Error()
		return nil
	}

	logger.Logger("[debug]", "Set new cache "+url).Debug()
	h.cacheDriver.Set(url, data, time.Duration(h.config.CACHE_TTL)*time.Second)
	return data
}

func (h *Handler) applyCacheDeviceKey(c *gin.Context) string {
	deviceKey := h.getDeviceKey(c)
	if deviceKey != "" {
		h.cacheDriver.SetKey(deviceKey)
	}
	return deviceKey
}

func (h *Handler) cacheFlightKey(url, deviceKey string) string {
	if deviceKey == "" {
		return url
	}
	return deviceKey + "\x00" + url
}

// UseCache retrieves cached data or builds it once per key under concurrent misses.
func (h *Handler) UseCache(c *gin.Context) {
	url := h.config.HOST_DESTINATION + c.Request.URL.String()
	deviceKey := h.applyCacheDeviceKey(c)

	if getCache, ok := h.cacheDriver.Get(url); ok {
		h.serveCachedResponse(c, url, getCache)
		return
	}

	logger.Logger("[debug] cache not found", url).Debug()

	flightKey := h.cacheFlightKey(url, deviceKey)
	result, err, _ := h.cacheBuildGroup.Do(flightKey, func() (interface{}, error) {
		h.applyCacheDeviceKey(c)

		if getCache, ok := h.cacheDriver.Get(url); ok {
			return getCache, nil
		}

		return h.fetchAndCache(c, url)
	})
	if err != nil {
		logger.Logger("[error] cache build failed, fallback to proxy: ", err).Error()
		h.FetchData(c)
		return
	}

	cacheBytes, ok := result.([]byte)
	if !ok || len(cacheBytes) == 0 {
		h.FetchData(c)
		return
	}

	h.serveCachedResponse(c, url, cacheBytes)
}

func (h *Handler) serveCachedResponse(c *gin.Context, url string, getCache []byte) {
	var cacheData CacheHandler
	if err := msgpack.Unmarshal(getCache, &cacheData); err != nil {
		logger.Logger("[error] Failed to unmarshal cache data: ", err).Error()
		go h.cacheDriver.Remove(url)
		h.FetchData(c)
		return
	}

	for key, headers := range cacheData.CacheHeaders {
		if len(headers) > 0 {
			c.Header(key, headers[0])
		}
	}

	etag := cacheData.CacheETag
	if etag == "" {
		etag = resolveETag(cacheData.CacheHeaders, cacheData.CacheData)
	}
	if etag != "" {
		c.Header("ETag", etag)
	}

	ttl, _ := h.cacheDriver.GetTTL(url)
	ttl = time.Duration(h.config.CACHE_TTL) - (ttl / time.Second)
	go func() {
		if ttl <= 0 {
			h.cacheDriver.Remove(url)
		}
	}()

	if h.config.ENABLE_GZIP {
		c.Header("Accept-Encoding", "")
		c.Header("Vary", "")
	}
	c.Header("Via", "")
	c.Header("Server", "")
	c.Header("X-Varnish", "")
	c.Header("X-Cache", "HIT")
	c.Header("X-Age", fmt.Sprintf("%d", ttl))

	if etagMatches(c.GetHeader("If-None-Match"), etag) {
		c.Status(http.StatusNotModified)
		return
	}

	if c.Request.Method == http.MethodHead {
		c.Status(http.StatusOK)
		return
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), cacheData.CacheData)
}
