package redis_cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jahrulnr/go-waf/internal/interface/repository"
	"github.com/jahrulnr/go-waf/pkg/logger"

	"github.com/redis/go-redis/v9"
)

// TTLCache is a Redis-based cache with time-to-live (TTL) expiration.
type TTLCache struct {
	client *redis.Client
	ctx    context.Context
}

// NewCache creates a new TTLCache instance connected to a Redis server.
func NewCache(ctx context.Context, redisClient *redis.Client) repository.CacheInterface {
	return &TTLCache{
		client: redisClient,
		ctx:    ctx,
	}
}

// Set adds a new item to the Redis cache with the specified key, value, and TTL.
func (c *TTLCache) Set(key string, value []byte, ttl time.Duration) {
	serializedValue, err := json.Marshal(value)
	if err != nil {
		logger.Logger("Error serializing value: ", err).Error()
		return
	}

	err = c.client.Set(c.ctx, key, serializedValue, ttl).Err()
	if err != nil {
		logger.Logger("Error setting value in Redis: ", err).Error()
	}
}

// Get retrieves the value associated with the given key from the Redis cache.
func (c *TTLCache) Get(key string) ([]byte, bool) {
	serializedValue, err := c.client.Get(c.ctx, key).Result()
	if err == redis.Nil {
		// Key does not exist
		return nil, false
	} else if err != nil {
		// Other Redis error
		logger.Logger("Error getting value from Redis: ", err).Error()
		return nil, false
	}

	var value []byte
	err = json.Unmarshal([]byte(serializedValue), &value)
	if err != nil {
		logger.Logger("Error deserializing value: ", err).Error()
		return nil, false
	}

	return value, true
}

// Pop removes and returns the item with the specified key from the Redis cache.
func (c *TTLCache) Pop(key string) ([]byte, bool) {
	serializedValue, err := c.client.GetDel(c.ctx, key).Result()
	if err == redis.Nil {
		// Key does not exist
		return nil, false
	} else if err != nil {
		// Other Redis error
		logger.Logger("Error getting value from Redis: ", err).Error()
		return nil, false
	}

	var value []byte
	err = json.Unmarshal([]byte(serializedValue), &value)
	if err != nil {
		logger.Logger("Error deserializing value: ", err).Error()
		return nil, false
	}

	return value, true
}

// Remove removes the item with the specified key from the Redis cache.
func (c *TTLCache) Remove(key string) {
	err := c.client.Del(c.ctx, key).Err()
	if err != nil {
		logger.Logger("Error removing key from Redis: ", err).Error()
	}
}

func (s *TTLCache) RemoveByPrefix(prefix string) {
	// Use Redis KEYS command to find all keys with the specified prefix
	keys, err := s.client.Keys(context.Background(), prefix+"*").Result()
	if err != nil {
		logger.Logger("[warn] Error retrieving keys from Redis: ", err).Warn()
		return
	}
	// Delete all matching keys
	if len(keys) > 0 {
		_, err = s.client.Del(context.Background(), keys...).Result()
		if err != nil {
			logger.Logger("[warn] Error deleting keys from Redis: ", err).Warn()
		}
	}
}

// GetTTL returns the remaining time before the specified key expires.
func (c *TTLCache) GetTTL(key string) (time.Duration, bool) {
	ttl, err := c.client.TTL(c.ctx, key).Result()
	if err == redis.Nil {
		// Key does not exist
		return 0, false
	} else if err != nil {
		// Other Redis error
		logger.Logger("Error getting TTL from Redis: ", err).Error()
		return 0, false
	}

	return ttl, true
}
