package credentials

import (
	"context"
	"sync"
	"time"
)

type ReplayChecker interface {
	Seen(ctx context.Context, id string, expiresAt time.Time) bool
}

// memoryReplayChecker is a simple in-memory implementation of ReplayChecker.
type memoryReplayChecker struct {
	mu     sync.Mutex
	seen   map[string]time.Time // id -> expiration time
	ticker *time.Ticker
	done   chan struct{}
}

// NewMemoryReplayChecker creates a new in-memory replay checker.
// cleanupInterval defines how often expired entries will be purged.
func NewMemoryReplayChecker(cleanupInterval time.Duration) ReplayChecker {
	rc := &memoryReplayChecker{
		seen:   make(map[string]time.Time),
		ticker: time.NewTicker(cleanupInterval),
		done:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go rc.cleanupLoop()

	return rc
}

func (rc *memoryReplayChecker) Seen(ctx context.Context, id string, expiresAt time.Time) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// If token was already seen and not expired → replay
	if exp, ok := rc.seen[id]; ok {
		if time.Now().Before(exp) {
			return true
		}
		// Expired, remove and treat as unseen
		delete(rc.seen, id)
	}

	// Mark as seen until expiresAt
	rc.seen[id] = expiresAt
	return false
}

func (rc *memoryReplayChecker) cleanupLoop() {
	for {
		select {
		case <-rc.ticker.C:
			rc.cleanup()
		case <-rc.done:
			rc.ticker.Stop()
			return
		}
	}
}

func (rc *memoryReplayChecker) cleanup() {
	now := time.Now()
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for id, exp := range rc.seen {
		if now.After(exp) {
			delete(rc.seen, id)
		}
	}
}

// Stop stops the background cleanup goroutine.
func (rc *memoryReplayChecker) Stop() {
	close(rc.done)
}
