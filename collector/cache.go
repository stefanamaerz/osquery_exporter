package collector

import (
	"context"
	"sync"
	"time"

	"github.com/stefanamaerz/osquery_exporter/model"
)

// maxErrorCacheTTL caps how long a failed osquery result is cached. We cache
// failures briefly to protect osqueryd from being hammered when it is already
// unhealthy.
const maxErrorCacheTTL = 5 * time.Second

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// cachedResult stores the outcome of a query execution along with its cache
// expiration time.
type cachedResult struct {
	result *model.OsqueryResult
	expiry time.Time
	err    error
}

// inFlight represents a query execution that is currently in progress. Callers
// receive the same result by waiting on the done channel.
type inFlight struct {
	done chan struct{}
	res  *cachedResult
}

// queryCache caches osquery results per query string for a configurable TTL.
// It also collapses concurrent requests for the same cold/expired query into a
// single execution.
type queryCache struct {
	mu       sync.Mutex
	entries  map[string]*cachedResult
	inflight map[string]*inFlight
}

func newQueryCache() *queryCache {
	return &queryCache{
		entries:  make(map[string]*cachedResult),
		inflight: make(map[string]*inFlight),
	}
}

// runOrWait returns the cached result if it is still fresh. Otherwise, it runs
// fetch exactly once for concurrent callers with the same query and caches the
// result for ttl.
//
// The second return value reports whether the call was served from cache.
// The third return value reports whether this was the leader that actually ran
// the query (true) or a waiter/follower (false).
func (c *queryCache) runOrWait(ctx context.Context, query string, ttl time.Duration, fetch func(context.Context) (*model.OsqueryResult, error)) (*model.OsqueryResult, bool, bool, error) {
	c.mu.Lock()
	entry, ok := c.entries[query]
	if ok && time.Now().Before(entry.expiry) {
		c.mu.Unlock()
		if entry.err != nil {
			return nil, true, false, entry.err
		}
		return entry.result, true, false, nil
	}

	if flight, ok := c.inflight[query]; ok {
		// Wait for the in-flight fetch to complete.
		c.mu.Unlock()
		select {
		case <-flight.done:
			// flight.res is guaranteed to be set by the leader before closing
			// the channel.
			if flight.res.err != nil {
				return nil, false, false, flight.res.err
			}
			return flight.res.result, false, false, nil
		case <-ctx.Done():
			return nil, false, false, ctx.Err()
		}
	}

	// We are the leader for this query.
	flight := &inFlight{done: make(chan struct{})}
	c.inflight[query] = flight
	c.mu.Unlock()

	res, err := fetch(ctx)

	expiry := time.Now().Add(ttl)
	if err != nil {
		expiry = time.Now().Add(minDuration(ttl, maxErrorCacheTTL))
	}
	flight.res = &cachedResult{result: res, err: err, expiry: expiry}

	c.mu.Lock()
	// Cache failures briefly so an unhealthy osqueryd isn't hammered by every
	// scrape while still allowing reasonably quick recovery.
	c.entries[query] = flight.res
	delete(c.inflight, query)
	c.mu.Unlock()

	close(flight.done)

	if err != nil {
		return nil, false, true, err
	}
	return res, false, true, nil
}
