package collector

import (
	"context"
	"sync"
	"time"

	"github.com/stefanamaerz/osquery_exporter/model"
)

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
// result for ttl. The second return value is true on a cache hit.
func (c *queryCache) runOrWait(ctx context.Context, query string, ttl time.Duration, fetch func(context.Context) (*model.OsqueryResult, error)) (*model.OsqueryResult, bool, error) {
	c.mu.Lock()
	entry, ok := c.entries[query]
	if ok && time.Now().Before(entry.expiry) {
		c.mu.Unlock()
		return entry.result, true, nil
	}

	if flight, ok := c.inflight[query]; ok {
		// Wait for the in-flight fetch to complete.
		c.mu.Unlock()
		select {
		case <-flight.done:
			// flight.res is guaranteed to be set by the leader before closing
			// the channel.
			if flight.res.err != nil {
				return nil, false, flight.res.err
			}
			return flight.res.result, false, nil
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	// We are the leader for this query.
	flight := &inFlight{done: make(chan struct{})}
	c.inflight[query] = flight
	c.mu.Unlock()

	res, err := fetch(ctx)
	flight.res = &cachedResult{result: res, err: err, expiry: time.Now().Add(ttl)}

	c.mu.Lock()
	// Only cache successful results. Errors are not cached so the next scrape
	// can retry immediately.
	if err == nil {
		c.entries[query] = flight.res
	}
	delete(c.inflight, query)
	c.mu.Unlock()

	close(flight.done)

	if err != nil {
		return nil, false, err
	}
	return res, false, nil
}
