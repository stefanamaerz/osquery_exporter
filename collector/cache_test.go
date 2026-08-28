package collector

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stefanamaerz/osquery_exporter/model"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCacheReturnsMissThenHit(t *testing.T) {
	cache := newQueryCache()
	calls := 0
	fetch := func(context.Context) (*model.OsqueryResult, error) {
		calls++
		return &model.OsqueryResult{Items: []model.OsqueryItem{{"v": "1"}}}, nil
	}

	res, hit, err := cache.runOrWait(context.Background(), "q", 10*time.Second, fetch)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if hit {
		t.Fatal("first call should be a cache miss")
	}
	if calls != 1 {
		t.Fatalf("expected 1 fetch call, got %d", calls)
	}

	res2, hit2, err := cache.runOrWait(context.Background(), "q", 10*time.Second, fetch)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if !hit2 {
		t.Fatal("second call should be a cache hit")
	}
	if calls != 1 {
		t.Fatalf("expected still 1 fetch call, got %d", calls)
	}
	if len(res2.Items) != len(res.Items) {
		t.Fatal("cached result mismatch")
	}
}

func TestCacheExpires(t *testing.T) {
	cache := newQueryCache()
	calls := 0
	fetch := func(context.Context) (*model.OsqueryResult, error) {
		calls++
		return &model.OsqueryResult{Items: []model.OsqueryItem{{"v": "1"}}}, nil
	}

	if _, _, err := cache.runOrWait(context.Background(), "q", 50*time.Millisecond, fetch); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	_, hit, err := cache.runOrWait(context.Background(), "q", 50*time.Millisecond, fetch)
	if err != nil {
		t.Fatalf("expired call failed: %v", err)
	}
	if hit {
		t.Fatal("expected cache miss after expiry")
	}
	if calls != 2 {
		t.Fatalf("expected 2 fetch calls after expiry, got %d", calls)
	}
}

func TestCachePropagatesError(t *testing.T) {
	cache := newQueryCache()
	wantErr := errors.New("boom")
	fetch := func(context.Context) (*model.OsqueryResult, error) {
		return nil, wantErr
	}

	_, _, err := cache.runOrWait(context.Background(), "q", 10*time.Second, fetch)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}
}

func TestCacheConcurrentColdCacheSingleFetch(t *testing.T) {
	cache := newQueryCache()
	var calls atomic.Int32

	fetch := func(context.Context) (*model.OsqueryResult, error) {
		time.Sleep(20 * time.Millisecond)
		calls.Add(1)
		return &model.OsqueryResult{Items: []model.OsqueryItem{{"v": "1"}}}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := cache.runOrWait(context.Background(), "q", 10*time.Second, fetch)
			if err != nil {
				t.Errorf("concurrent call failed: %v", err)
			}
		}()
	}
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 fetch call, got %d", calls.Load())
	}
}

func TestCacheFetchCancelledByContext(t *testing.T) {
	cache := newQueryCache()
	fetch := func(ctx context.Context) (*model.OsqueryResult, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return &model.OsqueryResult{}, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, _, err := cache.runOrWait(ctx, "q", 10*time.Second, fetch)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}
