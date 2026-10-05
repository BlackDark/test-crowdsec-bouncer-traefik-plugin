package test_crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	configuration "github.com/BlackDark/test-crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// lockedBuffer collects log output written from the ticker goroutine while the
// test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func capturingLogger() (*slog.Logger, *lockedBuffer) {
	out := &lockedBuffer{}
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})), out
}

func TestStartTickerContainsPanicAndKeepsTicking(t *testing.T) {
	log, logs := capturingLogger()
	runs := make(chan struct{}, 4)
	stop := startTicker("test", 1, log, func() {
		runs <- struct{}{}
		panic("sync exploded")
	}, false)
	// Sending on stop blocks until the in-flight run is done, so a panic cannot
	// leave the ticker running for the rest of the binary.
	defer func() { stop <- true }()

	// The panic must be contained: the ticker logs it and keeps going, so a
	// later tick still runs work.
	for range 2 {
		select {
		case <-runs:
		case <-time.After(5 * time.Second):
			t.Fatal("ticker stopped running work after a panic")
		}
	}

	if !strings.Contains(logs.String(), "test_ticker:panic sync exploded") {
		t.Errorf("panic value was not logged, got:\n%s", logs.String())
	}
}

func TestStartTickerSerializesRuns(t *testing.T) {
	log, _ := capturingLogger()
	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	stop := startTicker("test", 1, log, func() {
		entered <- struct{}{}
		<-release
	}, false)
	var released sync.Once
	releaseWork := func() { released.Do(func() { close(release) }) }
	defer func() { releaseWork(); stop <- true }()

	// Overlapping work is what let slow syncs pile up on the shared lease, so a
	// tick arriving while a run is in flight must wait rather than start another.
	waitForEntered(t, entered)
	select {
	case <-entered:
		t.Fatal("a second run of work started while the first was still in flight")
	case <-time.After(1500 * time.Millisecond):
	}

	// It must resume once the blocked run finishes, not wedge for good.
	releaseWork()
	waitForEntered(t, entered)
}

func waitForEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("ticker never ran work")
	}
}

func TestHandleStreamTickerLogsLAPIStateTransitionsOnly(t *testing.T) {
	var unreachable atomic.Bool
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if unreachable.Load() {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = rw.Write([]byte(`{"new":[],"deleted":[]}`))
	}))
	t.Cleanup(lapi.Close)
	resetStreamState(t)

	cfg := CreateConfig()
	cfg.Enabled = true
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.CrowdsecLapiScheme = configuration.HTTP
	cfg.CrowdsecLapiHost = strings.TrimPrefix(lapi.URL, "http://")
	cfg.CrowdsecLapiKey = "test-key"
	cfg.MetricsUpdateIntervalSeconds = 0

	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "lapi-transitions")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	bouncer, ok := handler.(*Bouncer)
	if !ok {
		t.Fatalf("New() returned %T, want *Bouncer", handler)
	}
	resetStreamState(t)
	// New already performed a successful startup sync; assert on what follows.
	// No global is written from here: handleStreamTicker owns them, and the only
	// writer at runtime is the single stream ticker goroutine.
	log, logs := capturingLogger()
	bouncer.log = log

	unreachable.Store(true)
	for range 3 {
		syncStreamCache(bouncer)
	}
	if down := strings.Count(logs.String(), "CrowdSec LAPI unreachable"); down != 1 {
		t.Errorf("LAPI down logged %d times over 3 failed syncs, want 1:\n%s", down, logs.String())
	}

	unreachable.Store(false)
	syncStreamCache(bouncer)
	if !strings.Contains(logs.String(), "CrowdSec LAPI connection restored") {
		t.Errorf("recovery was not logged, got:\n%s", logs.String())
	}

	// Going down again must re-arm the transition log.
	unreachable.Store(true)
	syncStreamCache(bouncer)
	if down := strings.Count(logs.String(), "CrowdSec LAPI unreachable"); down != 2 {
		t.Errorf("LAPI down logged %d times over two outages, want 2:\n%s", down, logs.String())
	}
}

func TestNew_PushesUsageMetricsAtStartup(t *testing.T) {
	resetStreamState(t)
	var pushed atomic.Int64
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/v1/usage-metrics") {
			pushed.Add(1)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(lapi.Close)

	cfg := streamStartupConfig(strings.TrimPrefix(lapi.URL, "http://"), true)
	// LiveMode keeps the stream ticker out of it; this test is about metrics.
	cfg.CrowdsecMode = configuration.LiveMode
	cfg.MetricsUpdateIntervalSeconds = 3600

	if _, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "metrics-startup"); err != nil {
		t.Fatalf("New() error: %v", err)
	}
	resetStreamState(t)

	// Otherwise the first usage report is delayed by a whole
	// metricsUpdateIntervalSeconds, which defaults to 10 minutes.
	deadline := time.Now().Add(5 * time.Second)
	for pushed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := pushed.Load(); got != 1 {
		t.Errorf("usage metrics pushed %d times at startup, want exactly 1", got)
	}
}

// syncStreamCache runs one ticker tick with the shared-cache lease cleared, so
// the sync really queries the LAPI instead of short-circuiting on a peer's
// refresh.
func syncStreamCache(bouncer *Bouncer) {
	bouncer.cacheClient.Delete(cacheTimeoutKey)
	handleStreamTicker(bouncer)
}

func TestHandleStreamTickerIgnoresPeerCacheRefresh(t *testing.T) {
	resetStreamState(t)
	var requests atomic.Int64
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(lapi.Close)

	cfg := streamStartupConfig(strings.TrimPrefix(lapi.URL, "http://"), false)

	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "peer-cache")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	bouncer, ok := handler.(*Bouncer)
	if !ok {
		t.Fatalf("New() returned %T, want *Bouncer", handler)
	}
	resetStreamState(t)
	log, logs := capturingLogger()
	bouncer.log = log
	bouncer.cacheClient.Delete(cacheTimeoutKey)

	// Fail once so the LAPI is marked down, then let the next tick hit the lease
	// left behind by that failed sync. No LAPI request happens on that tick, so
	// it must not be reported as a recovery. New's own startup sync may already
	// have hit the LAPI, so compare against a baseline.
	baseline := requests.Load()
	handleStreamTicker(bouncer)
	if got := requests.Load() - baseline; got != 1 {
		t.Fatalf("the first tick served %d LAPI requests, want 1", got)
	}
	handleStreamTicker(bouncer)
	if got := requests.Load() - baseline; got != 1 {
		t.Fatalf("the sync lease did not short-circuit the second tick: %d LAPI requests, want 1", got)
	}
	if !strings.Contains(logs.String(), "CrowdSec LAPI unreachable") {
		t.Fatalf("LAPI down was not logged, got:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "CrowdSec LAPI connection restored") {
		t.Errorf("a peer cache refresh was reported as an LAPI recovery:\n%s", logs.String())
	}
}

func TestHandleStreamTickerBlocksCacheMissesAfterMaxFailures(t *testing.T) {
	resetStreamState(t)
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(lapi.Close)

	cfg := streamStartupConfig(strings.TrimPrefix(lapi.URL, "http://"), false)
	cfg.UpdateMaxFailure = 2

	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "max-failures")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	bouncer, ok := handler.(*Bouncer)
	if !ok {
		t.Fatalf("New() returned %T, want *Bouncer", handler)
	}
	resetStreamState(t)
	log, logs := capturingLogger()
	bouncer.log = log

	for range 3 {
		syncStreamCache(bouncer)
	}
	if isCrowdsecStreamHealthy {
		t.Error("stream stayed healthy past updateMaxFailure failures")
	}
	// The third failure is the one that trips the threshold, and it is counted
	// before updateFailure is incremented.
	if !strings.Contains(logs.String(), "failed 3 times") {
		t.Errorf("threshold log missing or miscounted, got:\n%s", logs.String())
	}
}
