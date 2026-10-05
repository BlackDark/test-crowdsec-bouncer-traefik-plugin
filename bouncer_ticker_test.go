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

	// The panic must be contained: the ticker logs it and keeps going, so a
	// later tick still runs work.
	for range 2 {
		select {
		case <-runs:
		case <-time.After(5 * time.Second):
			t.Fatal("ticker stopped running work after a panic")
		}
	}
	stop <- true

	if !strings.Contains(logs.String(), "test_ticker:panic") {
		t.Errorf("panic was not logged, got:\n%s", logs.String())
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

	cfg := CreateConfig()
	cfg.Enabled = true
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.CrowdsecLapiScheme = configuration.HTTP
	cfg.CrowdsecLapiHost = strings.TrimPrefix(lapi.URL, "http://")
	cfg.CrowdsecLapiKey = "test-key"

	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "lapi-transitions")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	bouncer, ok := handler.(*Bouncer)
	if !ok {
		t.Fatalf("New() returned %T, want *Bouncer", handler)
	}
	stopStreamTicker(t)
	// New already performed a successful startup sync; assert on what follows.
	// No global is written from here: handleStreamTicker owns them, and the only
	// writer at runtime is the single stream ticker goroutine.
	log, logs := capturingLogger()
	bouncer.log = log
	bouncer.cacheClient.Delete(cacheTimeoutKey)

	unreachable.Store(true)
	for range 3 {
		handleStreamTicker(bouncer)
	}
	if down := strings.Count(logs.String(), "CrowdSec LAPI unreachable"); down != 1 {
		t.Errorf("LAPI down logged %d times over 3 failed syncs, want 1:\n%s", down, logs.String())
	}

	unreachable.Store(false)
	bouncer.cacheClient.Delete(cacheTimeoutKey)
	handleStreamTicker(bouncer)
	if !strings.Contains(logs.String(), "CrowdSec LAPI connection restored") {
		t.Errorf("recovery was not logged, got:\n%s", logs.String())
	}

	// Going down again must re-arm the transition log.
	unreachable.Store(true)
	bouncer.cacheClient.Delete(cacheTimeoutKey)
	handleStreamTicker(bouncer)
	if down := strings.Count(logs.String(), "CrowdSec LAPI unreachable"); down != 2 {
		t.Errorf("LAPI down logged %d times over two outages, want 2:\n%s", down, logs.String())
	}
}
