package test_crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BlackDark/test-crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/BlackDark/test-crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// slowLAPI returns a LAPI host that stalls stream syncs for delay and counts how
// many it served.
func slowLAPI(t *testing.T, delay time.Duration) (string, *atomic.Int64) {
	t.Helper()
	var served atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/v1/decisions/stream") {
			served.Add(1)
			time.Sleep(delay)
			_, _ = rw.Write([]byte(`{"new":[],"deleted":[]}`))
			return
		}
		http.NotFound(rw, req)
	}))
	t.Cleanup(slow.Close)
	return strings.TrimPrefix(slow.URL, "http://"), &served
}

func streamStartupConfig(host string, block bool) *configuration.Config {
	cfg := CreateConfig()
	cfg.Enabled = true
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.StreamStartupBlock = block
	cfg.CrowdsecLapiScheme = configuration.HTTP
	cfg.CrowdsecLapiHost = host
	cfg.CrowdsecLapiKey = "test-key"
	cfg.MetricsUpdateIntervalSeconds = 0
	// Far longer than any test, so a "served exactly N times" assertion measures
	// the startup sync rather than a periodic tick.
	cfg.UpdateIntervalSeconds = 3600
	return cfg
}

func TestNew_StreamStartupBlocking(t *testing.T) {
	resetStreamState(t)
	host, requests := slowLAPI(t, 2*time.Second)

	start := time.Now()
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		streamStartupConfig(host, true), "stream-block")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("New() returned in %v with streamStartupBlock=true, expected it to wait for the LAPI", elapsed)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("LAPI served %d stream syncs, want exactly 1", got)
	}
}

func TestNew_StreamStartupNonBlocking(t *testing.T) {
	resetStreamState(t)
	host, requests := slowLAPI(t, 2*time.Second)

	start := time.Now()
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		streamStartupConfig(host, false), "stream-nonblock")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if elapsed > 750*time.Millisecond {
		t.Fatalf("New() blocked %v with streamStartupBlock=false", elapsed)
	}

	// New must return first, but the sync still has to happen: without the
	// startup delay the ticker goroutine owns the first run, so the LAPI is
	// contacted within a fraction of updateIntervalSeconds rather than never.
	deadline := time.Now().Add(10 * time.Second)
	for requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("LAPI served %d stream syncs, want exactly 1", got)
	}
}

// resetStreamState puts the package-level stream state back to its startup
// values and parks any ticker a previous test left running. The lease key has to
// go too: pkg/cache is process-global, so a lease from an earlier test makes
// handleStreamCache skip the LAPI entirely.
func resetStreamState(t *testing.T) {
	t.Helper()
	if streamTicker != nil {
		streamTicker <- true
		streamTicker = nil
	}
	if metricsTicker != nil {
		metricsTicker <- true
		metricsTicker = nil
	}
	isCrowdsecStreamStartup = true
	isCrowdsecStreamHealthy = true
	lapiStreamConnected = true
	updateFailure = 0
	clearStreamLease()
}

// clearStreamLease drops the sync lease from the process-global cache store, so
// the next sync really contacts the LAPI instead of short-circuiting on a
// refresh left behind by an earlier test or a peer.
func clearStreamLease() {
	client := &cache.Client{}
	client.New(slog.Default(), false, "", nil, "", "0")
	client.Delete(cacheTimeoutKey)
}
