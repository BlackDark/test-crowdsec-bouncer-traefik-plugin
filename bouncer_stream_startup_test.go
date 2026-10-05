package test_crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BlackDark/test-crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func slowLAPIHost(t *testing.T) string {
	t.Helper()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/decisions/stream") {
			time.Sleep(2 * time.Second)
			_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(slow.Close)
	return strings.TrimPrefix(slow.URL, "http://")
}

// Run before TestNew_StreamStartupNonBlocking (name order); uses global streamTicker.
func TestNew_StreamStartupBlocking(t *testing.T) {
	streamTicker = nil
	metricsTicker = nil
	isCrowdsecStreamStartup = true

	host := slowLAPIHost(t)
	cfg := CreateConfig()
	cfg.Enabled = true
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.StreamStartupBlock = true
	cfg.CrowdsecLapiScheme = configuration.HTTP
	cfg.CrowdsecLapiHost = host
	cfg.CrowdsecLapiKey = "test-key"
	cfg.MetricsUpdateIntervalSeconds = 0

	start := time.Now()
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "stream-block")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("New() returned in %v with streamStartupBlock=true, expected LAPI delay", elapsed)
	}
	// Sending on the channel returns only once the ticker goroutine is parked in
	// its select, so no later test races with a still-running sync.
	stopStreamTicker(t)
}

func TestNew_StreamStartupNonBlocking(t *testing.T) {
	streamTicker = nil
	metricsTicker = nil

	host := slowLAPIHost(t)
	cfg := CreateConfig()
	cfg.Enabled = true
	cfg.CrowdsecMode = configuration.StreamMode
	cfg.StreamStartupBlock = false
	cfg.CrowdsecLapiScheme = configuration.HTTP
	cfg.CrowdsecLapiHost = host
	cfg.CrowdsecLapiKey = "test-key"
	cfg.MetricsUpdateIntervalSeconds = 0

	start := time.Now()
	_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "stream-nonblock")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if elapsed > 750*time.Millisecond {
		t.Fatalf("New() blocked %v with streamStartupBlock=false", elapsed)
	}
	stopStreamTicker(t)
}

// stopStreamTicker parks the stream ticker goroutine and clears the global so a
// later test starts from a known state.
func stopStreamTicker(t *testing.T) {
	t.Helper()
	if streamTicker != nil {
		streamTicker <- true
		streamTicker = nil
	}
}
