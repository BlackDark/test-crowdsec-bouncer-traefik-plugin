// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"testing"

	logger "github.com/BlackDark/test-crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/maxlerebourg/simpleredis"
)

// newTestClient returns a client over the shared local store, plus a cleanup
// dropping the keys the test writes. pkg/cache keeps one process-global TTL map,
// so tests reusing a key inherit each other's leftovers and pass only on a cold
// store: under -count=5 Test_Set failed because ttl_map's Set returns early for
// ttl 0 instead of overwriting, so the 0 second case saw the 10 second value the
// previous iteration had left behind.
func newTestClient(t *testing.T, keys ...string) *Client {
	t.Helper()
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	t.Cleanup(func() {
		for _, key := range keys {
			client.Delete(key)
		}
	})
	return client
}

func Test_Get(t *testing.T) {
	IPInCache := "10.0.0.10"
	IPNotInCache := "10.0.0.20"
	client := newTestClient(t, IPInCache, IPNotInCache)
	client.Set(IPInCache, BannedValue, 10)
	type args struct {
		clientIP string
	}
	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Fetch Known valid IP", args: args{clientIP: IPInCache}, want: BannedValue, wantErr: false, valueErr: ""},
		{name: "Fetch Unknown valid IP", args: args{clientIP: IPNotInCache}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Fetch invalid value", args: args{clientIP: "test"}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Fetch empty value", args: args{clientIP: ""}, want: "", wantErr: true, valueErr: CacheMiss},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Get() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Get() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_Set(t *testing.T) {
	client := newTestClient(t, "10.0.0.11", "10.0.0.12", "10.0.0.13")
	type args struct {
		clientIP string
		value    string
		duration int64
	}

	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		// A zero duration must not write: ttl_map's Set returns early for ttl 0
		// rather than overwriting, so reusing one key across the 0 and 10 second
		// cases would let the previous iteration's 10 second value decide the
		// 0 second case.
		{name: "Set valid IP in local cache for 0 sec", args: args{clientIP: "10.0.0.11", value: BannedValue, duration: 0}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Set valid IP in local cache for 10 sec (ban)", args: args{clientIP: "10.0.0.12", value: BannedValue, duration: 10}, want: BannedValue, wantErr: false, valueErr: ""},
		{name: "Set valid IP in local cache for 10 sec (no ban)", args: args{clientIP: "10.0.0.13", value: NoBannedValue, duration: 10}, want: NoBannedValue, wantErr: false, valueErr: ""},
		// Overwriting a live key is what a later delta has to do, and what the
		// shared-key table used to cover by accident.
		{name: "Overwrite a live ban", args: args{clientIP: "10.0.0.12", value: NoBannedValue, duration: 10}, want: NoBannedValue, wantErr: false, valueErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Set(tt.args.clientIP, tt.args.value, tt.args.duration)
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Set() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Set() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

func Test_Delete(t *testing.T) {
	IPInCache := "10.0.0.22"
	IPNotInCache := "10.0.0.23"
	client := newTestClient(t, IPInCache, IPNotInCache)
	client.Set(IPInCache, BannedValue, 10)
	type args struct {
		clientIP string
	}

	tests := []struct {
		name     string
		args     args
		want     string
		wantErr  bool
		valueErr string
	}{
		{name: "Delete Known valid IP", args: args{clientIP: IPInCache}, want: "", wantErr: true, valueErr: CacheMiss},
		{name: "Delete Unknown valid IP", args: args{clientIP: IPNotInCache}, want: "", wantErr: true, valueErr: CacheMiss},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.Delete(tt.args.clientIP)
			got, err := client.Get(tt.args.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Delete() = %v, want %v", got, tt.want)
				return
			}
			if tt.valueErr != "" && tt.valueErr != err.Error() {
				t.Errorf("Delete() err = %v, want %v", err.Error(), tt.valueErr)
			}
		})
	}
}

// indexOfReader returns the position of r inside rc.readers, or -1 when r is the writer (the no-readers fallback).
func indexOfReader(rc *redisCache, r *simpleredis.SimpleRedis) int {
	if r == &rc.writer {
		return -1
	}
	for i := range rc.readers {
		if r == &rc.readers[i] {
			return i
		}
	}
	return -2
}

func Test_nextReader(t *testing.T) {
	// The counter starts at 0, so the first Add(1) yields index 1, then 2, 0, 1, ... over n readers.
	tests := []struct {
		name    string
		readers int
		want    []int
	}{
		{name: "round-robin over three readers", readers: 3, want: []int{1, 2, 0, 1, 2, 0, 1}},
		{name: "single reader always selected", readers: 1, want: []int{0, 0, 0, 0, 0}},
		{name: "no readers fall back to writer", readers: 0, want: []int{-1, -1, -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &redisCache{log: logger.New("INFO", "")}
			rc.readers = make([]simpleredis.SimpleRedis, tt.readers)
			for call, want := range tt.want {
				if got := indexOfReader(rc, rc.nextReader()); got != want {
					t.Errorf("call %d: nextReader() -> reader[%d], want reader[%d]", call, got, want)
				}
			}
		})
	}
}
