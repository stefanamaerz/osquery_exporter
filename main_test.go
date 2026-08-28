package main

import (
	"testing"
	"time"
)

func TestParseCacheTTL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"empty disables caching", "", 0, false},
		{"zero explicit", "0", 0, false},
		{"zero seconds", "0s", 0, false},
		{"positive seconds", "30s", 30 * time.Second, false},
		{"minutes", "5m", 5 * time.Minute, false},
		{"negative", "-5s", 0, true},
		{"invalid", "garbage", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCacheTTL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCacheTTL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseCacheTTL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
