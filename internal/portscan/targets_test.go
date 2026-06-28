package portscan

import (
	"context"
	"testing"
)

func TestExpandTargetsExpandsResolvedIPsDeterministically(t *testing.T) {
	targets := expandTargets(context.Background(), []string{"example.com"}, func(context.Context, string) ([]string, error) {
		return []string{"2001:db8::2", "10.0.0.5", "10.0.0.5", "2001:db8::1"}, nil
	})

	if len(targets) != 3 {
		t.Fatalf("expected 3 expanded targets, got %d: %+v", len(targets), targets)
	}

	got := []string{targets[0].Address, targets[1].Address, targets[2].Address}
	want := []string{"10.0.0.5", "2001:db8::1", "2001:db8::2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected address order: got %v want %v", got, want)
		}
	}
}

func TestExpandTargetsFallsBackToHostname(t *testing.T) {
	targets := expandTargets(context.Background(), []string{"localhost"}, func(context.Context, string) ([]string, error) {
		return nil, context.DeadlineExceeded
	})
	if len(targets) != 1 {
		t.Fatalf("expected 1 fallback target, got %d: %+v", len(targets), targets)
	}
	if targets[0].Domain != "localhost" || targets[0].Address != "localhost" {
		t.Fatalf("unexpected fallback target: %+v", targets[0])
	}
}
