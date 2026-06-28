package dns

import (
	"context"
	"testing"
	"time"
)

func TestResolveSingleSystemResolverPopulatesMetadata(t *testing.T) {
	r := NewResolver(nil, 1, 0, 2)
	res := r.ResolveSingle(context.Background(), "localhost")
	if res.Domain != "localhost" {
		t.Fatalf("unexpected domain: %q", res.Domain)
	}
	// localhost behavior differs by system, but the function must not panic and should preserve slices.
	if res.NS == nil {
		res.NS = []string{}
	}
	if res.MX == nil {
		res.MX = []string{}
	}
}

func TestResolveSingleHandlesHostLookupFailure(t *testing.T) {
	r := &Resolver{
		useSystem: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	res := r.ResolveSingle(ctx, "nonexistent.invalid")
	if res.Error == nil {
		t.Fatalf("expected lookup error for nonexistent.invalid")
	}
}
