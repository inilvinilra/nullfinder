package dns

import "testing"

func TestEffectiveResolvers(t *testing.T) {
	t.Run("system mode uses system resolver", func(t *testing.T) {
		if got := EffectiveResolvers("system", []string{"1.1.1.1"}, []string{"8.8.8.8"}, true); got != nil {
			t.Fatalf("expected nil resolvers for system mode, got %v", got)
		}
	})

	t.Run("custom override wins", func(t *testing.T) {
		got := EffectiveResolvers("custom", []string{"1.1.1.1"}, []string{"8.8.8.8"}, true)
		if len(got) != 1 || got[0] != "8.8.8.8" {
			t.Fatalf("unexpected resolvers: %v", got)
		}
	})

	t.Run("fallback public resolvers used when enabled", func(t *testing.T) {
		got := EffectiveResolvers("mixed", nil, nil, true)
		if len(got) == 0 {
			t.Fatal("expected fallback public resolvers")
		}
	})
}
