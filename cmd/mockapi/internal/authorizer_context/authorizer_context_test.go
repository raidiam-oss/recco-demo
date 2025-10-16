//go:build !conformance

package authorizer_context

import (
	"context"
	"slices"
	"testing"
)

func TestAuthorizerDetails(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string]any
		validate func(t *testing.T, ctx context.Context)
	}{
		{
			name: "we can add keys to the context under the authorizer key",
			values: map[string]any{
				"foo1": "bar1",
				"foo2": []string{"bar2.1", "bar2.2"},
				"foo3": false,
			},
			validate: func(t *testing.T, ctx context.Context) {
				values := GetAuthorizerDetails(ctx)
				if foo1, found := values["foo1"]; found {
					if foo1 != "bar1" {
						t.Errorf("expected foo1 to be 'bar1', got %v", foo1)
					}
				} else {
					t.Error("expected foo1 to be present in the context")
				}

				if foo2, found := values["foo2"]; found {
					var ok bool
					var lfoo2 []string
					if lfoo2, ok = foo2.([]string); !ok {
						t.Errorf("expected foo2 to be of type []string, got %T", foo2)
					}
					if len(lfoo2) != 2 {
						t.Errorf("expected foo2 to have length 2, got %d", len(lfoo2))
					}
					if !slices.Contains(lfoo2, "bar2.1") {
						t.Error("expected foo2 to contain 'bar2.1'")
					}
					if !slices.Contains(lfoo2, "bar2.2") {
						t.Error("expected foo2 to contain 'bar2.2'")
					}
				} else {
					t.Error("expected foo2 to be present in the context")
				}

				if foo3, found := values["foo3"]; found {
					if foo3 != false {
						t.Errorf("expected foo3 to be false, got %v", foo3)
					}
				} else {
					t.Error("expected foo3 to be present in the context")
				}
			},
		},
		{
			name:   "we don't panic on empty authorizer context",
			values: map[string]any{},
			validate: func(t *testing.T, ctx context.Context) {
				values := GetAuthorizerDetails(ctx)
				if values == nil {
					t.Fatal("expected non-nil map, got nil")
				}
				if len(values) != 0 {
					t.Errorf("expected empty map, got %v", values)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = AddAuthorizerDetails(ctx, tt.values)
			tt.validate(t, ctx)
		})
	}
}

func TestAuthorizerDetails_Empty(t *testing.T) {
	ctx := context.Background()
	values := GetAuthorizerDetails(ctx)
	if values != nil {
		t.Fatal("expected nil map, got non-nil")
	}
}
