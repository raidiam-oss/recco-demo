//go:build !conformance

package context_keys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"testing/slogtest"
)

func Test_SlogtestHandler(t *testing.T) {
	var buf bytes.Buffer
	h := New(slog.NewJSONHandler(&buf, nil))

	results := func() []map[string]any {
		var ms []map[string]any
		for _, line := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatalf("failed to unmarshal line: %s", line)
			}
			ms = append(ms, m)
		}
		return ms
	}
	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatalf("unexpected error %s", err)
	}
}

func Test_HandlerWithContext(t *testing.T) {
	var buf bytes.Buffer
	h := New(slog.NewJSONHandler(&buf, nil))
	l := slog.New(h)

	tests := []struct {
		name   string
		f      func(l *slog.Logger)
		checks []check
	}{
		{
			name: "log with context",
			f: func(l *slog.Logger) {
				l.InfoContext(context.Background(), "hello")
			},
			checks: []check{
				hasKey("level"),
				hasKey("time"),
				hasKey("msg"),
			},
		},
		{
			name: "log with context and fields",
			f: func(l *slog.Logger) {
				ctx := WithValue(context.Background(), slog.String("k", "v"))
				l.InfoContext(ctx, "hello")
			},
			checks: []check{
				hasKey("level"),
				hasKey("time"),
				hasKey("msg"),
				hasKey("k"),
				hasAttr("k", "v"),
			},
		},
		{
			name: "chain fields in context",
			f: func(l *slog.Logger) {
				ctx := WithValue(context.Background(), slog.String("k1", "v1"))
				ctx = WithValue(ctx, slog.String("k2", "v2"))
				l.InfoContext(ctx, "hello")
			},
			checks: []check{
				hasKey("level"),
				hasKey("time"),
				hasKey("msg"),
				hasKey("k1"),
				hasAttr("k1", "v1"),
				hasKey("k2"),
				hasAttr("k2", "v2"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf.Reset()
			test.f(l)
			var got map[string]any
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("failed to unmarshal line: %s", buf.Bytes())
			}
			for _, check := range test.checks {
				if p := check(got); p != "" {
					t.Errorf("%s: %s", p, buf.String())
				}
			}
			t.Log(strings.TrimSpace(buf.String()))
		})
	}
}

type check func(map[string]any) string

func hasKey(key string) check {
	return func(m map[string]any) string {
		if _, ok := m[key]; !ok {
			return fmt.Sprintf("missing key %q", key)
		}
		return ""
	}
}

func hasAttr(key string, wantVal any) check {
	return func(m map[string]any) string {
		if s := hasKey(key)(m); s != "" {
			return s
		}
		gotVal := m[key]
		if !reflect.DeepEqual(gotVal, wantVal) {
			return fmt.Sprintf("%q: got %#v, want %#v", key, gotVal, wantVal)
		}
		return ""
	}
}
