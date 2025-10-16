package context_keys

import (
	"context"
	"log/slog"
	"runtime"
)

type contextKey struct{}

var CallerFn func(file string, line int) string

type Handler struct {
	slog.Handler
}

func New(h slog.Handler) slog.Handler {
	return Handler{Handler: h}
}

func WithValue(parent context.Context, attr slog.Attr) context.Context {
	var attrs []slog.Attr
	if v, ok := parent.Value(contextKey{}).([]slog.Attr); ok {
		attrs = append(attrs, v...)
	}
	attrs = append(attrs, attr)
	return context.WithValue(parent, contextKey{}, attrs)
}

func (h Handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelError && CallerFn != nil {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		r.Add("caller", CallerFn(f.File, f.Line))
	}
	r.AddAttrs(h.observe(ctx)...)
	return h.Handler.Handle(ctx, r)
}

func (h Handler) observe(ctx context.Context) []slog.Attr {
	if as, ok := ctx.Value(contextKey{}).([]slog.Attr); ok {
		return as
	}
	return nil
}
