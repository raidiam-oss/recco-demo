package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"recco-demo/cmd/mockapi/internal/api"
	"recco-demo/cmd/mockapi/internal/context_keys"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/google/uuid"
)

var (
	l *slog.Logger
)

func main() {
	l = slog.New(context_keys.New(slog.NewJSONHandler(os.Stdout, nil)))
	slog.SetDefault(l)
	ctx := context_keys.WithValue(context.Background(), slog.String("stage", "initialization"))
	l.InfoContext(ctx, "initializing lambda")

	mux := http.NewServeMux()
	mux.Handle("/", api.Handler(l))
	handler := middleware(mux, ctx)
	fapiHandler := enforceXFapiInteractionId(handler, ctx)

	lambdaAdapter := httpadapter.New(fapiHandler)
	lambda.Start(lambdaAdapter.ProxyWithContext)
}

func middleware(next http.Handler, ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.InfoContext(ctx, "request received", "method", r.Method, "path", r.URL.Path, "url", r.URL.String())
		start := time.Now().UTC()
		defer func() {
			if rec := recover(); rec != nil {
				l.ErrorContext(ctx, "panic recovered", "error", rec, "stack", string(debug.Stack()))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			l.InfoContext(ctx, "request completed", slog.Duration("duration", time.Since(start)))
		}()
		next.ServeHTTP(w, r)
	})
}

// enforceXFapiInteractionId ensures that the x-fapi-interaction-id header is set. If not set, it returns a random UUIDv4.
// If the header is set, it ensures that it is a valid UUIDv4 and propagates it to the request context.
// 400 if the header is not a valid UUIDv4.
func enforceXFapiInteractionId(next http.Handler, ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		interactionId := r.Header.Get("x-fapi-interaction-id")
		if interactionId != "" {
			if !isUUIDv4(interactionId) {
				http.Error(w, "Bad Request: invalid x-fapi-interaction-id (must be UUIDv4)", http.StatusBadRequest)
				return
			}

			l.InfoContext(ctx, "call made with x-fapi-interaction-id, using provided id", slog.String("x-fapi-interaction-id", interactionId))
			w.Header().Set("x-fapi-interaction-id", interactionId)
		} else {
			l.InfoContext(ctx, "x-fapi-interaction-id not found, generating random id")
			w.Header().Set("x-fapi-interaction-id", uuid.NewString())
		}
		next.ServeHTTP(w, r)
	})
}

func isUUIDv4(s string) bool {
	var reUUIDv4 = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
	return reUUIDv4.MatchString(strings.TrimSpace(s))
}
