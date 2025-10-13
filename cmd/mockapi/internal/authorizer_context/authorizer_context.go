package authorizer_context

import (
	"context"
)

type ContextAuthorizerKey struct{}

var authorizerKey = ContextAuthorizerKey{}

//nolint:forcetypeassert
func GetAuthorizerDetails(ctx context.Context) map[string]any {
	authorizerDetails := ctx.Value(authorizerKey)
	if authorizerDetails != nil {
		return authorizerDetails.(map[string]any)
	} else {
		return nil
	}
}

func AddAuthorizerDetails(ctx context.Context, values map[string]any) context.Context {
	return context.WithValue(ctx, authorizerKey, values)
}
