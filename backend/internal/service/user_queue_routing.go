package service

import "context"

// queuedUserAPIKeyRoutingContextKey marks a request that had to wait for a
// user-concurrency slot. Such requests are routed strictly through API-key
// accounts by the OpenAI scheduler.
type queuedUserAPIKeyRoutingContextKey struct{}

// WithQueuedUserAPIKeyRouting marks a request as having waited in the user
// concurrency queue.
func WithQueuedUserAPIKeyRouting(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, queuedUserAPIKeyRoutingContextKey{}, true)
}

// QueuedUserAPIKeyRoutingFromContext reports whether the request must use an
// API-key account because it waited for a user-concurrency slot.
func QueuedUserAPIKeyRoutingFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, _ := ctx.Value(queuedUserAPIKeyRoutingContextKey{}).(bool)
	return enabled
}
