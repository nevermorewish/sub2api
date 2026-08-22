package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRateLimitClientMessage(t *testing.T) {
	t.Run("preserves Kimi engine overload", func(t *testing.T) {
		require.Equal(t,
			"The engine is currently overloaded, please try again later",
			RateLimitClientMessage("  The engine is currently overloaded, please try again later  "),
		)
	})

	t.Run("redacts arbitrary upstream detail", func(t *testing.T) {
		require.Equal(t,
			"Upstream rate limit exceeded, please retry later",
			RateLimitClientMessage("account secret billing detail"),
		)
	})
}
