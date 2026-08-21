//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type kimiTempUnschedCacheRecorder struct {
	accountID int64
	state     *TempUnschedState
}

func (c *kimiTempUnschedCacheRecorder) SetTempUnsched(_ context.Context, accountID int64, state *TempUnschedState) error {
	c.accountID = accountID
	c.state = state
	return nil
}

func (c *kimiTempUnschedCacheRecorder) GetTempUnsched(context.Context, int64) (*TempUnschedState, error) {
	return nil, nil
}

func (c *kimiTempUnschedCacheRecorder) DeleteTempUnsched(context.Context, int64) error {
	return nil
}

func TestRateLimitService_KimiConcurrent403UsesOneMinuteCooldown(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		t.Run(platform, func(t *testing.T) {
			repo := &rateLimitAccountRepoStub{}
			cache := &kimiTempUnschedCacheRecorder{}
			blocker := &runtimeBlockRecorder{}
			svc := NewRateLimitService(repo, nil, &config.Config{}, nil, cache)
			svc.SetAccountRuntimeBlocker(blocker)
			account := &Account{ID: 601, Platform: platform, Type: AccountTypeAPIKey}
			before := time.Now()

			shouldDisable := svc.HandleUpstreamError(
				context.Background(),
				account,
				http.StatusForbidden,
				http.Header{},
				[]byte(`{"error":{"message":"You've reached your concurrent request limit. Please wait for your ongoing requests to finish and try again."}}`),
			)

			require.True(t, shouldDisable)
			require.Zero(t, repo.setErrorCalls)
			require.Equal(t, 1, repo.tempCalls)
			require.WithinDuration(t, before.Add(time.Minute), repo.lastTempUntil, time.Second)
			require.Contains(t, repo.lastTempReason, kimiConcurrentRequestLimitMessage)
			require.Equal(t, account.ID, cache.accountID)
			require.NotNil(t, cache.state)
			require.Equal(t, http.StatusForbidden, cache.state.StatusCode)
			require.Len(t, blocker.accounts, 1)
			require.Equal(t, "kimi_concurrent_request_limit", blocker.reasons[0])
			require.WithinDuration(t, repo.lastTempUntil, blocker.until[0], time.Second)
		})
	}
}

func TestRateLimitService_KimiConcurrent403RequiresExactMessage(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "different_wording", body: `{"error":{"message":"You've reached your request limit."}}`},
		{name: "different_case", body: `{"error":{"message":"you've reached your concurrent request limit"}}`},
		{name: "plain_text_not_structured", body: kimiConcurrentRequestLimitMessage},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &rateLimitAccountRepoStub{}
			svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
			account := &Account{ID: 602, Platform: PlatformAnthropic, Type: AccountTypeAPIKey}

			require.True(t, svc.HandleUpstreamError(context.Background(), account, http.StatusForbidden, http.Header{}, []byte(tc.body)))
			require.Equal(t, 1, repo.setErrorCalls)
			require.Zero(t, repo.tempCalls)
		})
	}
}

func TestRateLimitService_KimiConcurrent403AllowsUpstreamExplanationChanges(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{ID: 604, Platform: PlatformAnthropic, Type: AccountTypeAPIKey}

	require.True(t, svc.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"You've reached your concurrent request limit. Contact support if this persists."}}`),
	))
	require.Zero(t, repo.setErrorCalls)
	require.Equal(t, 1, repo.tempCalls)
}

func TestAccountTestService_KimiConcurrent403UsesCooldownInsteadOfError(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	svc := &AccountTestService{accountRepo: repo}
	account := &Account{ID: 603, Platform: PlatformAnthropic, Type: AccountTypeAPIKey}
	before := time.Now()

	matched := svc.handleKimiConcurrentRequestLimit(
		context.Background(),
		account,
		http.StatusForbidden,
		[]byte(`{"type":"error","error":{"message":"You've reached your concurrent request limit. Please wait for your ongoing requests to finish and try again."}}`),
	)

	require.True(t, matched)
	require.Zero(t, repo.setErrorCalls)
	require.Equal(t, 1, repo.tempCalls)
	require.WithinDuration(t, before.Add(time.Minute), repo.lastTempUntil, time.Second)
}
