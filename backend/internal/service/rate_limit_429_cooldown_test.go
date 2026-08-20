//go:build unit

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type rateLimit429AccountRepoStub struct {
	mockAccountRepoForGemini
	rateLimitCalls     int
	lastRateLimitID    int64
	lastRateLimitReset time.Time
}

func (r *rateLimit429AccountRepoStub) SetRateLimited(_ context.Context, id int64, resetAt time.Time) error {
	r.rateLimitCalls++
	r.lastRateLimitID = id
	r.lastRateLimitReset = resetAt
	return nil
}

func TestGetRateLimit429CooldownSettings_DefaultsWhenNotSet(t *testing.T) {
	repo := newMockSettingRepo()
	svc := NewSettingService(repo, &config.Config{})

	settings, err := svc.GetRateLimit429CooldownSettings(context.Background())
	require.NoError(t, err)
	require.True(t, settings.Enabled)
	require.Equal(t, 5, settings.CooldownSeconds)
}

func TestGetRateLimit429CooldownSettings_ReadsFromDB(t *testing.T) {
	repo := newMockSettingRepo()
	data, _ := json.Marshal(RateLimit429CooldownSettings{Enabled: false, CooldownSeconds: 12})
	repo.data[SettingKeyRateLimit429CooldownSettings] = string(data)
	svc := NewSettingService(repo, &config.Config{})

	settings, err := svc.GetRateLimit429CooldownSettings(context.Background())
	require.NoError(t, err)
	require.False(t, settings.Enabled)
	require.Equal(t, 12, settings.CooldownSeconds)
}

func TestSetRateLimit429CooldownSettings_EnabledRejectsOutOfRange(t *testing.T) {
	svc := NewSettingService(newMockSettingRepo(), &config.Config{})

	for _, seconds := range []int{0, -1, 7201, 99999} {
		err := svc.SetRateLimit429CooldownSettings(context.Background(), &RateLimit429CooldownSettings{
			Enabled: true, CooldownSeconds: seconds,
		})
		require.Error(t, err, "should reject enabled=true + cooldown_seconds=%d", seconds)
		require.Contains(t, err.Error(), "cooldown_seconds must be between 1-7200")
	}
}

func TestHandle429_FallbackUsesDBSeconds(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	settingRepo := newMockSettingRepo()
	data, _ := json.Marshal(RateLimit429CooldownSettings{Enabled: true, CooldownSeconds: 12})
	settingRepo.data[SettingKeyRateLimit429CooldownSettings] = string(data)

	settingSvc := NewSettingService(settingRepo, &config.Config{})
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	svc.SetSettingService(settingSvc)

	account := &Account{ID: 42, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	before := time.Now()
	svc.handle429(context.Background(), account, http.Header{}, []byte(`{"error":{"type":"rate_limit_error","message":"slow down"}}`))
	after := time.Now()

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(42), accountRepo.lastRateLimitID)
	require.True(t, !accountRepo.lastRateLimitReset.Before(before.Add(12*time.Second)) && !accountRepo.lastRateLimitReset.After(after.Add(12*time.Second)))
}

func TestParseOpenAIRateLimitResetTime_AccountQuotaExceeded(t *testing.T) {
	body := []byte(`{"error":{"code":"AccountQuotaExceeded","message":"You have exceeded the monthly usage quota. It will reset at 2026-08-25 23:59:59 +0800 CST. We recommend upgrading your plan for more quota, or waiting for the reset.","param":"","type":"TooManyRequests"}}`)

	resetUnix := parseOpenAIRateLimitResetTime(body)
	require.NotNil(t, resetUnix)
	require.Equal(t, time.Date(2026, time.August, 25, 23, 59, 59, 0, time.FixedZone("CST", 8*60*60)).Unix(), *resetUnix)
}

func TestParseOpenAIRateLimitResetTime_AccountQuotaExceededMalformedReset(t *testing.T) {
	body := []byte(`{"error":{"code":"AccountQuotaExceeded","message":"You have exceeded the monthly usage quota. It will reset sometime next month.","type":"TooManyRequests"}}`)

	require.Nil(t, parseOpenAIRateLimitResetTime(body))
}

func TestParseOpenAIRateLimitResetTime_DoesNotParseOrdinary429MessageDate(t *testing.T) {
	body := []byte(`{"error":{"code":"RateLimitExceeded","message":"Slow down. It will reset at 2026-08-25 23:59:59 +0800 CST.","type":"TooManyRequests"}}`)

	require.Nil(t, parseOpenAIRateLimitResetTime(body))
}

func TestHandle429_AccountQuotaExceededUsesBodyReset(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	account := &Account{ID: 47, Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	body := []byte(`{"error":{"code":"AccountQuotaExceeded","message":"You have exceeded the monthly usage quota. It will reset at 2026-08-25 23:59:59 +0800 CST.","type":"TooManyRequests"}}`)

	svc.handle429(context.Background(), account, http.Header{}, body)

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(47), accountRepo.lastRateLimitID)
	require.Equal(t, time.Date(2026, time.August, 25, 23, 59, 59, 0, time.FixedZone("CST", 8*60*60)).Unix(), accountRepo.lastRateLimitReset.Unix())
}

func TestParseAliyunTokenPlanQuotaResetTime_OpenAIEnvelope(t *testing.T) {
	body := []byte(`{"error":{"message":"Your token-plan 1-week quota has been exhausted. The quota will reset at 08-12 14:52:00 UTC.","id":"567a856e-020c-436f-b31b-f8788b66c2f1","type":"insufficient_quota","code":"insufficient_quota"}}`)
	now := time.Date(2026, time.August, 12, 9, 31, 52, 0, time.UTC)

	resetAt := parseAliyunTokenPlanQuotaResetTime(body, now)
	require.NotNil(t, resetAt)
	require.Equal(t, time.Date(2026, time.August, 12, 14, 52, 0, 0, time.UTC), *resetAt)
}

func TestParseAliyunTokenPlanQuotaResetTime_AnthropicEnvelope(t *testing.T) {
	body := []byte(`{"code":"Throttling.AllocationQuota","message":"Your token-plan 1-week quota has been exhausted. The quota will reset at 08-12 14:52:00 UTC.","request_id":"6d9552e4-9982-4e67-9dbe-532c342c3de6"}`)
	now := time.Date(2026, time.August, 12, 9, 31, 52, 0, time.UTC)

	resetAt := parseAliyunTokenPlanQuotaResetTime(body, now)
	require.NotNil(t, resetAt)
	require.Equal(t, time.Date(2026, time.August, 12, 14, 52, 0, 0, time.UTC), *resetAt)
}

func TestParseAliyunTokenPlanQuotaResetTime_YearRollover(t *testing.T) {
	body := []byte(`{"error":{"message":"Your token-plan 1-week quota has been exhausted. The quota will reset at 01-03 14:52:00 UTC.","code":"insufficient_quota"}}`)
	now := time.Date(2026, time.December, 29, 9, 0, 0, 0, time.UTC)

	resetAt := parseAliyunTokenPlanQuotaResetTime(body, now)
	require.NotNil(t, resetAt)
	require.Equal(t, time.Date(2027, time.January, 3, 14, 52, 0, 0, time.UTC), *resetAt)
}

func TestParseAliyunTokenPlanQuotaResetTime_StaleResetDoesNotDisableForYear(t *testing.T) {
	body := []byte(`{"error":{"message":"Your token-plan 1-week quota has been exhausted. The quota will reset at 08-12 14:52:00 UTC.","code":"insufficient_quota"}}`)
	now := time.Date(2026, time.August, 12, 15, 0, 0, 0, time.UTC)

	require.Nil(t, parseAliyunTokenPlanQuotaResetTime(body, now))
}

func TestParseAliyunTokenPlanQuotaResetTime_OrdinaryInsufficientQuotaIgnored(t *testing.T) {
	body := []byte(`{"error":{"message":"Your prepaid balance is exhausted.","code":"insufficient_quota"}}`)

	require.Nil(t, parseAliyunTokenPlanQuotaResetTime(body, time.Date(2026, time.August, 12, 9, 0, 0, 0, time.UTC)))
}

func TestHandle429_AnthropicAliyunTokenPlanUsesBodyReset(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	account := &Account{ID: 48, Platform: PlatformAnthropic, Type: AccountTypeAPIKey}
	body := []byte(`{"code":"Throttling.AllocationQuota","message":"Your token-plan 1-week quota has been exhausted. The quota will reset at 08-12 14:52:00 UTC."}`)

	// Use a future reset independent of the wall clock while retaining the exact
	// Alibaba response shape observed in production.
	future := time.Now().UTC().Add(2 * time.Hour)
	body = []byte(fmt.Sprintf(`{"code":"Throttling.AllocationQuota","message":"Your token-plan 1-week quota has been exhausted. The quota will reset at %s UTC."}`, future.Format("01-02 15:04:05")))
	svc.handle429(context.Background(), account, http.Header{}, body)

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(48), accountRepo.lastRateLimitID)
	require.Equal(t, future.Unix(), accountRepo.lastRateLimitReset.Unix())
}

func TestAccountTestService_AnthropicAliyunTokenPlanPersistsRateLimit(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	svc := &AccountTestService{accountRepo: accountRepo}
	account := &Account{ID: 49, Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true}
	future := time.Now().UTC().Add(2 * time.Hour)
	body := []byte(fmt.Sprintf(`{"code":"Throttling.AllocationQuota","message":"Your token-plan 1-week quota has been exhausted. The quota will reset at %s UTC."}`, future.Format("01-02 15:04:05")))

	svc.reconcileAliyunTokenPlan429State(context.Background(), account, body)

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(49), accountRepo.lastRateLimitID)
	require.Equal(t, future.Unix(), accountRepo.lastRateLimitReset.Unix())
	require.NotNil(t, account.RateLimitResetAt)
	require.False(t, account.IsSchedulable())
}

func TestHandle429_FallbackDisabledSkipsLocalMark(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	settingRepo := newMockSettingRepo()
	data, _ := json.Marshal(RateLimit429CooldownSettings{Enabled: false, CooldownSeconds: 12})
	settingRepo.data[SettingKeyRateLimit429CooldownSettings] = string(data)

	settingSvc := NewSettingService(settingRepo, &config.Config{})
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	svc.SetSettingService(settingSvc)

	account := &Account{ID: 43, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	svc.handle429(context.Background(), account, http.Header{}, []byte(`{"error":{"type":"rate_limit_error","message":"slow down"}}`))

	require.Zero(t, accountRepo.rateLimitCalls)
}

// Anthropic 无 reset 头的 429（如 Extra usage required）也应走兜底冷却，
// 否则账号永不冷却，调度器会让每个请求反复撞同一批 429 账号（旋转木马）。
func TestHandle429_AnthropicNoResetTimeUsesFallbackCooldown(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	settingRepo := newMockSettingRepo()
	data, _ := json.Marshal(RateLimit429CooldownSettings{Enabled: true, CooldownSeconds: 12})
	settingRepo.data[SettingKeyRateLimit429CooldownSettings] = string(data)

	settingSvc := NewSettingService(settingRepo, &config.Config{})
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	svc.SetSettingService(settingSvc)

	account := &Account{ID: 45, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	before := time.Now()
	svc.handle429(context.Background(), account, http.Header{}, []byte(`{"error":{"type":"rate_limit_error","message":"Extra usage required"}}`))
	after := time.Now()

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(45), accountRepo.lastRateLimitID)
	require.True(t, !accountRepo.lastRateLimitReset.Before(before.Add(12*time.Second)) && !accountRepo.lastRateLimitReset.After(after.Add(12*time.Second)))
}

// 管理端关闭兜底冷却时，Anthropic 无 reset 头的 429 保持旧行为：不标记账号。
func TestHandle429_AnthropicNoResetTimeFallbackDisabledSkipsMark(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	settingRepo := newMockSettingRepo()
	data, _ := json.Marshal(RateLimit429CooldownSettings{Enabled: false, CooldownSeconds: 12})
	settingRepo.data[SettingKeyRateLimit429CooldownSettings] = string(data)

	settingSvc := NewSettingService(settingRepo, &config.Config{})
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	svc.SetSettingService(settingSvc)

	account := &Account{ID: 46, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	svc.handle429(context.Background(), account, http.Header{}, []byte(`{"error":{"type":"rate_limit_error","message":"Extra usage required"}}`))

	require.Zero(t, accountRepo.rateLimitCalls)
}

func TestParseAnthropicQuotaResetTime_GLMChineseBody(t *testing.T) {
	zone := time.FixedZone("CST", 8*60*60)
	now := time.Date(2026, time.August, 20, 18, 20, 0, 0, zone)
	body := []byte(`{"type":"error","error":{"type":"rate_limit_error","message":"[1308][已达到 5 小时的使用上限。您的限额将在 2026-08-20 18:43:45 重置。][request-id]"}}`)

	resetAt := parseAnthropicQuotaResetTime(body, now)
	require.NotNil(t, resetAt)
	require.Equal(t, time.Date(2026, time.August, 20, 18, 43, 45, 0, zone), *resetAt)
}

func TestHandle429_AnthropicQuotaBodyUsesResetTime(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	svc := NewRateLimitService(accountRepo, nil, &config.Config{}, nil, nil)
	account := &Account{ID: 47, Platform: PlatformAnthropic, Type: AccountTypeAPIKey}
	future := time.Now().Add(2 * time.Hour)
	body := []byte(fmt.Sprintf(`{"error":{"code":"AccountQuotaExceeded","message":"You have exceeded the monthly usage quota. It will reset at %s."}}`, future.Format("2006-01-02 15:04:05 -0700 MST")))

	svc.handle429(context.Background(), account, http.Header{}, body)

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(47), accountRepo.lastRateLimitID)
	require.WithinDuration(t, future, accountRepo.lastRateLimitReset, time.Second)
}

func TestHandle429_FallbackUsesDefaultSecondsWhenSettingServiceMissing(t *testing.T) {
	accountRepo := &rateLimit429AccountRepoStub{}
	cfg := &config.Config{}
	svc := NewRateLimitService(accountRepo, nil, cfg, nil, nil)

	account := &Account{ID: 44, Platform: PlatformGemini, Type: AccountTypeAPIKey}
	before := time.Now()
	svc.handle429(context.Background(), account, http.Header{}, []byte(`{"error":{"message":"slow down"}}`))
	after := time.Now()

	require.Equal(t, 1, accountRepo.rateLimitCalls)
	require.Equal(t, int64(44), accountRepo.lastRateLimitID)
	require.True(t, !accountRepo.lastRateLimitReset.Before(before.Add(5*time.Second)) && !accountRepo.lastRateLimitReset.After(after.Add(5*time.Second)))
}
