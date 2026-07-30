package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/robfig/cron/v3"
)

const (
	scheduledTestDefaultMaxWorkers = 10
	accountAutoMonitorSettingKey   = "account_auto_monitor"
	accountAutoMonitorInterval     = 30 * time.Minute
)

// AccountAutoMonitorSettings is the persisted state of the global account
// monitor exposed on the admin accounts page.
type AccountAutoMonitorSettings struct {
	Enabled         bool       `json:"enabled"`
	IntervalMinutes int        `json:"interval_minutes"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
	Running         bool       `json:"running"`
}

type scheduledAccountTester interface {
	RunTestBackground(ctx context.Context, accountID int64, modelID string) (*ScheduledTestResult, error)
}

type accountAutoMonitorRepository interface {
	ListAllWithFilters(ctx context.Context, platform, accountType, status, search string, groupID int64, privacyMode string) ([]Account, error)
	SetSchedulable(ctx context.Context, id int64, schedulable bool) error
}

type accountAutoMonitorRecovery interface {
	RecoverAccountAfterSuccessfulTest(ctx context.Context, accountID int64) (*SuccessfulTestRecoveryResult, error)
}

type accountAutoMonitorSettingRepository interface {
	GetValue(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// ScheduledTestRunnerService periodically scans due test plans and executes
// both per-account plans and the optional global account monitor.
type ScheduledTestRunnerService struct {
	planRepo       ScheduledTestPlanRepository
	scheduledSvc   *ScheduledTestService
	accountTestSvc scheduledAccountTester
	rateLimitSvc   accountAutoMonitorRecovery
	accountRepo    accountAutoMonitorRepository
	settingRepo    accountAutoMonitorSettingRepository
	cfg            *config.Config

	cron      *cron.Cron
	startOnce sync.Once
	stopOnce  sync.Once

	autoMonitorMu      sync.Mutex
	autoMonitorRunning bool
}

// NewScheduledTestRunnerService creates a new runner.
func NewScheduledTestRunnerService(
	planRepo ScheduledTestPlanRepository,
	scheduledSvc *ScheduledTestService,
	accountTestSvc *AccountTestService,
	rateLimitSvc *RateLimitService,
	accountRepo AccountRepository,
	settingRepo SettingRepository,
	cfg *config.Config,
) *ScheduledTestRunnerService {
	return &ScheduledTestRunnerService{
		planRepo:       planRepo,
		scheduledSvc:   scheduledSvc,
		accountTestSvc: accountTestSvc,
		rateLimitSvc:   rateLimitSvc,
		accountRepo:    accountRepo,
		settingRepo:    settingRepo,
		cfg:            cfg,
	}
}

// Start begins the cron ticker (every minute).
func (s *ScheduledTestRunnerService) Start() {
	if s == nil {
		return
	}
	s.startOnce.Do(func() {
		loc := time.Local
		if s.cfg != nil {
			if parsed, err := time.LoadLocation(s.cfg.Timezone); err == nil && parsed != nil {
				loc = parsed
			}
		}

		c := cron.New(cron.WithParser(scheduledTestCronParser), cron.WithLocation(loc))
		_, err := c.AddFunc("* * * * *", func() { s.runScheduled() })
		if err != nil {
			logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] not started (invalid schedule): %v", err)
			return
		}
		s.cron = c
		s.cron.Start()
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] started (tick=every minute)")
	})
}

// Stop gracefully shuts down the cron scheduler.
func (s *ScheduledTestRunnerService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		if s.cron != nil {
			ctx := s.cron.Stop()
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
				logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] cron stop timed out")
			}
		}
	})
}

func (s *ScheduledTestRunnerService) runScheduled() {
	// Delay 10s so execution lands at ~:10 of each minute instead of :00.
	time.Sleep(10 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	now := time.Now()
	plans, err := s.planRepo.ListDue(ctx, now)
	if err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] ListDue error: %v", err)
	} else if len(plans) > 0 {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] found %d due plans", len(plans))
		s.runPlans(ctx, plans)
	}

	s.runAutoMonitorIfDue(ctx, now)
}

func (s *ScheduledTestRunnerService) runPlans(ctx context.Context, plans []*ScheduledTestPlan) {
	sem := make(chan struct{}, scheduledTestDefaultMaxWorkers)
	var wg sync.WaitGroup
	for _, plan := range plans {
		sem <- struct{}{}
		wg.Add(1)
		go func(p *ScheduledTestPlan) {
			defer wg.Done()
			defer func() { <-sem }()
			s.runOnePlan(ctx, p)
		}(plan)
	}
	wg.Wait()
}

func (s *ScheduledTestRunnerService) runOnePlan(ctx context.Context, plan *ScheduledTestPlan) {
	result, err := s.accountTestSvc.RunTestBackground(ctx, plan.AccountID, plan.ModelID)
	if err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d RunTestBackground error: %v", plan.ID, err)
		return
	}

	if err := s.scheduledSvc.SaveResult(ctx, plan.ID, plan.MaxResults, result); err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d SaveResult error: %v", plan.ID, err)
	}

	// Auto-recover account if test succeeded and auto_recover is enabled.
	if result.Status == "success" && plan.AutoRecover {
		s.tryRecoverAccount(ctx, plan.AccountID, plan.ID)
	}

	nextRun, err := computeNextRun(plan.CronExpression, time.Now())
	if err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d computeNextRun error: %v", plan.ID, err)
		return
	}

	if err := s.planRepo.UpdateAfterRun(ctx, plan.ID, time.Now(), nextRun); err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d UpdateAfterRun error: %v", plan.ID, err)
	}
}

// tryRecoverAccount attempts to recover an account from recoverable runtime state.
func (s *ScheduledTestRunnerService) tryRecoverAccount(ctx context.Context, accountID int64, planID int64) {
	if s.rateLimitSvc == nil {
		return
	}

	recovery, err := s.rateLimitSvc.RecoverAccountAfterSuccessfulTest(ctx, accountID)
	if err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d auto-recover failed: %v", planID, err)
		return
	}
	if recovery == nil {
		return
	}

	if recovery.ClearedError {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d auto-recover: account=%d recovered from error status", planID, accountID)
	}
	if recovery.ClearedRateLimit {
		logger.LegacyPrintf("service.scheduled_test_runner", "[ScheduledTestRunner] plan=%d auto-recover: account=%d cleared rate-limit/runtime state", planID, accountID)
	}
}

func defaultAccountAutoMonitorSettings() *AccountAutoMonitorSettings {
	return &AccountAutoMonitorSettings{IntervalMinutes: int(accountAutoMonitorInterval / time.Minute)}
}

func (s *ScheduledTestRunnerService) loadAutoMonitorSettings(ctx context.Context) (*AccountAutoMonitorSettings, error) {
	settings := defaultAccountAutoMonitorSettings()
	if s == nil || s.settingRepo == nil {
		return settings, nil
	}
	raw, err := s.settingRepo.GetValue(ctx, accountAutoMonitorSettingKey)
	if err != nil {
		if errors.Is(err, ErrSettingNotFound) {
			return settings, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), settings); err != nil {
		return nil, err
	}
	// This interval is intentionally fixed by the feature contract.
	settings.IntervalMinutes = int(accountAutoMonitorInterval / time.Minute)
	return settings, nil
}

func (s *ScheduledTestRunnerService) saveAutoMonitorSettings(ctx context.Context, settings *AccountAutoMonitorSettings) error {
	if s == nil || s.settingRepo == nil {
		return errors.New("account auto monitor setting repository is not configured")
	}
	persisted := *settings
	persisted.Running = false
	raw, err := json.Marshal(&persisted)
	if err != nil {
		return err
	}
	return s.settingRepo.Set(ctx, accountAutoMonitorSettingKey, string(raw))
}

// GetAccountAutoMonitorSettings returns the global monitor state.
func (s *ScheduledTestRunnerService) GetAccountAutoMonitorSettings(ctx context.Context) (*AccountAutoMonitorSettings, error) {
	s.autoMonitorMu.Lock()
	defer s.autoMonitorMu.Unlock()
	settings, err := s.loadAutoMonitorSettings(ctx)
	if err != nil {
		return nil, err
	}
	settings.Running = s.autoMonitorRunning
	return settings, nil
}

// SetAccountAutoMonitorEnabled persists the global switch. A newly enabled
// monitor gets its first run after one complete 30-minute interval.
func (s *ScheduledTestRunnerService) SetAccountAutoMonitorEnabled(ctx context.Context, enabled bool) (*AccountAutoMonitorSettings, error) {
	s.autoMonitorMu.Lock()
	defer s.autoMonitorMu.Unlock()

	settings, err := s.loadAutoMonitorSettings(ctx)
	if err != nil {
		return nil, err
	}
	if settings.Enabled != enabled {
		settings.Enabled = enabled
		if enabled {
			next := time.Now().Add(accountAutoMonitorInterval)
			settings.NextRunAt = &next
		} else {
			settings.NextRunAt = nil
		}
	}
	if err := s.saveAutoMonitorSettings(ctx, settings); err != nil {
		return nil, err
	}
	settings.Running = s.autoMonitorRunning
	return settings, nil
}

func (s *ScheduledTestRunnerService) runAutoMonitorIfDue(ctx context.Context, now time.Time) {
	if s == nil || s.accountRepo == nil || s.accountTestSvc == nil || s.rateLimitSvc == nil {
		return
	}

	s.autoMonitorMu.Lock()
	if s.autoMonitorRunning {
		s.autoMonitorMu.Unlock()
		return
	}
	settings, err := s.loadAutoMonitorSettings(ctx)
	if err != nil {
		s.autoMonitorMu.Unlock()
		logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] load settings failed: %v", err)
		return
	}
	if !settings.Enabled {
		s.autoMonitorMu.Unlock()
		return
	}
	if settings.NextRunAt == nil {
		next := now.Add(accountAutoMonitorInterval)
		settings.NextRunAt = &next
		if err := s.saveAutoMonitorSettings(ctx, settings); err != nil {
			logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] initialize schedule failed: %v", err)
		}
		s.autoMonitorMu.Unlock()
		return
	}
	if settings.NextRunAt.After(now) {
		s.autoMonitorMu.Unlock()
		return
	}

	startedAt := now
	next := now.Add(accountAutoMonitorInterval)
	settings.LastRunAt = &startedAt
	settings.NextRunAt = &next
	if err := s.saveAutoMonitorSettings(ctx, settings); err != nil {
		s.autoMonitorMu.Unlock()
		logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] claim run failed: %v", err)
		return
	}
	s.autoMonitorRunning = true
	s.autoMonitorMu.Unlock()

	defer func() {
		s.autoMonitorMu.Lock()
		s.autoMonitorRunning = false
		s.autoMonitorMu.Unlock()
	}()

	accounts, err := s.accountRepo.ListAllWithFilters(ctx, "", "", "", "", 0, "")
	if err != nil {
		logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] list accounts failed: %v", err)
		return
	}

	// Disabled accounts represent an explicit administrator choice. Active and
	// error accounts remain testable even while scheduling/cooldown blocks them.
	candidates := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if account.Status == StatusActive || account.Status == StatusError {
			candidates = append(candidates, account)
		}
	}

	logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] probing %d accounts", len(candidates))
	sem := make(chan struct{}, scheduledTestDefaultMaxWorkers)
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	succeeded := 0
	failed := 0

	for i := range candidates {
		accountID := candidates[i].ID
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// Reuse exactly the same default request path as the existing
			// account connection test (default model/mapping/proxy/headers and hi).
			result, runErr := s.accountTestSvc.RunTestBackground(ctx, accountID, "")
			if runErr != nil || result == nil || result.Status != "success" {
				resultMu.Lock()
				failed++
				resultMu.Unlock()
				return
			}

			if _, recoverErr := s.rateLimitSvc.RecoverAccountAfterSuccessfulTest(ctx, accountID); recoverErr != nil {
				logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] recover account=%d failed: %v", accountID, recoverErr)
				resultMu.Lock()
				failed++
				resultMu.Unlock()
				return
			}
			if schedErr := s.accountRepo.SetSchedulable(ctx, accountID, true); schedErr != nil {
				logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] enable scheduling account=%d failed: %v", accountID, schedErr)
				resultMu.Lock()
				failed++
				resultMu.Unlock()
				return
			}

			resultMu.Lock()
			succeeded++
			resultMu.Unlock()
		}()
	}
	wg.Wait()
	logger.LegacyPrintf("service.scheduled_test_runner", "[AccountAutoMonitor] completed: success=%d failed=%d", succeeded, failed)
}
