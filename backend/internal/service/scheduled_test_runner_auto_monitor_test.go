package service

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type autoMonitorSettingRepoStub struct {
	mu    sync.Mutex
	value string
}

func (s *autoMonitorSettingRepoStub) GetValue(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key != accountAutoMonitorSettingKey || s.value == "" {
		return "", ErrSettingNotFound
	}
	return s.value, nil
}

func (s *autoMonitorSettingRepoStub) Set(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == accountAutoMonitorSettingKey {
		s.value = value
	}
	return nil
}

type autoMonitorAccountRepoStub struct {
	accounts       []Account
	mu             sync.Mutex
	schedulableIDs []int64
}

func (s *autoMonitorAccountRepoStub) ListAllWithFilters(context.Context, string, string, string, string, int64, string) ([]Account, error) {
	return s.accounts, nil
}

func (s *autoMonitorAccountRepoStub) SetSchedulable(_ context.Context, id int64, schedulable bool) error {
	if schedulable {
		s.mu.Lock()
		s.schedulableIDs = append(s.schedulableIDs, id)
		s.mu.Unlock()
	}
	return nil
}

type autoMonitorTesterStub struct {
	mu      sync.Mutex
	results map[int64]string
	called  map[int64]string
}

func (s *autoMonitorTesterStub) RunTestBackground(_ context.Context, accountID int64, modelID string) (*ScheduledTestResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called[accountID] = modelID
	return &ScheduledTestResult{Status: s.results[accountID]}, nil
}

type autoMonitorRecoveryStub struct {
	mu     sync.Mutex
	called []int64
}

func (s *autoMonitorRecoveryStub) RecoverAccountAfterSuccessfulTest(_ context.Context, accountID int64) (*SuccessfulTestRecoveryResult, error) {
	s.mu.Lock()
	s.called = append(s.called, accountID)
	s.mu.Unlock()
	return &SuccessfulTestRecoveryResult{ClearedRateLimit: true}, nil
}

func TestScheduledTestRunnerAccountAutoMonitorToggle(t *testing.T) {
	repo := &autoMonitorSettingRepoStub{}
	runner := &ScheduledTestRunnerService{settingRepo: repo}

	initial, err := runner.GetAccountAutoMonitorSettings(context.Background())
	require.NoError(t, err)
	require.False(t, initial.Enabled)
	require.Equal(t, 30, initial.IntervalMinutes)
	require.Nil(t, initial.NextRunAt)

	before := time.Now()
	enabled, err := runner.SetAccountAutoMonitorEnabled(context.Background(), true)
	require.NoError(t, err)
	require.True(t, enabled.Enabled)
	require.NotNil(t, enabled.NextRunAt)
	require.WithinDuration(t, before.Add(30*time.Minute), *enabled.NextRunAt, 2*time.Second)

	disabled, err := runner.SetAccountAutoMonitorEnabled(context.Background(), false)
	require.NoError(t, err)
	require.False(t, disabled.Enabled)
	require.Nil(t, disabled.NextRunAt)
}

func TestScheduledTestRunnerAccountAutoMonitorOnlyRecoversSuccessfulTests(t *testing.T) {
	now := time.Now()
	due := now.Add(-time.Minute)
	settingsJSON, err := json.Marshal(AccountAutoMonitorSettings{
		Enabled:         true,
		IntervalMinutes: 30,
		NextRunAt:       &due,
	})
	require.NoError(t, err)

	settingRepo := &autoMonitorSettingRepoStub{value: string(settingsJSON)}
	accountRepo := &autoMonitorAccountRepoStub{accounts: []Account{
		{ID: 1, Status: StatusActive},
		{ID: 2, Status: StatusError},
		{ID: 3, Status: StatusDisabled},
	}}
	tester := &autoMonitorTesterStub{
		results: map[int64]string{1: "success", 2: "failed"},
		called:  make(map[int64]string),
	}
	recovery := &autoMonitorRecoveryStub{}
	runner := &ScheduledTestRunnerService{
		accountTestSvc: tester,
		rateLimitSvc:   recovery,
		accountRepo:    accountRepo,
		settingRepo:    settingRepo,
	}

	runner.runAutoMonitorIfDue(context.Background(), now)

	tester.mu.Lock()
	require.Equal(t, map[int64]string{1: "", 2: ""}, tester.called,
		"the monitor must reuse the existing connection test's default model/request path")
	tester.mu.Unlock()

	recovery.mu.Lock()
	require.Equal(t, []int64{1}, recovery.called,
		"a failed 403/429-style connection test must stay in cooldown")
	recovery.mu.Unlock()

	accountRepo.mu.Lock()
	require.Equal(t, []int64{1}, accountRepo.schedulableIDs)
	accountRepo.mu.Unlock()

	stored, err := runner.GetAccountAutoMonitorSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stored.LastRunAt)
	require.NotNil(t, stored.NextRunAt)
	require.WithinDuration(t, now.Add(30*time.Minute), *stored.NextRunAt, time.Second)
}

func TestScheduledTestRunnerAccountAutoMonitorProcessesRuntimeBlocks(t *testing.T) {
	now := time.Now()
	due := now.Add(-time.Minute)
	settingsJSON, err := json.Marshal(AccountAutoMonitorSettings{
		Enabled: true, IntervalMinutes: 30, NextRunAt: &due,
	})
	require.NoError(t, err)

	resetAt := now.Add(time.Hour)
	settingRepo := &autoMonitorSettingRepoStub{value: string(settingsJSON)}
	accountRepo := &autoMonitorAccountRepoStub{accounts: []Account{
		{ID: 1, Status: StatusActive, RateLimitResetAt: &resetAt},
		{ID: 2, Status: StatusActive, OverloadUntil: &resetAt},
		{ID: 3, Status: StatusActive, TempUnschedulableUntil: &resetAt},
		{ID: 4, Status: StatusActive},
	}}
	tester := &autoMonitorTesterStub{results: map[int64]string{2: "success", 3: "success", 4: "success"}, called: make(map[int64]string)}
	recovery := &autoMonitorRecoveryStub{}
	runner := &ScheduledTestRunnerService{
		accountTestSvc: tester, rateLimitSvc: recovery, accountRepo: accountRepo, settingRepo: settingRepo,
	}

	runner.runAutoMonitorIfDue(context.Background(), now)

	tester.mu.Lock()
	require.Equal(t, map[int64]string{2: "", 3: "", 4: ""}, tester.called)
	tester.mu.Unlock()
	recovery.mu.Lock()
	require.ElementsMatch(t, []int64{2, 3, 4}, recovery.called)
	recovery.mu.Unlock()
}

func TestFormatAccountAutoMonitorEnabledAccounts(t *testing.T) {
	formatted := formatAccountAutoMonitorEnabledAccounts([]accountAutoMonitorEnabledAccount{
		{ID: 35, Name: "账号\nB"},
		{ID: 12, Name: `账号"A`},
	})

	require.JSONEq(t, `[
		{"id":12,"name":"账号\"A"},
		{"id":35,"name":"账号\nB"}
	]`, formatted)
	require.NotContains(t, formatted, "\n")
}
