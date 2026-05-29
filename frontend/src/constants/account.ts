/** WebSearch emulation mode values (must match backend WebSearchMode* constants in account.go) */
export const WEB_SEARCH_MODE_DEFAULT = 'default' as const
export const WEB_SEARCH_MODE_ENABLED = 'enabled' as const
export const WEB_SEARCH_MODE_DISABLED = 'disabled' as const
export type WebSearchMode = typeof WEB_SEARCH_MODE_DEFAULT | typeof WEB_SEARCH_MODE_ENABLED | typeof WEB_SEARCH_MODE_DISABLED

/** Quota notification threshold type values (must match thresholdType* constants in balance_notify_service.go) */
export const QUOTA_THRESHOLD_TYPE_FIXED = 'fixed' as const
export const QUOTA_THRESHOLD_TYPE_PERCENTAGE = 'percentage' as const
export type QuotaThresholdType = typeof QUOTA_THRESHOLD_TYPE_FIXED | typeof QUOTA_THRESHOLD_TYPE_PERCENTAGE

/** Quota reset mode values */
export const QUOTA_RESET_MODE_ROLLING = 'rolling' as const
export const QUOTA_RESET_MODE_FIXED = 'fixed' as const
export type QuotaResetMode = typeof QUOTA_RESET_MODE_ROLLING | typeof QUOTA_RESET_MODE_FIXED

/** OpenCode Go API endpoints */
export const OPENCODE_GO_DOCS_URL = 'https://opencode.ai/docs/zh-cn/go/'
export const OPENCODE_GO_BASE_URL = 'https://opencode.ai/zen/go'
export const OPENCODE_GO_MODELS_URL = `${OPENCODE_GO_BASE_URL}/v1/models`
export const OPENCODE_GO_CHAT_MODELS = [
  'glm-5.1',
  'glm-5',
  'kimi-k2.5',
  'kimi-k2.6',
  'deepseek-v4-pro',
  'deepseek-v4-flash',
  'mimo-v2.5',
  'mimo-v2.5-pro'
] as const
export const OPENCODE_GO_MESSAGES_MODELS = [
  'minimax-m2.7',
  'minimax-m2.5',
  'qwen3.7-max',
  'qwen3.6-plus',
  'qwen3.5-plus'
] as const
export const OPENCODE_GO_ENDPOINTS = [
  {
    key: 'chatCompletions',
    label: 'Chat Completions',
    url: `${OPENCODE_GO_BASE_URL}/v1/chat/completions`,
    sdk: '@ai-sdk/openai-compatible',
    models: OPENCODE_GO_CHAT_MODELS
  },
  {
    key: 'messages',
    label: 'Messages',
    url: `${OPENCODE_GO_BASE_URL}/v1/messages`,
    sdk: '@ai-sdk/anthropic',
    models: OPENCODE_GO_MESSAGES_MODELS
  }
] as const
