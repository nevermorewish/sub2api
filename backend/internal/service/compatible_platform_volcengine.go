package service

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

func volcengineCompatibleProviderPreset() CompatibleProviderPreset {
	return CompatibleProviderPreset{
		Platform:       PlatformVolcEngine,
		DisplayName:    compatiblePlatformDisplayName(PlatformVolcEngine),
		DefaultBaseURL: "https://ark.cn-beijing.volces.com",
		DefaultModels: NormalizeCompatibleModelList([]claude.Model{
			{ID: "doubao-seed-2.0-code", Type: "model", DisplayName: "Doubao Seed 2.0 Code"},
			{ID: "doubao-seed-2.0-pro", Type: "model", DisplayName: "Doubao Seed 2.0 Pro"},
			{ID: "doubao-seed-2.0-lite", Type: "model", DisplayName: "Doubao Seed 2.0 Lite"},
			{ID: "doubao-seed-code", Type: "model", DisplayName: "Doubao Seed Code"},
			{ID: "minimax-m2.7", Type: "model", DisplayName: "MiniMax M2.7"},
			{ID: "minimax-m3", Type: "model", DisplayName: "MiniMax M3"},
			{ID: "glm-5.2", Type: "model", DisplayName: "GLM-5.2"},
			{ID: "deepseek-v4-flash", Type: "model", DisplayName: "DeepSeek V4 Flash"},
			{ID: "deepseek-v4-pro", Type: "model", DisplayName: "DeepSeek V4 Pro"},
			{ID: "kimi-k2.6", Type: "model", DisplayName: "Kimi K2.6"},
			{ID: "kimi-k2.7-code", Type: "model", DisplayName: "Kimi K2.7 Code"},
		}),
		DefaultTestModel:  "glm-5.2",
		AuthMode:          CompatibleAuthBearer,
		SupportsChat:      true,
		SupportsResponses: true,
		SupportsMessages:  func(string) bool { return true },
		BuildChatURL: func(baseURL, upstreamModel string) string {
			baseURL = normalizeVolcengineChatBaseURL(baseURL)
			if strings.HasPrefix(strings.TrimSpace(upstreamModel), "bot") {
				return baseURL + "/bots/chat/completions"
			}
			return baseURL + "/chat/completions"
		},
		BuildResponsesURL: func(baseURL, _ string) string {
			return normalizeVolcengineChatBaseURL(baseURL) + "/responses"
		},
		BuildMessagesURL: func(baseURL, upstreamModel string) string {
			if isVolcengineCodingBaseURL(baseURL) {
				return normalizeVolcengineMessagesBaseURL(baseURL) + "/messages"
			}
			baseURL = normalizeVolcengineChatBaseURL(baseURL)
			if strings.HasPrefix(strings.TrimSpace(upstreamModel), "bot") {
				return baseURL + "/bots/chat/completions"
			}
			return baseURL + "/chat/completions"
		},
		PatchChatBody: patchVolcengineChatBody,
	}
}

func isVolcengineCodingBaseURL(baseURL string) bool {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return strings.HasSuffix(baseURL, "/api/coding") || strings.HasSuffix(baseURL, "/api/coding/v1") || strings.HasSuffix(baseURL, "/api/coding/v3")
}

func normalizeVolcengineMessagesBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	switch {
	case strings.HasSuffix(baseURL, "/api/coding/v1"):
		return baseURL
	case strings.HasSuffix(baseURL, "/api/coding/v3"):
		return strings.TrimSuffix(baseURL, "/v3") + "/v1"
	case strings.HasSuffix(baseURL, "/api/coding"):
		return baseURL + "/v1"
	default:
		return baseURL + "/api/v3"
	}
}

func normalizeVolcengineChatBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	switch {
	case strings.HasSuffix(baseURL, "/api/coding/v3"):
		return baseURL
	case strings.HasSuffix(baseURL, "/api/coding"):
		return baseURL + "/v3"
	case strings.HasSuffix(baseURL, "/api/v3"):
		return baseURL
	default:
		return baseURL + "/api/v3"
	}
}

func patchVolcengineChatBody(body []byte, _ *Account, _ string) ([]byte, error) {
	return normalizeStopStringToArray(body), nil
}
