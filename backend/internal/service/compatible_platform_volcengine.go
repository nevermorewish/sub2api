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
			{ID: "doubao-seed-1-6-thinking-250715", Type: "model", DisplayName: "Doubao Seed 1.6 Thinking"},
			{ID: "Doubao-pro-128k", Type: "model", DisplayName: "Doubao Pro 128k"},
			{ID: "Doubao-lite-32k", Type: "model", DisplayName: "Doubao Lite 32k"},
		}),
		DefaultTestModel:  "Doubao-lite-32k",
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
