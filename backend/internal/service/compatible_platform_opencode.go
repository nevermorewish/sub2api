package service

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

// OpenCode aggregator (https://opencode.ai/zen/go) exposes 14 models behind two upstream endpoints:
//   - /v1/messages         : minimax-* and qwen* models (Anthropic-style native)
//   - /v1/chat/completions : everything else (OpenAI-compatible)
func opencodeCompatibleProviderPreset() CompatibleProviderPreset {
	return CompatibleProviderPreset{
		Platform:       PlatformOpenCode,
		DisplayName:    compatiblePlatformDisplayName(PlatformOpenCode),
		DefaultBaseURL: "https://opencode.ai/zen/go",
		DefaultModels: NormalizeCompatibleModelList([]claude.Model{
			{ID: "glm-5.1", Type: "model", DisplayName: "GLM-5.1"},
			{ID: "glm-5", Type: "model", DisplayName: "GLM-5"},
			{ID: "kimi-k2.5", Type: "model", DisplayName: "Kimi K2.5"},
			{ID: "kimi-k2.6", Type: "model", DisplayName: "Kimi K2.6"},
			{ID: "deepseek-v4-pro", Type: "model", DisplayName: "DeepSeek V4 Pro"},
			{ID: "deepseek-v4-flash", Type: "model", DisplayName: "DeepSeek V4 Flash"},
			{ID: "mimo-v2.5", Type: "model", DisplayName: "MiMo V2.5"},
			{ID: "mimo-v2.5-pro", Type: "model", DisplayName: "MiMo V2.5 Pro"},
			{ID: "minimax-m3", Type: "model", DisplayName: "MiniMax M3"},
			{ID: "minimax-m2.7", Type: "model", DisplayName: "MiniMax M2.7"},
			{ID: "minimax-m2.5", Type: "model", DisplayName: "MiniMax M2.5"},
			{ID: "qwen3.7-max", Type: "model", DisplayName: "Qwen3.7 Max"},
			{ID: "qwen3.6-plus", Type: "model", DisplayName: "Qwen3.6 Plus"},
			{ID: "qwen3.5-plus", Type: "model", DisplayName: "Qwen3.5 Plus"},
		}),
		DefaultTestModel:  "glm-5",
		AuthMode:          CompatibleAuthBearer,
		SupportsChat:      true,
		SupportsResponses: false,
		SupportsMessages:  isOpencodeNativeMessagesModel,
		// On OpenCode the minimax-*/qwen* models are messages-only: the
		// chat/completions (oa-compat) format rejects them outright.
		RequiresNativeMessages: isOpencodeNativeMessagesModel,
		BuildChatURL: func(baseURL, _ string) string {
			return strings.TrimRight(baseURL, "/") + "/v1/chat/completions"
		},
		BuildResponsesURL: func(baseURL, _ string) string {
			return strings.TrimRight(baseURL, "/") + "/v1/chat/completions"
		},
		BuildMessagesURL: func(baseURL, upstreamModel string) string {
			baseURL = strings.TrimRight(baseURL, "/")
			if isOpencodeNativeMessagesModel(upstreamModel) {
				return baseURL + "/v1/messages"
			}
			return baseURL + "/v1/chat/completions"
		},
		PatchChatBody: normalizeTopPForCompatibleBody,
	}
}

func isOpencodeNativeMessagesModel(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(m, "minimax-") || strings.HasPrefix(m, "qwen")
}
