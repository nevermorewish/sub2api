package service

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

func minimaxCompatibleProviderPreset() CompatibleProviderPreset {
	return CompatibleProviderPreset{
		Platform:       PlatformMiniMax,
		DisplayName:    compatiblePlatformDisplayName(PlatformMiniMax),
		DefaultBaseURL: "https://api.minimaxi.com",
		DefaultModels: NormalizeCompatibleModelList([]claude.Model{
			{ID: "minimax-m2.5", Type: "model", DisplayName: "MiniMax M2.5"},
			{ID: "minimax-m2.7", Type: "model", DisplayName: "MiniMax M2.7"},
		}),
		DefaultTestModel:  "minimax-m2.5",
		AuthMode:          CompatibleAuthBearer,
		SupportsChat:      true,
		SupportsResponses: false,
		SupportsMessages:  func(string) bool { return true },
		BuildChatURL: func(baseURL, _ string) string {
			return joinRelayCompatibleURL(baseURL, "/chat/completions")
		},
		BuildResponsesURL: func(baseURL, _ string) string {
			return joinRelayCompatibleURL(baseURL, "/chat/completions")
		},
		BuildMessagesURL: func(baseURL, _ string) string {
			baseURL = strings.TrimRight(baseURL, "/")
			lower := strings.ToLower(baseURL)
			switch {
			case strings.HasSuffix(lower, "/anthropic/v1/messages"),
				strings.HasSuffix(lower, "/v1/messages"):
				return baseURL
			case strings.HasSuffix(lower, "/anthropic/v1"):
				return baseURL + "/messages"
			case strings.HasSuffix(lower, "/anthropic"):
				return baseURL + "/v1/messages"
			default:
				return baseURL + "/anthropic/v1/messages"
			}
		},
		PatchChatBody:     normalizeTopPForCompatibleBody,
		PatchMessagesBody: nil,
	}
}
