package service

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

func mimoCompatibleProviderPreset() CompatibleProviderPreset {
	return CompatibleProviderPreset{
		Platform:       PlatformMimo,
		DisplayName:    compatiblePlatformDisplayName(PlatformMimo),
		DefaultBaseURL: "https://api.xiaomimimo.com/v1",
		DefaultModels: NormalizeCompatibleModelList([]claude.Model{
			{ID: "mimo-v2.5-pro", Type: "model", DisplayName: "MiMo V2.5 Pro"},
			{ID: "mimo-v2.5", Type: "model", DisplayName: "MiMo V2.5"},
		}),
		DefaultTestModel:  "mimo-v2.5",
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
