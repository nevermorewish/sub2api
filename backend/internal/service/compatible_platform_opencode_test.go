//go:build unit

package service

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestOpenCodeCompatibleProviderPreset_Routes(t *testing.T) {
	preset := opencodeCompatibleProviderPreset()
	baseURL := "https://opencode.ai/zen/go/"

	wantChat := "https://opencode.ai/zen/go/v1/chat/completions"
	if got := preset.BuildChatURL(baseURL, "glm-5"); got != wantChat {
		t.Fatalf("BuildChatURL() = %q, want %q", got, wantChat)
	}
	if got := preset.BuildResponsesURL(baseURL, "glm-5"); got != wantChat {
		t.Fatalf("BuildResponsesURL() = %q, want %q", got, wantChat)
	}
	if got := preset.BuildMessagesURL(baseURL, "glm-5"); got != wantChat {
		t.Fatalf("BuildMessagesURL(non-native) = %q, want %q", got, wantChat)
	}

	wantMessages := "https://opencode.ai/zen/go/v1/messages"
	if got := preset.BuildMessagesURL(baseURL, " minimax-m2.7 "); got != wantMessages {
		t.Fatalf("BuildMessagesURL(minimax) = %q, want %q", got, wantMessages)
	}
	if got := preset.BuildMessagesURL(baseURL, "QWEN3.7-MAX"); got != wantMessages {
		t.Fatalf("BuildMessagesURL(qwen) = %q, want %q", got, wantMessages)
	}
}

func TestOpenCodeCompatibleProviderPreset_SupportsMessages(t *testing.T) {
	preset := opencodeCompatibleProviderPreset()

	if !preset.SupportsMessages("minimax-m2.7") {
		t.Fatal("SupportsMessages(minimax-m2.7) = false, want true")
	}
	if !preset.SupportsMessages(" QWEN3.7-MAX ") {
		t.Fatal("SupportsMessages(qwen3.7-max) = false, want true")
	}
	if preset.SupportsMessages("glm-5") {
		t.Fatal("SupportsMessages(glm-5) = true, want false")
	}
	if preset.SupportsMessages("kimi-k2.5") {
		t.Fatal("SupportsMessages(kimi-k2.5) = true, want false")
	}
}

func TestCompatibleGatewayServicePrepareRequest_OpenCodeRoutesByMappedModel(t *testing.T) {
	svc := &CompatibleGatewayService{}
	account := &Account{
		Platform: PlatformOpenCode,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key": "test-key",
			"model_mapping": map[string]any{
				"claude-sonnet-4": "qwen3.7-max",
			},
		},
	}

	prepared, err := svc.prepareRequest(account, CompatibleRouteMessages, []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":16}`))
	if err != nil {
		t.Fatalf("prepareRequest() error = %v", err)
	}
	if prepared.UpstreamKind != compatibleUpstreamMessages {
		t.Fatalf("UpstreamKind = %q, want %q", prepared.UpstreamKind, compatibleUpstreamMessages)
	}
	if prepared.UpstreamEndpoint != "/v1/messages" {
		t.Fatalf("UpstreamEndpoint = %q, want %q", prepared.UpstreamEndpoint, "/v1/messages")
	}
	if prepared.UpstreamModel != "qwen3.7-max" {
		t.Fatalf("UpstreamModel = %q, want %q", prepared.UpstreamModel, "qwen3.7-max")
	}
	if got := gjson.GetBytes(prepared.RequestBody, "model").String(); got != "qwen3.7-max" {
		t.Fatalf("patched request model = %q, want %q", got, "qwen3.7-max")
	}
	if got := svc.buildURLForPreparedRequest(account, prepared, "https://opencode.ai/zen/go"); got != "https://opencode.ai/zen/go/v1/messages" {
		t.Fatalf("buildURLForPreparedRequest() = %q, want messages endpoint", got)
	}
}

func TestCompatibleGatewayServicePrepareRequest_OpenCodeFallsBackToChatByMappedModel(t *testing.T) {
	svc := &CompatibleGatewayService{}
	account := &Account{
		Platform: PlatformOpenCode,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key": "test-key",
			"model_mapping": map[string]any{
				"claude-sonnet-4": "glm-5",
			},
		},
	}

	prepared, err := svc.prepareRequest(account, CompatibleRouteMessages, []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":16}`))
	if err != nil {
		t.Fatalf("prepareRequest() error = %v", err)
	}
	if prepared.UpstreamKind != compatibleUpstreamChat {
		t.Fatalf("UpstreamKind = %q, want %q", prepared.UpstreamKind, compatibleUpstreamChat)
	}
	if prepared.UpstreamEndpoint != "/v1/chat/completions" {
		t.Fatalf("UpstreamEndpoint = %q, want %q", prepared.UpstreamEndpoint, "/v1/chat/completions")
	}
	if prepared.UpstreamModel != "glm-5" {
		t.Fatalf("UpstreamModel = %q, want %q", prepared.UpstreamModel, "glm-5")
	}
	if got := gjson.GetBytes(prepared.RequestBody, "model").String(); got != "glm-5" {
		t.Fatalf("patched request model = %q, want %q", got, "glm-5")
	}
	if got := svc.buildURLForPreparedRequest(account, prepared, "https://opencode.ai/zen/go"); got != "https://opencode.ai/zen/go/v1/chat/completions" {
		t.Fatalf("buildURLForPreparedRequest() = %q, want chat completions endpoint", got)
	}
}
