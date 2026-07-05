//go:build unit

package service

import (
	"net/http"
	"testing"

	"github.com/tidwall/gjson"
)

func TestVolcengineCompatibleProviderPreset(t *testing.T) {
	preset := volcengineCompatibleProviderPreset()

	if preset.Platform != PlatformVolcEngine {
		t.Fatalf("Platform = %q, want %q", preset.Platform, PlatformVolcEngine)
	}
	if preset.DefaultBaseURL != "https://ark.cn-beijing.volces.com" {
		t.Fatalf("DefaultBaseURL = %q", preset.DefaultBaseURL)
	}
	if preset.DefaultTestModel != "glm-5.2" {
		t.Fatalf("DefaultTestModel = %q", preset.DefaultTestModel)
	}
	if preset.AuthMode != CompatibleAuthBearer {
		t.Fatalf("AuthMode = %q, want %q", preset.AuthMode, CompatibleAuthBearer)
	}
	if !preset.SupportsChat {
		t.Fatal("SupportsChat = false, want true")
	}
	if !preset.SupportsResponses {
		t.Fatal("SupportsResponses = false, want true")
	}
	if preset.SupportsMessages == nil {
		t.Fatal("SupportsMessages should not be nil")
	}
	if !preset.SupportsMessages("Doubao-lite-32k") {
		t.Fatal("SupportsMessages(Doubao-lite-32k) = false, want true")
	}
	if !preset.SupportsMessages("bot-ep-20250421") {
		t.Fatal("SupportsMessages(bot-ep-20250421) = false, want true")
	}
	if preset.PatchChatBody == nil {
		t.Fatal("PatchChatBody should not be nil")
	}
	if len(preset.DefaultModels) != 11 {
		t.Fatalf("len(DefaultModels) = %d, want 11", len(preset.DefaultModels))
	}

	wantModels := []string{
		"doubao-seed-2.0-code",
		"doubao-seed-2.0-pro",
		"doubao-seed-2.0-lite",
		"doubao-seed-code",
		"minimax-m2.7",
		"minimax-m3",
		"glm-5.2",
		"deepseek-v4-flash",
		"deepseek-v4-pro",
		"kimi-k2.6",
		"kimi-k2.7-code",
	}
	for i, want := range wantModels {
		if preset.DefaultModels[i].ID != want {
			t.Fatalf("DefaultModels[%d].ID = %q, want %q", i, preset.DefaultModels[i].ID, want)
		}
	}
}

func TestVolcengineCompatibleProviderPreset_Routes(t *testing.T) {
	preset := volcengineCompatibleProviderPreset()
	baseURL := "https://ark.cn-beijing.volces.com/"

	if got := preset.BuildChatURL(baseURL, "Doubao-lite-32k"); got != "https://ark.cn-beijing.volces.com/api/v3/chat/completions" {
		t.Fatalf("BuildChatURL() = %q", got)
	}
	if got := preset.BuildChatURL(baseURL, " bot-ep-20250421 "); got != "https://ark.cn-beijing.volces.com/api/v3/bots/chat/completions" {
		t.Fatalf("BuildChatURL(bot) = %q", got)
	}
	if got := preset.BuildResponsesURL(baseURL, "Doubao-lite-32k"); got != "https://ark.cn-beijing.volces.com/api/v3/responses" {
		t.Fatalf("BuildResponsesURL() = %q", got)
	}
	if got := preset.BuildMessagesURL(baseURL, "Doubao-lite-32k"); got != "https://ark.cn-beijing.volces.com/api/v3/chat/completions" {
		t.Fatalf("BuildMessagesURL() = %q", got)
	}
	if got := preset.BuildMessagesURL(baseURL, " bot-ep-20250421 "); got != "https://ark.cn-beijing.volces.com/api/v3/bots/chat/completions" {
		t.Fatalf("BuildMessagesURL(bot) = %q", got)
	}
}

func TestVolcengineCompatibleProviderPreset_CodingPlanRoutes(t *testing.T) {
	preset := volcengineCompatibleProviderPreset()

	if got := preset.BuildChatURL("https://ark.cn-beijing.volces.com/api/coding", "glm-5.2"); got != "https://ark.cn-beijing.volces.com/api/coding/v3/chat/completions" {
		t.Fatalf("BuildChatURL(coding) = %q", got)
	}
	if got := preset.BuildChatURL("https://ark.cn-beijing.volces.com/api/coding/v3", "glm-5.2"); got != "https://ark.cn-beijing.volces.com/api/coding/v3/chat/completions" {
		t.Fatalf("BuildChatURL(coding v3) = %q", got)
	}
	if got := preset.BuildResponsesURL("https://ark.cn-beijing.volces.com/api/coding", "glm-5.2"); got != "https://ark.cn-beijing.volces.com/api/coding/v3/responses" {
		t.Fatalf("BuildResponsesURL(coding) = %q", got)
	}
	if got := preset.BuildMessagesURL("https://ark.cn-beijing.volces.com/api/coding", "glm-5.2"); got != "https://ark.cn-beijing.volces.com/api/coding/v1/messages" {
		t.Fatalf("BuildMessagesURL(coding) = %q", got)
	}
	if got := preset.BuildMessagesURL("https://ark.cn-beijing.volces.com/api/coding/v3", "glm-5.2"); got != "https://ark.cn-beijing.volces.com/api/coding/v1/messages" {
		t.Fatalf("BuildMessagesURL(coding v3) = %q", got)
	}
}

func TestVolcengineCompatibleProviderPreset_MessagesFallback(t *testing.T) {
	svc := &CompatibleGatewayService{}
	account := newVolcengineCompatibleAccount()
	body := []byte(`{
		"model": "bot-ep-20250421",
		"max_tokens": 32,
		"messages": [
			{
				"role": "user",
				"content": "hello from messages"
			}
		]
	}`)

	prepared, err := svc.prepareRequest(account, CompatibleRouteMessages, body)
	if err != nil {
		t.Fatalf("prepareRequest() error = %v", err)
	}
	if prepared.UpstreamKind != compatibleUpstreamChat {
		t.Fatalf("UpstreamKind = %q, want %q", prepared.UpstreamKind, compatibleUpstreamChat)
	}
	if prepared.UpstreamEndpoint != "/v1/chat/completions" {
		t.Fatalf("UpstreamEndpoint = %q, want %q", prepared.UpstreamEndpoint, "/v1/chat/completions")
	}
	if prepared.UpstreamModel != "bot-ep-20250421" {
		t.Fatalf("UpstreamModel = %q, want %q", prepared.UpstreamModel, "bot-ep-20250421")
	}
	if got := gjson.GetBytes(prepared.RequestBody, "model").String(); got != "bot-ep-20250421" {
		t.Fatalf("patched model = %q, want %q", got, "bot-ep-20250421")
	}
	if got := gjson.GetBytes(prepared.RequestBody, "messages.0.role").String(); got != "user" {
		t.Fatalf("messages.0.role = %q, want %q", got, "user")
	}
	if got := gjson.GetBytes(prepared.RequestBody, "messages.0.content").String(); got != "hello from messages" {
		t.Fatalf("messages.0.content = %q, want %q", got, "hello from messages")
	}
	if got := svc.buildURLForPreparedRequest(account, prepared, account.GetCompatibleBaseURL()); got != "https://ark.cn-beijing.volces.com/api/v3/bots/chat/completions" {
		t.Fatalf("buildURLForPreparedRequest() = %q", got)
	}
}

func TestVolcengineCompatibleProviderPreset_CodingMessagesNative(t *testing.T) {
	svc := &CompatibleGatewayService{}
	account := newVolcengineCompatibleAccount()
	account.Credentials["base_url"] = "https://ark.cn-beijing.volces.com/api/coding"
	body := []byte(`{
		"model": "glm-5.2",
		"max_tokens": 32,
		"messages": [
			{
				"role": "user",
				"content": "hello from messages"
			}
		]
	}`)

	prepared, err := svc.prepareRequest(account, CompatibleRouteMessages, body)
	if err != nil {
		t.Fatalf("prepareRequest() error = %v", err)
	}
	if prepared.UpstreamKind != compatibleUpstreamMessages {
		t.Fatalf("UpstreamKind = %q, want %q", prepared.UpstreamKind, compatibleUpstreamMessages)
	}
	if prepared.UpstreamEndpoint != "/v1/messages" {
		t.Fatalf("UpstreamEndpoint = %q, want %q", prepared.UpstreamEndpoint, "/v1/messages")
	}
	if got := svc.buildURLForPreparedRequest(account, prepared, account.GetCompatibleBaseURL()); got != "https://ark.cn-beijing.volces.com/api/coding/v1/messages" {
		t.Fatalf("buildURLForPreparedRequest() = %q", got)
	}
}

func TestVolcengineCompatibleProviderPreset_BearerAuthAndBodyPatch(t *testing.T) {
	svc := &CompatibleGatewayService{}
	account := newVolcengineCompatibleAccount()

	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := svc.applyAuth(req, account); err != nil {
		t.Fatalf("applyAuth() error = %v", err)
	}
	if got := getHeaderRaw(req.Header, "authorization"); got != "Bearer volc-api-key" {
		t.Fatalf("authorization = %q, want %q", got, "Bearer volc-api-key")
	}

	chatBody := []byte(`{
		"model": "Doubao-lite-32k",
		"stop": "END",
		"messages": [
			{
				"role": "user",
				"content": "hello"
			}
		]
	}`)
	preparedChat, err := svc.prepareRequest(account, CompatibleRouteChatCompletions, chatBody)
	if err != nil {
		t.Fatalf("prepareRequest(chat) error = %v", err)
	}
	if !gjson.GetBytes(preparedChat.RequestBody, "stop").IsArray() {
		t.Fatalf("patched chat stop = %s, want array", gjson.GetBytes(preparedChat.RequestBody, "stop").Raw)
	}
	if len(gjson.GetBytes(preparedChat.RequestBody, "stop").Array()) != 1 || gjson.GetBytes(preparedChat.RequestBody, "stop.0").String() != "END" {
		t.Fatalf("patched chat stop = %s, want [\"END\"]", gjson.GetBytes(preparedChat.RequestBody, "stop").Raw)
	}

	responsesBody := []byte(`{
		"model": "Doubao-lite-32k",
		"input": "hello",
		"stop": "END"
	}`)
	preparedResponses, err := svc.prepareRequest(account, CompatibleRouteResponses, responsesBody)
	if err != nil {
		t.Fatalf("prepareRequest(responses) error = %v", err)
	}
	if preparedResponses.UpstreamKind != compatibleUpstreamResponses {
		t.Fatalf("responses UpstreamKind = %q, want %q", preparedResponses.UpstreamKind, compatibleUpstreamResponses)
	}
	if got := gjson.GetBytes(preparedResponses.RequestBody, "stop").String(); got != "END" {
		t.Fatalf("responses stop = %q, want %q", got, "END")
	}
	if gjson.GetBytes(preparedResponses.RequestBody, "stop").IsArray() {
		t.Fatalf("responses stop = %s, want string", gjson.GetBytes(preparedResponses.RequestBody, "stop").Raw)
	}
}

func newVolcengineCompatibleAccount() *Account {
	return &Account{
		Platform: PlatformVolcEngine,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key": "volc-api-key",
		},
	}
}
