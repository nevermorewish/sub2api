package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsGLMMultimodalRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		model string
		body  string
		want  bool
	}{
		{
			name:  "chat image url",
			model: "glm-4.6v",
			body:  `{"messages":[{"role":"user","content":[{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`,
			want:  true,
		},
		{
			name:  "responses input image",
			model: "vendor/glm-4.6",
			body:  `{"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AA=="}]}]}`,
			want:  true,
		},
		{
			name:  "anthropic image source",
			model: "GLM-4.5V",
			body:  `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}}]}]}`,
			want:  true,
		},
		{
			name:  "glm text only",
			model: "glm-4.6",
			body:  `{"messages":[{"role":"user","content":"hello"}]}`,
			want:  false,
		},
		{
			name:  "non glm vision request",
			model: "gpt-4.1",
			body:  `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`,
			want:  false,
		},
		{
			name:  "image generation tool is not image input",
			model: "glm-4.6",
			body:  `{"tools":[{"type":"image_generation"}],"input":"draw a cat"}`,
			want:  false,
		},
		{
			name:  "invalid json",
			model: "glm-4.6",
			body:  `{`,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, IsGLMMultimodalRequest(tt.model, []byte(tt.body)))
		})
	}
}

func TestGLMMultimodalRoutingRequiresExplicitAccountSupport(t *testing.T) {
	t.Parallel()

	unsupported := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true, Extra: map[string]any{}}
	supported := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true, Extra: map[string]any{GLMMultimodalSupportedExtraKey: true}}
	ctx := WithGLMMultimodalRouting(context.Background())

	require.False(t, isOpenAICompatibleAccountEligibleForRequest(ctx, unsupported, PlatformOpenAI, "glm-4.6", false, ""))
	require.True(t, isOpenAICompatibleAccountEligibleForRequest(ctx, supported, PlatformOpenAI, "glm-4.6", false, ""))
	require.True(t, isOpenAICompatibleAccountEligibleForRequest(context.Background(), unsupported, PlatformOpenAI, "glm-4.6", false, ""))
}

func TestSupportsGLMMultimodalForAPIKeyProtocols(t *testing.T) {
	t.Parallel()

	for _, platform := range []string{PlatformOpenAI, PlatformAnthropic} {
		account := &Account{
			Platform: platform,
			Type:     AccountTypeAPIKey,
			Extra:    map[string]any{GLMMultimodalSupportedExtraKey: true},
		}
		require.True(t, account.SupportsGLMMultimodal(), platform)
	}

	require.False(t, (&Account{
		Platform: PlatformAnthropic,
		Type:     AccountTypeAPIKey,
	}).SupportsGLMMultimodal())
	require.False(t, (&Account{
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{GLMMultimodalSupportedExtraKey: true},
	}).SupportsGLMMultimodal())
}

func TestAnthropicSchedulerFiltersGLMMultimodalCapability(t *testing.T) {
	t.Parallel()

	ctx := WithGLMMultimodalRouting(context.Background())
	unsupported := &Account{
		Platform:    PlatformAnthropic,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
	}
	supported := &Account{
		Platform:    PlatformAnthropic,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Extra:       map[string]any{GLMMultimodalSupportedExtraKey: true},
	}
	service := &GatewayService{}

	require.False(t, service.isAccountSchedulableForModelSelection(ctx, unsupported, "glm-4.6"))
	require.True(t, service.isAccountSchedulableForModelSelection(ctx, supported, "glm-4.6"))
	require.True(t, service.isAccountSchedulableForModelSelection(context.Background(), unsupported, "glm-4.6"))
}

func TestAdvancedSchedulerFiltersGLMMultimodalCapability(t *testing.T) {
	t.Parallel()

	unsupported := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true}
	supported := &Account{
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Extra:       map[string]any{GLMMultimodalSupportedExtraKey: true},
	}
	scheduler := &defaultOpenAIAccountScheduler{}
	ctx := WithGLMMultimodalRouting(context.Background())
	req := OpenAIAccountScheduleRequest{Platform: PlatformOpenAI, RequestedModel: "glm-4.6"}

	compatible, reason := scheduler.isAccountRequestCompatibleReason(ctx, unsupported, req)
	require.False(t, compatible)
	require.Equal(t, "glm_multimodal_unsupported", reason)

	compatible, reason = scheduler.isAccountRequestCompatibleReason(ctx, supported, req)
	require.True(t, compatible)
	require.Empty(t, reason)
}
