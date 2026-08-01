package service

import (
	"context"
	"encoding/json"
	"strings"
)

// GLMMultimodalSupportedExtraKey marks OpenAI-compatible accounts dedicated
// to GLM requests that need multimodal-capable routing. A true value enables
// image and 131072-token requests and excludes the account from ordinary GLM
// routing.
const GLMMultimodalSupportedExtraKey = "glm_multimodal_supported"

// defaultGLMMultimodalSupported keeps specialized GLM routing opt-in. Accounts
// that omit the capability flag, set it to false, or provide an invalid value
// must not receive image-bearing or 131072-token GLM requests.
const defaultGLMMultimodalSupported = false

const glmMultimodalRoutingMaxTokens = 131072

type glmMultimodalRoutingContextKey struct{}

// WithGLMMultimodalRouting requires account selection to use a GLM account
// marked as multimodal-capable.
func WithGLMMultimodalRouting(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, glmMultimodalRoutingContextKey{}, true)
}

func requiresGLMMultimodalRouting(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	required, _ := ctx.Value(glmMultimodalRoutingContextKey{}).(bool)
	return required
}

// SupportsGLMMultimodal reports whether this account is explicitly enabled
// for GLM multimodal-capable routing. Missing values default to false.
func (a *Account) SupportsGLMMultimodal() bool {
	if a == nil || a.Type != AccountTypeAPIKey || a.Extra == nil {
		return false
	}
	if a.Platform != PlatformOpenAI && a.Platform != PlatformAnthropic {
		return false
	}
	supported, ok := a.Extra[GLMMultimodalSupportedExtraKey].(bool)
	if !ok {
		return defaultGLMMultimodalSupported
	}
	return supported
}

func glmMultimodalRoutingRejectionReason(ctx context.Context, account *Account, model string) string {
	if account == nil || !isGLMModel(model) {
		return ""
	}

	multimodalRequired := requiresGLMMultimodalRouting(ctx)
	multimodalOnly := account.SupportsGLMMultimodal()
	switch {
	case multimodalRequired && !multimodalOnly:
		return "glm_multimodal_unsupported"
	case !multimodalRequired && multimodalOnly:
		return "glm_multimodal_only"
	default:
		return ""
	}
}

// RequiresGLMMultimodalRouting detects GLM requests that must use accounts
// marked as multimodal-capable. In addition to image input, max_tokens=131072
// uses this route because some otherwise compatible providers cap it at 128000.
func RequiresGLMMultimodalRouting(model string, body []byte) bool {
	payload, ok := parseGLMRequestPayload(model, body)
	if !ok {
		return false
	}

	if root, ok := payload.(map[string]any); ok {
		maxTokens, isNumber := root["max_tokens"].(float64)
		if isNumber && maxTokens == glmMultimodalRoutingMaxTokens {
			return true
		}
	}
	return containsImageInput(payload)
}

// IsGLMMultimodalRequest detects image-bearing GLM requests across OpenAI
// Chat Completions, Responses, and Anthropic Messages compatible payloads.
func IsGLMMultimodalRequest(model string, body []byte) bool {
	payload, ok := parseGLMRequestPayload(model, body)
	if !ok {
		return false
	}
	return containsImageInput(payload)
}

func parseGLMRequestPayload(model string, body []byte) (any, bool) {
	if !isGLMModel(model) || len(body) == 0 {
		return nil, false
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false
	}
	return payload, true
}

func isGLMModel(model string) bool {
	normalized := strings.ToLower(strings.TrimSpace(model))
	if normalized == "" {
		return false
	}
	for _, separator := range []string{"/", ":"} {
		if index := strings.LastIndex(normalized, separator); index >= 0 {
			normalized = normalized[index+1:]
		}
	}
	return normalized == "glm" || strings.HasPrefix(normalized, "glm-") || strings.HasPrefix(normalized, "glm_")
}

func containsImageInput(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if containsImageInput(item) {
				return true
			}
		}
	case map[string]any:
		if typeValue, _ := typed["type"].(string); isImageInputType(typeValue) {
			return true
		}
		if hasNonEmptyImageValue(typed["image_url"]) || hasNonEmptyImageValue(typed["image"]) {
			return true
		}
		for key, item := range typed {
			// Output-only image fields and image-generation tool declarations do
			// not make a text-generation request multimodal.
			if key == "tools" || key == "tool_choice" || key == "response_format" {
				continue
			}
			if containsImageInput(item) {
				return true
			}
		}
	}
	return false
}

func isImageInputType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "image", "image_url", "input_image", "input_image_url":
		return true
	default:
		return false
	}
}

func hasNonEmptyImageValue(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case map[string]any:
		return len(typed) > 0
	default:
		return false
	}
}
