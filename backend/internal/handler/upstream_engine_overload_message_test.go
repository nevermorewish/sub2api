package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const engineOverloadedUpstreamBody = `{"error":{"type":"rate_limit_error","message":"The engine is currently overloaded, please try again later"},"type":"error"}`

func TestGatewayFailoverExhausted_PreservesEngineOverloadedMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	(&GatewayHandler{}).handleFailoverExhausted(c, engineOverloadedFailoverError(), service.PlatformAnthropic, false)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "The engine is currently overloaded, please try again later", responseErrorMessage(t, rec))
}

func TestOpenAIFailoverExhausted_PreservesEngineOverloadedMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	(&OpenAIGatewayHandler{}).handleFailoverExhausted(c, engineOverloadedFailoverError(), false)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "The engine is currently overloaded, please try again later", responseErrorMessage(t, rec))
}

func TestGatewayFailoverExhausted_RedactsOtherRateLimitMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	err := &service.UpstreamFailoverError{
		StatusCode:   http.StatusTooManyRequests,
		ResponseBody: []byte(`{"error":{"message":"private upstream billing detail"}}`),
	}
	(&GatewayHandler{}).handleFailoverExhausted(c, err, service.PlatformAnthropic, false)

	require.Equal(t, "Upstream rate limit exceeded, please retry later", responseErrorMessage(t, rec))
	require.NotContains(t, rec.Body.String(), "private upstream billing detail")
}

func engineOverloadedFailoverError() *service.UpstreamFailoverError {
	return &service.UpstreamFailoverError{
		StatusCode:   http.StatusTooManyRequests,
		ResponseBody: []byte(engineOverloadedUpstreamBody),
	}
}

func responseErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	return envelope.Error.Message
}
