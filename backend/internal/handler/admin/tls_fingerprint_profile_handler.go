package admin

import (
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// TLSFingerprintProfileHandler 处理 TLS 指纹模板的 HTTP 请求
type TLSFingerprintProfileHandler struct {
	service *service.TLSFingerprintProfileService
}

// NewTLSFingerprintProfileHandler 创建 TLS 指纹模板处理器
func NewTLSFingerprintProfileHandler(service *service.TLSFingerprintProfileService) *TLSFingerprintProfileHandler {
	return &TLSFingerprintProfileHandler{service: service}
}

// CreateTLSFingerprintProfileRequest 创建模板请求
type CreateTLSFingerprintProfileRequest struct {
	Name                string   `json:"name" binding:"required"`
	Description         *string  `json:"description"`
	EnableGREASE        *bool    `json:"enable_grease"`
	CipherSuites        []uint16 `json:"cipher_suites"`
	Curves              []uint16 `json:"curves"`
	PointFormats        []uint16 `json:"point_formats"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms"`
	ALPNProtocols       []string `json:"alpn_protocols"`
	SupportedVersions   []uint16 `json:"supported_versions"`
	KeyShareGroups      []uint16 `json:"key_share_groups"`
	PSKModes            []uint16 `json:"psk_modes"`
	Extensions          []uint16 `json:"extensions"`
}

// UpdateTLSFingerprintProfileRequest 更新模板请求（部分更新）
type UpdateTLSFingerprintProfileRequest struct {
	Name                *string  `json:"name"`
	Description         *string  `json:"description"`
	EnableGREASE        *bool    `json:"enable_grease"`
	CipherSuites        []uint16 `json:"cipher_suites"`
	Curves              []uint16 `json:"curves"`
	PointFormats        []uint16 `json:"point_formats"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms"`
	ALPNProtocols       []string `json:"alpn_protocols"`
	SupportedVersions   []uint16 `json:"supported_versions"`
	KeyShareGroups      []uint16 `json:"key_share_groups"`
	PSKModes            []uint16 `json:"psk_modes"`
	Extensions          []uint16 `json:"extensions"`
}

type GenerateTLSFingerprintProfileRequest struct {
	Name            string   `json:"name"`
	Description     *string  `json:"description"`
	Runtime         string   `json:"runtime"`
	RuntimeVersion  string   `json:"runtime_version"`
	NodeMajor       int      `json:"node_major"`
	OpenSSLVersion  string   `json:"openssl_version"`
	Transport       string   `json:"transport"`
	HTTPClient      string   `json:"http_client"`
	WebSocketClient string   `json:"websocket_client"`
	ProxyMode       string   `json:"proxy_mode"`
	MTLSEnabled     bool     `json:"mtls_enabled"`
	CustomCAEnabled bool     `json:"custom_ca_enabled"`
	ALPNProtocols   []string `json:"alpn_protocols"`
	EnableGREASE    *bool    `json:"enable_grease"`
}

type GenerateTLSFingerprintProfileResponse struct {
	Profile *model.TLSFingerprintProfile `json:"profile"`
	Notes   []string                     `json:"notes"`
}

// List 获取所有模板
// GET /api/v1/admin/tls-fingerprint-profiles
func (h *TLSFingerprintProfileHandler) List(c *gin.Context) {
	profiles, err := h.service.List(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, profiles)
}

// GetByID 根据 ID 获取模板
// GET /api/v1/admin/tls-fingerprint-profiles/:id
func (h *TLSFingerprintProfileHandler) GetByID(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid profile ID")
		return
	}

	profile, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if profile == nil {
		response.NotFound(c, "Profile not found")
		return
	}

	response.Success(c, profile)
}

// Create 创建模板
// POST /api/v1/admin/tls-fingerprint-profiles
func (h *TLSFingerprintProfileHandler) Create(c *gin.Context) {
	var req CreateTLSFingerprintProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	profile := &model.TLSFingerprintProfile{
		Name:                req.Name,
		Description:         req.Description,
		CipherSuites:        req.CipherSuites,
		Curves:              req.Curves,
		PointFormats:        req.PointFormats,
		SignatureAlgorithms: req.SignatureAlgorithms,
		ALPNProtocols:       req.ALPNProtocols,
		SupportedVersions:   req.SupportedVersions,
		KeyShareGroups:      req.KeyShareGroups,
		PSKModes:            req.PSKModes,
		Extensions:          req.Extensions,
	}

	if req.EnableGREASE != nil {
		profile.EnableGREASE = *req.EnableGREASE
	}

	created, err := h.service.Create(c.Request.Context(), profile)
	if err != nil {
		if _, ok := err.(*model.ValidationError); ok {
			response.BadRequest(c, err.Error())
			return
		}
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, created)
}

// POST /api/v1/admin/tls-fingerprint-profiles/generate
func (h *TLSFingerprintProfileHandler) Generate(c *gin.Context) {
	var req GenerateTLSFingerprintProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	generated := tlsfingerprint.GenerateProfileTemplate(tlsfingerprint.GenerateOptions{
		Name:            req.Name,
		Runtime:         req.Runtime,
		RuntimeVersion:  req.RuntimeVersion,
		NodeMajor:       req.NodeMajor,
		OpenSSLVersion:  req.OpenSSLVersion,
		Transport:       req.Transport,
		HTTPClient:      req.HTTPClient,
		WebSocketClient: req.WebSocketClient,
		ProxyMode:       req.ProxyMode,
		MTLSEnabled:     req.MTLSEnabled,
		CustomCAEnabled: req.CustomCAEnabled,
		ALPNProtocols:   req.ALPNProtocols,
		EnableGREASE:    req.EnableGREASE,
	})

	profile := &model.TLSFingerprintProfile{
		Name:                generated.Profile.Name,
		Description:         req.Description,
		EnableGREASE:        generated.Profile.EnableGREASE,
		CipherSuites:        generated.Profile.CipherSuites,
		Curves:              generated.Profile.Curves,
		PointFormats:        generated.Profile.PointFormats,
		SignatureAlgorithms: generated.Profile.SignatureAlgorithms,
		ALPNProtocols:       generated.Profile.ALPNProtocols,
		SupportedVersions:   generated.Profile.SupportedVersions,
		KeyShareGroups:      generated.Profile.KeyShareGroups,
		PSKModes:            generated.Profile.PSKModes,
		Extensions:          generated.Profile.Extensions,
	}

	response.Success(c, GenerateTLSFingerprintProfileResponse{
		Profile: profile,
		Notes:   generated.Notes,
	})
}

// Update 更新模板（支持部分更新）
// PUT /api/v1/admin/tls-fingerprint-profiles/:id
func (h *TLSFingerprintProfileHandler) Update(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid profile ID")
		return
	}

	var req UpdateTLSFingerprintProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	existing, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if existing == nil {
		response.NotFound(c, "Profile not found")
		return
	}

	// 部分更新
	profile := &model.TLSFingerprintProfile{
		ID:                  id,
		Name:                existing.Name,
		Description:         existing.Description,
		EnableGREASE:        existing.EnableGREASE,
		CipherSuites:        existing.CipherSuites,
		Curves:              existing.Curves,
		PointFormats:        existing.PointFormats,
		SignatureAlgorithms: existing.SignatureAlgorithms,
		ALPNProtocols:       existing.ALPNProtocols,
		SupportedVersions:   existing.SupportedVersions,
		KeyShareGroups:      existing.KeyShareGroups,
		PSKModes:            existing.PSKModes,
		Extensions:          existing.Extensions,
	}

	if req.Name != nil {
		profile.Name = *req.Name
	}
	if req.Description != nil {
		profile.Description = req.Description
	}
	if req.EnableGREASE != nil {
		profile.EnableGREASE = *req.EnableGREASE
	}
	if req.CipherSuites != nil {
		profile.CipherSuites = req.CipherSuites
	}
	if req.Curves != nil {
		profile.Curves = req.Curves
	}
	if req.PointFormats != nil {
		profile.PointFormats = req.PointFormats
	}
	if req.SignatureAlgorithms != nil {
		profile.SignatureAlgorithms = req.SignatureAlgorithms
	}
	if req.ALPNProtocols != nil {
		profile.ALPNProtocols = req.ALPNProtocols
	}
	if req.SupportedVersions != nil {
		profile.SupportedVersions = req.SupportedVersions
	}
	if req.KeyShareGroups != nil {
		profile.KeyShareGroups = req.KeyShareGroups
	}
	if req.PSKModes != nil {
		profile.PSKModes = req.PSKModes
	}
	if req.Extensions != nil {
		profile.Extensions = req.Extensions
	}

	updated, err := h.service.Update(c.Request.Context(), profile)
	if err != nil {
		if _, ok := err.(*model.ValidationError); ok {
			response.BadRequest(c, err.Error())
			return
		}
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, updated)
}

// Delete 删除模板
// DELETE /api/v1/admin/tls-fingerprint-profiles/:id
func (h *TLSFingerprintProfileHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid profile ID")
		return
	}

	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Profile deleted successfully"})
}
