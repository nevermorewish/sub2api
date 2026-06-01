package tlsfingerprint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// GenerateOptions describes a high-level client environment that should be
// converted into a concrete TLS Profile template. The result is a best-effort
// uTLS template; exact Node/Bun fingerprints still require capture-based
// verification because runtime TLS stacks are not stable API contracts.
type GenerateOptions struct {
	Name            string
	Description     string
	Runtime         string
	RuntimeVersion  string
	NodeMajor       int
	OpenSSLVersion  string
	Transport       string
	HTTPClient      string
	WebSocketClient string
	ProxyMode       string
	MTLSEnabled     bool
	CustomCAEnabled bool
	ALPNProtocols   []string
	EnableGREASE    *bool
}

// GeneratedProfile is returned by GenerateProfileTemplate.
type GeneratedProfile struct {
	Profile *Profile
	Notes   []string
}

// GenerateProfileTemplate creates a concrete TLS Profile from high-level
// runtime parameters. This intentionally encodes known templates instead of
// pretending that Node/OpenSSL versions can be mathematically expanded into a
// ClientHello. Use the capture tool for byte-level fidelity.
func GenerateProfileTemplate(opts GenerateOptions) GeneratedProfile {
	runtime := strings.ToLower(strings.TrimSpace(opts.Runtime))
	if runtime == "" {
		runtime = "node"
	}
	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" {
		transport = "fetch"
	}

	major := opts.NodeMajor
	if major == 0 {
		major = parseMajorVersion(opts.RuntimeVersion)
	}

	var p *Profile
	var notes []string
	switch runtime {
	case "node", "nodejs":
		if major >= 24 {
			p = node24Template()
			notes = append(notes, "Using captured Claude Code Node.js 24/OpenSSL 3 template. This template includes the captured extension order, including padding, because extension order affects JA3/JA4.")
		} else {
			p = node22Template()
			if major == 0 {
				notes = append(notes, "Node.js major version was not provided; using the Node.js 22/OpenSSL style compatibility template.")
			} else {
				notes = append(notes, fmt.Sprintf("Using Node.js %d/OpenSSL style compatibility template.", major))
			}
		}
	case "bun":
		p = node24Template()
		p.Name = "Bun-compatible Claude Code TLS template"
		p.EnableGREASE = true
		notes = append(notes, "Bun TLS is runtime-owned and differs from Node/OpenSSL; this generator uses a GREASE-enabled Node 24 compatible fallback. Capture a real Bun ClientHello for strict matching.")
	default:
		p = node24Template()
		notes = append(notes, fmt.Sprintf("Unknown runtime %q; using Node.js 24 compatible template.", opts.Runtime))
	}

	if opts.Name != "" {
		p.Name = strings.TrimSpace(opts.Name)
	} else {
		p.Name = buildGeneratedName(runtime, major, transport, opts.HTTPClient, opts.WebSocketClient)
	}

	if opts.EnableGREASE != nil {
		p.EnableGREASE = *opts.EnableGREASE
	}

	if len(opts.ALPNProtocols) > 0 {
		p.ALPNProtocols = cloneStrings(opts.ALPNProtocols)
	} else {
		p.ALPNProtocols = defaultALPNForTransport(transport)
	}

	if strings.Contains(transport, "h2") || strings.Contains(transport, "http2") {
		notes = append(notes, "HTTP/2 changes ALPN and HTTP/2 frames; this template only controls TLS ClientHello.")
	}
	if strings.TrimSpace(opts.OpenSSLVersion) != "" {
		notes = append(notes, "OpenSSL version is recorded as selector metadata; exact fingerprints can still vary by Node build and platform.")
	}
	if strings.TrimSpace(opts.ProxyMode) != "" && !strings.EqualFold(opts.ProxyMode, "none") {
		notes = append(notes, "Proxy CONNECT does not change the inner upstream TLS ClientHello, but proxy software can add timing and network-level signals.")
	}
	if opts.MTLSEnabled {
		notes = append(notes, "mTLS sends client certificate messages after ClientHello; it is not represented by JA3/JA4 ClientHello fields.")
	}
	if opts.CustomCAEnabled {
		notes = append(notes, "Custom CA trust affects verification, not ClientHello.")
	}

	return GeneratedProfile{Profile: p, Notes: notes}
}

func buildGeneratedName(runtime string, major int, transport, httpClient, wsClient string) string {
	label := "Claude Code"
	if runtime == "bun" {
		label += " Bun"
	} else if major > 0 {
		label += fmt.Sprintf(" Node.js %d", major)
	} else {
		label += " Node.js"
	}
	if transport != "" {
		label += " " + transport
	}
	if strings.Contains(transport, "websocket") && wsClient != "" {
		label += " " + wsClient
	} else if httpClient != "" {
		label += " " + httpClient
	}
	return label
}

func parseMajorVersion(v string) int {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if v == "" {
		return 0
	}
	re := regexp.MustCompile(`^(\d+)`)
	match := re.FindStringSubmatch(v)
	if len(match) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(match[1])
	return n
}

func defaultALPNForTransport(transport string) []string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "h2", "http2", "http/2":
		return []string{"h2", "http/1.1"}
	default:
		return []string{"http/1.1"}
	}
}

func node24Template() *Profile {
	return &Profile{
		Name:                "Claude Code Node.js 24",
		EnableGREASE:        false,
		CipherSuites:        cloneUint16s(defaultCipherSuites),
		Curves:              curvesToUint16s(defaultCurves),
		PointFormats:        cloneUint16s(defaultPointFormats),
		SignatureAlgorithms: sigSchemesToUint16s(defaultSignatureAlgorithms),
		ALPNProtocols:       []string{"http/1.1"},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		KeyShareGroups:      []uint16{29},
		PSKModes:            []uint16{1},
		Extensions:          cloneUint16s(defaultExtensionOrder),
	}
}

func node22Template() *Profile {
	return &Profile{
		Name:                "Claude Code Node.js 22",
		EnableGREASE:        false,
		CipherSuites:        []uint16{4866, 4867, 4865, 49199, 49195, 49200, 49196, 158, 49191, 103, 49192, 107, 163, 159, 52393, 52392, 52394, 49327, 49325, 49315, 49311, 49245, 49249, 49239, 49235, 162, 49326, 49324, 49314, 49310, 49244, 49248, 49238, 49234, 49188, 106, 49187, 64, 49162, 49172, 57, 56, 49161, 49171, 51, 50, 157, 49313, 49309, 49233, 156, 49312, 49308, 49232, 61, 60, 53, 47, 255},
		Curves:              []uint16{29, 23, 30, 25, 24, 256, 257, 258, 259, 260},
		PointFormats:        []uint16{0, 1, 2},
		SignatureAlgorithms: []uint16{0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602},
		ALPNProtocols:       []string{"http/1.1"},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		KeyShareGroups:      []uint16{29},
		PSKModes:            []uint16{1},
		Extensions:          []uint16{0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51},
	}
}

func cloneUint16s(in []uint16) []uint16 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint16, len(in))
	copy(out, in)
	return out
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func curvesToUint16s(in []utls.CurveID) []uint16 {
	out := make([]uint16, len(in))
	for i, v := range in {
		out[i] = uint16(v)
	}
	return out
}

func sigSchemesToUint16s(in []utls.SignatureScheme) []uint16 {
	out := make([]uint16, len(in))
	for i, v := range in {
		out[i] = uint16(v)
	}
	return out
}
