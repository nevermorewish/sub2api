package tlsfingerprint

import (
	"reflect"
	"testing"
)

func TestGenerateProfileTemplateNode24(t *testing.T) {
	generated := GenerateProfileTemplate(GenerateOptions{
		Runtime:        "node",
		RuntimeVersion: "v24.3.0",
		Transport:      "fetch",
	})

	if generated.Profile == nil {
		t.Fatal("expected generated profile")
	}
	if generated.Profile.Name != "Claude Code Node.js 24 fetch" {
		t.Fatalf("name = %q, want generated Node 24 name", generated.Profile.Name)
	}
	if !reflect.DeepEqual(generated.Profile.Extensions, defaultExtensionOrder) {
		t.Fatalf("extensions = %v, want %v", generated.Profile.Extensions, defaultExtensionOrder)
	}
	wantExtensions := []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 21}
	if !reflect.DeepEqual(generated.Profile.Extensions, wantExtensions) {
		t.Fatalf("extensions = %v, want captured Claude Code order %v", generated.Profile.Extensions, wantExtensions)
	}
	if !reflect.DeepEqual(generated.Profile.ALPNProtocols, []string{"http/1.1"}) {
		t.Fatalf("alpn = %v, want [http/1.1]", generated.Profile.ALPNProtocols)
	}
	if generated.Profile.EnableGREASE {
		t.Fatal("Node template should keep GREASE disabled unless requested")
	}
	if len(generated.Notes) == 0 {
		t.Fatal("expected generation notes")
	}
}

func TestGenerateProfileTemplateNode22(t *testing.T) {
	generated := GenerateProfileTemplate(GenerateOptions{
		Runtime:   "node",
		NodeMajor: 22,
	})

	if generated.Profile == nil {
		t.Fatal("expected generated profile")
	}
	if generated.Profile.Name != "Claude Code Node.js 22 fetch" {
		t.Fatalf("name = %q, want generated Node 22 name", generated.Profile.Name)
	}
	if len(generated.Profile.CipherSuites) < 50 {
		t.Fatalf("cipher suites = %d entries, want Node 22 compatibility list", len(generated.Profile.CipherSuites))
	}
	wantExtensions := []uint16{0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51}
	if !reflect.DeepEqual(generated.Profile.Extensions, wantExtensions) {
		t.Fatalf("extensions = %v, want %v", generated.Profile.Extensions, wantExtensions)
	}
}

func TestGenerateProfileTemplateOverrides(t *testing.T) {
	enableGREASE := true
	generated := GenerateProfileTemplate(GenerateOptions{
		Name:          "custom",
		Runtime:       "node",
		NodeMajor:     24,
		Transport:     "h2",
		ALPNProtocols: []string{"h2"},
		EnableGREASE:  &enableGREASE,
	})

	if generated.Profile.Name != "custom" {
		t.Fatalf("name = %q, want custom", generated.Profile.Name)
	}
	if !generated.Profile.EnableGREASE {
		t.Fatal("expected GREASE override to enable GREASE")
	}
	if !reflect.DeepEqual(generated.Profile.ALPNProtocols, []string{"h2"}) {
		t.Fatalf("alpn = %v, want [h2]", generated.Profile.ALPNProtocols)
	}
}
