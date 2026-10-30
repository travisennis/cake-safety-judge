package gate

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/travisennis/cake-safety-judge/internal/protocol"
	"github.com/travisennis/cake-safety-judge/internal/provider"
)

func TestDiagnosticRedactsSecretsAndControls(t *testing.T) {
	t.Parallel()
	engine := fakeEngine(t, &provider.Fake{Decision: "allow"})
	engine.Judge.APIKey = "sk-live-supersecret"
	var log bytes.Buffer
	engine.SetDiagnosticWriter(&log)

	check := protocol.CheckFrame{
		Protocol: protocol.Version,
		Type:     "check",
		ID:       "check",
		Phase:    "pre_tool",
		Action:   "bash.exec",
		Input: protocol.BashInput{
			Command:        "echo ghp_abcdefghijklmnopqrstuvwxyz0123456789 \x1b[31m",
			Cwd:            "/work",
			ScriptEvidence: []protocol.ScriptEvidence{},
		},
		Options: &protocol.CheckOptions{Diagnostic: true},
	}
	if _, failure := engine.Evaluate(context.Background(), check); failure != nil {
		t.Fatalf("evaluate: %+v", failure)
	}
	out := log.String()
	for _, secret := range []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789", "sk-live-supersecret"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret %q leaked into diagnostics: %s", secret, out)
		}
	}
	if strings.ContainsRune(out, '\x1b') {
		t.Fatalf("control byte leaked into diagnostics: %q", out)
	}
	if !strings.Contains(out, "[REDACTED") {
		t.Fatalf("missing redaction marker: %s", out)
	}
}

func TestErrorFrameRedactsProviderMessage(t *testing.T) {
	t.Parallel()
	engine := fakeEngine(t, &provider.Fake{Err: &provider.Error{
		Class:   "transport",
		Message: "upstream failed for ghp_abcdefghijklmnopqrstuvwxyz0123456789 and sk-live-supersecret",
	}})
	engine.Judge.APIKey = "sk-live-supersecret"
	check := protocol.CheckFrame{
		Protocol: protocol.Version,
		Type:     "check",
		ID:       "check",
		Phase:    "pre_tool",
		Action:   "bash.exec",
		Input: protocol.BashInput{
			Command:        "git status",
			Cwd:            "/work",
			ScriptEvidence: []protocol.ScriptEvidence{},
		},
		Options: &protocol.CheckOptions{},
	}
	_, failure := engine.Evaluate(context.Background(), check)
	if failure == nil {
		t.Fatal("want error frame")
	}
	for _, secret := range []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789", "sk-live-supersecret"} {
		if strings.Contains(failure.Message, secret) {
			t.Fatalf("secret %q leaked into error frame: %s", secret, failure.Message)
		}
	}
	if !strings.Contains(failure.Message, "[REDACTED") {
		t.Fatalf("missing redaction marker: %s", failure.Message)
	}
}

func TestOversizedPacketFailsClosedWithoutProviderCall(t *testing.T) {
	t.Parallel()
	fake := &countingProvider{}
	engine := fakeEngine(t, nil)
	engine.Judge.Provider = fake
	check := protocol.CheckFrame{
		Protocol: protocol.Version,
		Type:     "check",
		ID:       "check",
		Phase:    "pre_tool",
		Action:   "bash.exec",
		Input: protocol.BashInput{
			Command:        strings.Repeat("a", 40<<10),
			Cwd:            "/work",
			ScriptEvidence: []protocol.ScriptEvidence{},
		},
		Options: &protocol.CheckOptions{},
	}
	_, failure := engine.Evaluate(context.Background(), check)
	if failure == nil || failure.Class != "unsupported" {
		t.Fatalf("want unsupported error, got %+v", failure)
	}
	if fake.calls != 0 {
		t.Fatalf("provider calls = %d, want 0", fake.calls)
	}
}

type countingProvider struct {
	calls int
}

func (p *countingProvider) Complete(context.Context, provider.Request) (provider.Result, error) {
	p.calls++
	return provider.Result{Content: `{"verdict":"allow","message":"ok"}`}, nil
}
