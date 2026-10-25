package gate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/travisennis/cake-safety-judge/internal/protocol"
	"github.com/travisennis/cake-safety-judge/internal/provider"
)

func rawConfig(value string) json.RawMessage {
	return json.RawMessage(value)
}

func offlineInit(config string) protocol.InitFrame {
	return protocol.InitFrame{
		Protocol: protocol.Version,
		Type:     "init",
		ID:       "init",
		Session:  protocol.InitSession{Cwd: "/work/cake"},
		Config:   rawConfig(config),
		Models:   map[string]protocol.ModelDescriptor{},
	}
}

func fakeEngine(t *testing.T, fake *provider.Fake) *Engine {
	t.Helper()
	engine, err := BuildWith(offlineInit(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
		Dependencies{Provider: fake})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return engine
}

func TestBuildDescriptorAndCredential(t *testing.T) {
	t.Setenv("CSJ_TEST_KEY", "secret")
	init := protocol.InitFrame{
		Protocol: protocol.Version,
		Type:     "init",
		ID:       "init",
		Session:  protocol.InitSession{Cwd: "/work/cake"},
		Config:   rawConfig(`{"model":"judge","timeout_secs":5}`),
		Models: map[string]protocol.ModelDescriptor{
			"judge": {
				BaseURL: "https://api.example.test/v1", APIType: "responses",
				Model: "judge-model", APIKeyEnv: "CSJ_TEST_KEY",
			},
		},
	}
	engine, err := BuildWith(init, Dependencies{Provider: &provider.Fake{}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if engine.Descriptor.Model != "judge-model" || engine.Descriptor.APIType != "responses" {
		t.Fatalf("descriptor = %+v", engine.Descriptor)
	}
	if engine.Judge.Timeout != 5*time.Second {
		t.Fatalf("timeout = %v", engine.Judge.Timeout)
	}
}

func TestBuildMissingCredential(t *testing.T) {
	init := protocol.InitFrame{
		Protocol: protocol.Version, Type: "init", ID: "init",
		Session: protocol.InitSession{Cwd: "/work/cake"},
		Models: map[string]protocol.ModelDescriptor{"default": {
			BaseURL: "https://api.example.test/v1", APIType: "chat_completions",
			Model: "judge", APIKeyEnv: "CSJ_DEFINITELY_MISSING_KEY",
		}},
	}
	if _, err := BuildWith(init, Dependencies{Provider: &provider.Fake{}}); err == nil ||
		!strings.Contains(err.Error(), "not set") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildRejectsUnknownConfigKey(t *testing.T) {
	init := offlineInit(`{"timeout_sec":5}`)
	if _, err := BuildWith(init, Dependencies{Provider: &provider.Fake{}}); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildRejectsMissingDescriptor(t *testing.T) {
	init := offlineInit(`{}`)
	if _, err := BuildWith(init, Dependencies{Provider: &provider.Fake{}}); err == nil ||
		!strings.Contains(err.Error(), "no model descriptor") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildLoadsUserRubric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rubric.md")
	if err := os.WriteFile(path, []byte("Prefer dry runs."), 0o600); err != nil {
		t.Fatal(err)
	}
	init := offlineInit(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"},"rubric_file":` +
		string(mustMarshal(path)) + `}`)
	engine, err := BuildWith(init, Dependencies{Provider: &provider.Fake{}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(engine.Judge.Rubric, "User-added rubric guidance") {
		t.Fatalf("rubric = %q", engine.Judge.Rubric)
	}
}

func mustMarshal(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

func checkFrame(id, command string) protocol.CheckFrame {
	return protocol.CheckFrame{
		Protocol: protocol.Version, Type: "check", ID: id,
		Phase: "pre_tool", Action: "bash.exec",
		Input: protocol.BashInput{
			Command: command, Cwd: "/work/cake", ScriptEvidence: []protocol.ScriptEvidence{},
		},
		Options: &protocol.CheckOptions{},
	}
}

func TestEvaluateDecisions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		fake     *provider.Fake
		decision string
		code     string
	}{
		{"allow", &provider.Fake{Decision: "allow"}, "allow", ""},
		{"warn", &provider.Fake{Decision: "warn", Code: "rg-replace-footgun"}, "warn", "rg-replace-footgun"},
		{"block", &provider.Fake{Decision: "block", Code: "unknown-destructive"}, "block", "unknown-destructive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decision, failure := fakeEngine(t, tc.fake).Evaluate(context.Background(), checkFrame("c1", "git status"))
			if failure != nil {
				t.Fatalf("failure: %+v", failure)
			}
			if decision.Decision != tc.decision {
				t.Fatalf("decision = %q", decision.Decision)
			}
			if tc.code == "" {
				if decision.Code != nil {
					t.Fatalf("code = %q", *decision.Code)
				}
			} else if decision.Code == nil || *decision.Code != tc.code {
				t.Fatalf("code = %v", decision.Code)
			}
			found := false
			for _, evidence := range decision.Evidence {
				if evidence.Kind == "attempt" {
					found = true
				}
			}
			if !found {
				t.Fatalf("no attempt evidence: %+v", decision.Evidence)
			}
		})
	}
}

func TestEvaluateFailureMapsClass(t *testing.T) {
	t.Parallel()
	fake := &provider.Fake{Err: &provider.Error{Class: "timeout", Message: "slow"}}
	_, failure := fakeEngine(t, fake).Evaluate(context.Background(), checkFrame("c1", "git status"))
	if failure == nil || failure.Class != "timeout" {
		t.Fatalf("failure = %+v", failure)
	}
	if ExitCodeForClass(failure.Class) != 2 {
		t.Fatalf("exit = %d", ExitCodeForClass(failure.Class))
	}
}

func typesafeServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func typesafeInit(endpoint, mode string) protocol.InitFrame {
	return offlineInit(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"},"typesafe":{"mode":"` +
		mode + `","model":"jev-test","timeout_ms":1000,"endpoint":"` + endpoint + `"}}`)
}

func TestEvaluateTypeSafeCascade(t *testing.T) {
	t.Setenv("TYPESAFE_AI_API_KEY", "key")
	server := typesafeServer(t, `{"model":"jev-test","answers":{"eligible":{"type":"noul","noul":0.91}}}`, http.StatusOK)
	defer server.Close()
	engine, err := BuildWith(typesafeInit(server.URL, "cascade"),
		Dependencies{Provider: &provider.Fake{Decision: "block", Code: "unknown-destructive"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if engine.TypesafeMode != "cascade" {
		t.Fatalf("typesafe mode = %q", engine.TypesafeMode)
	}
	decision, failure := engine.Evaluate(context.Background(), checkFrame("c1", "git status"))
	if failure != nil {
		t.Fatalf("failure: %+v", failure)
	}
	if decision.Decision != "allow" || !decision.ShortCircuit {
		t.Fatalf("decision = %+v", decision)
	}
	if len(decision.Evidence) == 0 || decision.Evidence[0].Kind != "typesafe_observation" {
		t.Fatalf("evidence = %+v", decision.Evidence)
	}
}

func TestEvaluateTypeSafeShadowFallsThrough(t *testing.T) {
	t.Setenv("TYPESAFE_AI_API_KEY", "key")
	server := typesafeServer(t, `{"model":"jev-test","answers":{"eligible":{"type":"noul","noul":0.91}}}`, http.StatusOK)
	defer server.Close()
	engine, err := BuildWith(typesafeInit(server.URL, "shadow"),
		Dependencies{Provider: &provider.Fake{Decision: "block", Code: "unknown-destructive"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	decision, failure := engine.Evaluate(context.Background(), checkFrame("c1", "git status"))
	if failure != nil {
		t.Fatalf("failure: %+v", failure)
	}
	if decision.Decision != "block" {
		t.Fatalf("decision = %+v", decision)
	}
	if len(decision.Evidence) != 2 {
		t.Fatalf("evidence = %+v", decision.Evidence)
	}
}

func TestEvaluateTypeSafeFailureFallsBack(t *testing.T) {
	t.Setenv("TYPESAFE_AI_API_KEY", "key")
	server := typesafeServer(t, "nope", http.StatusInternalServerError)
	defer server.Close()
	engine, err := BuildWith(typesafeInit(server.URL, "cascade"),
		Dependencies{Provider: &provider.Fake{Decision: "allow"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	decision, failure := engine.Evaluate(context.Background(), checkFrame("c1", "git status"))
	if failure != nil {
		t.Fatalf("failure: %+v", failure)
	}
	if decision.Decision != "allow" {
		t.Fatalf("decision = %+v", decision)
	}
	if len(decision.Evidence) != 2 {
		t.Fatalf("evidence = %+v", decision.Evidence)
	}
}

type delayedProvider struct {
	delay map[string]time.Duration
}

func (p *delayedProvider) Complete(_ context.Context, request provider.Request) (provider.Result, error) {
	time.Sleep(p.delay[request.Command])
	return provider.Result{Content: `{"verdict":"allow","message":"ok"}`}, nil
}

func TestServeEndToEndOutOfOrder(t *testing.T) {
	t.Parallel()
	engine, err := BuildWith(offlineInit(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
		Dependencies{Provider: &delayedProvider{delay: map[string]time.Duration{
			"slow": 40 * time.Millisecond,
			"fast": 0,
		}}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var input bytes.Buffer
	input.WriteString(line(protocol.InitFrame{
		Protocol: protocol.Version, Type: "init", ID: "init",
		Session: protocol.InitSession{Cwd: "/work/cake"},
		Config:  rawConfig(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
	}))
	input.WriteString(line(checkFrame("slow", "slow")))
	input.WriteString(line(checkFrame("fast", "fast")))
	input.WriteString(line(protocol.ShutdownFrame{Protocol: protocol.Version, Type: "shutdown", ID: "shutdown"}))

	var output bytes.Buffer
	if err := Serve(&input, &output, nil, func(protocol.InitFrame) (*Engine, error) { return engine, nil }); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readLines(t, output.Bytes())
	if len(frames) != 3 {
		t.Fatalf("frames = %d: %s", len(frames), output.String())
	}
	if frames[0].Type != "ready" {
		t.Fatalf("first frame = %+v", frames[0])
	}
	if frames[1].ID != "fast" || frames[2].ID != "slow" {
		t.Fatalf("order = %+v", frames)
	}
}

type parsedFrame struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Class    string `json:"class"`
}

func line(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw) + "\n"
}

func readLines(t *testing.T, raw []byte) []parsedFrame {
	t.Helper()
	var frames []parsedFrame
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var frame parsedFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			t.Fatalf("output frame: %v (%s)", err, scanner.Text())
		}
		frames = append(frames, frame)
	}
	return frames
}

func TestServeClosedStdinExitsCleanly(t *testing.T) {
	t.Parallel()
	engine, err := BuildWith(offlineInit(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
		Dependencies{Provider: &provider.Fake{}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var input bytes.Buffer
	input.WriteString(line(protocol.InitFrame{
		Protocol: protocol.Version, Type: "init", ID: "init",
		Session: protocol.InitSession{Cwd: "/work/cake"},
		Config:  rawConfig(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
	}))
	var output bytes.Buffer
	if err := Serve(&input, &output, nil, func(protocol.InitFrame) (*Engine, error) { return engine, nil }); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readLines(t, output.Bytes())
	if len(frames) != 1 || frames[0].Type != "ready" {
		t.Fatalf("frames = %+v", frames)
	}
}

func TestServeInitErrorFrame(t *testing.T) {
	t.Parallel()
	init := protocol.InitFrame{
		Protocol: protocol.Version, Type: "init", ID: "init",
		Session: protocol.InitSession{Cwd: "/work/cake"},
	}
	var input bytes.Buffer
	input.WriteString(line(init))
	var output bytes.Buffer
	err := Serve(&input, &output, nil, Build)
	if err != nil {
		t.Fatalf("serve returned %v, want nil after an init error frame", err)
	}
	frames := readLines(t, output.Bytes())
	if len(frames) != 1 || frames[0].Type != "error" || frames[0].Class != "config" {
		t.Fatalf("frames = %+v", frames)
	}
}

func TestServeDuplicateID(t *testing.T) {
	t.Parallel()
	init := protocol.InitFrame{
		Protocol: protocol.Version, Type: "init", ID: "init",
		Session: protocol.InitSession{Cwd: "/work/cake"},
		Config:  rawConfig(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
	}
	var input bytes.Buffer
	input.WriteString(line(init))
	input.WriteString(line(checkFrame("same", "git status")))
	input.WriteString(line(checkFrame("same", "git status")))
	var output bytes.Buffer
	err := Serve(&input, &output, nil, func(protocol.InitFrame) (*Engine, error) {
		return BuildWith(init, Dependencies{Provider: &provider.Fake{}})
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v", err)
	}
}

func TestServeRejectsCakeFrames(t *testing.T) {
	t.Parallel()
	init := protocol.InitFrame{
		Protocol: protocol.Version, Type: "init", ID: "init",
		Session: protocol.InitSession{Cwd: "/work/cake"},
		Config:  rawConfig(`{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}`),
	}
	var input bytes.Buffer
	input.WriteString(line(init))
	input.WriteString(line(protocol.ReadyFrame{
		Protocol: protocol.Version, Type: "ready", ID: "init", Name: "safety", Version: Version,
	}))
	var output bytes.Buffer
	err := Serve(&input, &output, nil, func(protocol.InitFrame) (*Engine, error) {
		return BuildWith(init, Dependencies{Provider: &provider.Fake{}})
	})
	if err == nil || !strings.Contains(err.Error(), "ready") {
		t.Fatalf("error = %v", err)
	}
}

func TestExitCodes(t *testing.T) {
	t.Parallel()
	tests := map[string]int{
		"timeout": 2, "network": 2, "auth": 2, "rate_limit": 2,
		"transport": 1, "malformed": 1, "refusal": 1, "protocol": 1,
		"unsupported": 1, "internal": 1, "config": 3,
	}
	for class, want := range tests {
		if got := ExitCodeForClass(class); got != want {
			t.Fatalf("%s = %d, want %d", class, got, want)
		}
	}
}

func TestConfidenceValidation(t *testing.T) {
	t.Parallel()
	engine := fakeEngine(t, &provider.Fake{Decision: "allow", Confidence: floatPointer(math.NaN())})
	_, failure := engine.Evaluate(context.Background(), checkFrame("c1", "git status"))
	if failure == nil || failure.Class != "internal" {
		t.Fatalf("failure = %+v", failure)
	}
}

func floatPointer(value float64) *float64 {
	return &value
}
