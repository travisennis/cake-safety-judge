package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/travisennis/cake-safety-judge/internal/protocol"
)

func runCLI(t *testing.T, args []string, stdin io.Reader) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, stdin, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runCLI(t, []string{"describe"}, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var describe protocol.Describe
	if err := json.Unmarshal([]byte(stdout), &describe); err != nil {
		t.Fatalf("describe: %v", err)
	}
	if err := describe.Validate(); err != nil {
		t.Fatalf("describe: %v", err)
	}
}

func TestCheckFakeBlock(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runCLI(t, []string{
		"check", "--json", "--fake", "--fake-verdict", "block",
		"--fake-code", "unknown-destructive", "--", "find . -delete",
	}, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var decision protocol.DecisionFrame
	if err := json.Unmarshal([]byte(stdout), &decision); err != nil {
		t.Fatalf("decision: %v", err)
	}
	if decision.Decision != "block" || decision.Code == nil || *decision.Code != "unknown-destructive" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestCheckFakeMalformedCode(t *testing.T) {
	t.Parallel()
	code, stdout, _ := runCLI(t, []string{
		"check", "--json", "--fake", "--fake-verdict", "block", "--fake-code", "made-up", "--", "rm -rf /",
	}, nil)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	var failure protocol.ErrorFrame
	if err := json.Unmarshal([]byte(stdout), &failure); err != nil {
		t.Fatalf("error frame: %v", err)
	}
	if failure.Class != "malformed" {
		t.Fatalf("class = %q", failure.Class)
	}
}

func TestCheckRequiresConfiguration(t *testing.T) {
	t.Parallel()
	code, _, stderr := runCLI(t, []string{"check", "--", "git status"}, nil)
	if code != 3 || !strings.Contains(stderr, "requires") {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
}

func TestCheckLiveAuthFailure(t *testing.T) {
	t.Setenv("CSJ_CLI_KEY", "secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	code, stdout, _ := runCLI(t, []string{
		"check", "--json", "--base-url", server.URL, "--api-type", "chat_completions",
		"--model-name", "judge-model", "--api-key-env", "CSJ_CLI_KEY", "--", "git status",
	}, nil)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	var failure protocol.ErrorFrame
	if err := json.Unmarshal([]byte(stdout), &failure); err != nil {
		t.Fatalf("error: %v", err)
	}
	if failure.Class != "auth" {
		t.Fatalf("class = %q", failure.Class)
	}
}

func TestCheckLiveTransportFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	code, _, _ := runCLI(t, []string{
		"check", "--json", "--base-url", server.URL, "--model-name", "judge-model",
		"--retry-budget", "0s", "--", "git status",
	}, nil)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestCorpusCommand(t *testing.T) {
	t.Parallel()
	report := filepath.Join(t.TempDir(), "report.json")
	code, _, stderr := runCLI(t, []string{
		"corpus", "--corpus", filepath.Join("..", "..", "corpus", "commands.jsonl"),
		"--provider", "fake", "--report", report,
	}, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Passes bool `json:"passes"`
		Cases  int  `json:"cases"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Passes || parsed.Cases != 210 {
		t.Fatalf("report = %+v", parsed)
	}
}

func TestCorpusMissingFile(t *testing.T) {
	t.Parallel()
	code, _, _ := runCLI(t, []string{"corpus", "--corpus", "does-not-exist.jsonl"}, nil)
	if code != 2 {
		t.Fatalf("code = %d", code)
	}
}

func TestServeReadyThenShutdown(t *testing.T) {
	t.Parallel()
	init := `{"protocol":"cake-gate/1","type":"init","id":"init","session":{"cwd":"/work/cake"},"config":{"endpoint":{"base_url":"offline://fake","api_type":"chat_completions","model":"offline"}}}` + "\n"
	shutdown := `{"protocol":"cake-gate/1","type":"shutdown","id":"shutdown"}` + "\n"
	code, stdout, stderr := runCLI(t, []string{"serve"}, strings.NewReader(init+shutdown))
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, `"type":"ready"`) {
		t.Fatalf("stdout = %s", stdout)
	}
}

func TestVersionAndUsage(t *testing.T) {
	t.Parallel()
	if code, stdout, _ := runCLI(t, []string{"version"}, nil); code != 0 ||
		!strings.Contains(stdout, "cake-safety-judge 0.1.0") {
		t.Fatalf("version: %d %s", code, stdout)
	}
	if code, _, _ := runCLI(t, []string{"nope"}, nil); code != 2 {
		t.Fatalf("unknown subcommand code = %d", code)
	}
}
