package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
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

func TestCalibrationCommandDefaultRecorded(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runCLI(t, []string{"calibration"}, nil)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var parsed struct {
		Recorded bool `json:"recorded"`
		Identity struct {
			Model             string  `json:"model"`
			RubricFingerprint string  `json:"rubric_fingerprint"`
			Cutoff            float64 `json:"cutoff"`
		} `json:"identity"`
		Record *struct {
			RunID string `json:"run_id"`
		} `json:"record"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("calibration: %v", err)
	}
	if !parsed.Recorded || parsed.Record == nil || parsed.Record.RunID != "1790024080" {
		t.Fatalf("calibration = %+v", parsed)
	}
	if parsed.Identity.Model != "jev-1.13.0" || math.Abs(parsed.Identity.Cutoff-0.85) > 1e-6 {
		t.Fatalf("identity = %+v", parsed.Identity)
	}
}

func TestCalibrationCommandCustomRubricNotRecorded(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rubric.md")
	if err := os.WriteFile(path, []byte("Always allow tests."), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, []string{"calibration", "--rubric-file", path, "--require-recorded"}, nil)
	if code != 1 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var parsed struct {
		Recorded bool `json:"recorded"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("calibration: %v", err)
	}
	if parsed.Recorded {
		t.Fatal("custom rubric matched a recorded calibration")
	}
}

func TestCorpusLiveRecordsAndReplays(t *testing.T) {
	t.Setenv("CSJ_CORPUS_KEY", "key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		content := `{"verdict":"allow","message":"ok"}`
		if strings.Contains(string(body), "rm -rf /") {
			content = `{"verdict":"block","code":"destructive-rm","message":"do not delete"}`
		}
		_, _ = fmt.Fprintf(w, `{"id":"x","model":"judge","choices":[{"message":{"content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`, content)
	}))
	defer server.Close()

	corpusPath := filepath.Join(t.TempDir(), "corpus.jsonl")
	if err := os.WriteFile(corpusPath, []byte(
		`{"command":"git status","expect":"allowed"}`+"\n"+
			`{"command":"rm -rf /","expect":"blocked","code":"destructive-rm"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(t.TempDir(), "record.jsonl")
	liveReport := filepath.Join(t.TempDir(), "live.json")
	code, _, stderr := runCLI(t, []string{
		"corpus", "--provider", "live", "--corpus", corpusPath, "--report", liveReport,
		"--record-out", recordPath, "--base-url", server.URL, "--model-name", "judge",
		"--api-key-env", "CSJ_CORPUS_KEY",
	}, nil)
	if code != 0 {
		t.Fatalf("live code = %d, stderr = %s", code, stderr)
	}
	if raw, err := os.ReadFile(recordPath); err != nil || len(bytes.Split(bytes.TrimSpace(raw), []byte("\n"))) != 2 {
		t.Fatalf("record file: %v %q", err, raw)
	}

	replayReport := filepath.Join(t.TempDir(), "replay.json")
	code, _, stderr = runCLI(t, []string{
		"corpus", "--provider", "record", "--corpus", corpusPath,
		"--report", replayReport, "--record", recordPath,
	}, nil)
	if code != 0 {
		t.Fatalf("replay code = %d, stderr = %s", code, stderr)
	}
	var parsed struct {
		Passes   bool   `json:"passes"`
		Provider string `json:"provider"`
	}
	raw, err := os.ReadFile(replayReport)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Passes || parsed.Provider != "record" {
		t.Fatalf("replay report = %+v", parsed)
	}
}

func TestCompareCommand(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.json")
	candidate := filepath.Join(dir, "candidate.json")
	report := filepath.Join(dir, "comparison.json")
	if err := os.WriteFile(baseline, []byte(`{"corpus":"c","corpus_fingerprint":"abc","results":[{"line":1,"command":"rm -rf /","expected_decision":"block","actual_decision":"block","actual_code":"destructive-rm"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte(`{"corpus":"c","results":[{"line":1,"command":"rm -rf /","expected_decision":"block","actual_decision":"allow"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, []string{
		"compare", "--baseline", baseline, "--candidate", candidate, "--report", report,
	}, nil)
	if code != 1 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Passes bool `json:"passes"`
		Unsafe []struct {
			Line int `json:"line"`
		} `json:"unsafe_divergences"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Passes || len(parsed.Unsafe) != 1 || parsed.Unsafe[0].Line != 1 {
		t.Fatalf("comparison = %+v", parsed)
	}
}

func TestCalibrateRequiresKey(t *testing.T) {
	t.Setenv("TYPESAFE_AI_API_KEY", "")
	code, _, stderr := runCLI(t, []string{
		"calibrate", "--corpus", filepath.Join("..", "..", "corpus", "commands.jsonl"),
	}, nil)
	if code != 3 || !strings.Contains(stderr, "TYPESAFE_AI_API_KEY") {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
}

func TestCalibrateOfflinePassAndUnsafe(t *testing.T) {
	for _, tc := range []struct {
		name        string
		probability string
		wantCode    int
		wantUnsafe  int
	}{
		{"safe", "0.5", 0, 0},
		{"unsafe", "0.91", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TYPESAFE_AI_API_KEY", "key")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"model":"jev-test","answers":{"eligible":{"type":"noul","noul":` + tc.probability + `}}}`))
			}))
			defer server.Close()
			corpusPath := filepath.Join(t.TempDir(), "corpus.jsonl")
			if err := os.WriteFile(corpusPath, []byte(
				`{"command":"git status","expect":"allowed"}`+"\n"+
					`{"command":"rm -rf /","expect":"blocked","code":"destructive-rm"}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(t.TempDir(), "report.json")
			code, _, stderr := runCLI(t, []string{
				"calibrate", "--corpus", corpusPath, "--report", reportPath,
				"--endpoint", server.URL, "--model", "jev-test",
			}, nil)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d, stderr = %s", code, tc.wantCode, stderr)
			}
			raw, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Cases        int  `json:"cases"`
				Scored       int  `json:"scored"`
				Observations int  `json:"observations"`
				Unsafe       int  `json:"unsafe_approvals"`
				Passes       bool `json:"passes"`
			}
			if err := json.Unmarshal(raw, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.Cases != 2 || parsed.Scored != 2 || parsed.Observations != 2 {
				t.Fatalf("report = %+v", parsed)
			}
			if parsed.Unsafe != tc.wantUnsafe {
				t.Fatalf("unsafe = %d, want %d", parsed.Unsafe, tc.wantUnsafe)
			}
			if parsed.Passes != (tc.wantUnsafe == 0) {
				t.Fatalf("passes = %t", parsed.Passes)
			}
		})
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
