package judge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/travisennis/cake-safety-judge/internal/provider"
)

func TestParseVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		want    Verdict
		wantErr string
	}{
		{
			name:    "allow",
			content: `{"verdict":"allow","message":"Read-only."}`,
			want:    Verdict{Decision: "allow", Message: "Read-only."},
		},
		{
			name:    "block",
			content: `{"verdict":"block","code":"git-force-push","message":"Use --force-with-lease."}`,
			want:    Verdict{Decision: "block", Code: "git-force-push", Message: "Use --force-with-lease."},
		},
		{
			name:    "warn",
			content: `{"verdict":"warn","code":"rg-replace-footgun","message":"Use rg -n."}`,
			want:    Verdict{Decision: "warn", Code: "rg-replace-footgun", Message: "Use rg -n."},
		},
		{
			name:    "json fence",
			content: "```json\n{\"verdict\":\"allow\",\"message\":\"ok\"}\n```",
			want:    Verdict{Decision: "allow", Message: "ok"},
		},
		{
			name:    "bare fence",
			content: "```\n{\"verdict\":\"allow\",\"message\":\"ok\"}\n```",
			want:    Verdict{Decision: "allow", Message: "ok"},
		},
		{
			name:    "allow empty code",
			content: `{"verdict":"allow","code":"","message":"ok"}`,
			want:    Verdict{Decision: "allow", Message: "ok"},
		},
		{"duplicate field", `{"verdict":"allow","verdict":"block","message":"ok"}`, Verdict{}, "duplicate field"},
		{"trailing data", `{"verdict":"allow","message":"ok"} extra`, Verdict{}, "parse"},
		{"missing message", `{"verdict":"allow"}`, Verdict{}, "empty message"},
		{"unknown decision", `{"verdict":"deny","message":"no"}`, Verdict{}, "not block"},
		{"block no code", `{"verdict":"block","message":"no"}`, Verdict{}, "include a verdict code"},
		{"block warn code", `{"verdict":"block","code":"rg-replace-footgun","message":"no"}`, Verdict{}, "warn-class"},
		{"warn block code", `{"verdict":"warn","code":"git-force-push","message":"no"}`, Verdict{}, "warn-class"},
		{"unknown code", `{"verdict":"block","code":"made-up","message":"no"}`, Verdict{}, "known verdict code"},
		{"allow code", `{"verdict":"allow","code":"git-force-push","message":"ok"}`, Verdict{}, "omit"},
		{"confidence high", `{"verdict":"allow","message":"ok","confidence":1.2}`, Verdict{}, "confidence"},
		{"bad fence tag", "```javascript\n{\"verdict\":\"allow\",\"message\":\"ok\"}\n```", Verdict{}, "parse"},
		{"trailing fence text", "```json\n{\"verdict\":\"allow\",\"message\":\"ok\"}\n``` extra", Verdict{}, "parse"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseVerdict(tc.content)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Decision != tc.want.Decision || got.Code != tc.want.Code || got.Message != tc.want.Message {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

type step struct {
	content string
	refusal bool
	err     error
}

type scriptedProvider struct {
	steps []step
	calls int
}

func (s *scriptedProvider) Complete(context.Context, provider.Request) (provider.Result, error) {
	if s.calls >= len(s.steps) {
		return provider.Result{}, errors.New("script exhausted")
	}
	current := s.steps[s.calls]
	s.calls++
	return provider.Result{Content: current.content, Refusal: current.refusal}, current.err
}

func testClient(providerImpl provider.Provider) *Client {
	client := New(providerImpl, provider.Descriptor{Model: "judge", APIType: "chat_completions"},
		time.Second, time.Second)
	client.Sleep = func(time.Duration) {}
	return client
}

func TestEvaluateSuccess(t *testing.T) {
	t.Parallel()
	p := &scriptedProvider{steps: []step{{content: `{"verdict":"allow","message":"ok"}`}}}
	verdict, attempts, err := testClient(p).Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Decision != "allow" || p.calls != 1 || len(attempts) != 1 {
		t.Fatalf("verdict=%+v calls=%d attempts=%d", verdict, p.calls, len(attempts))
	}
	if attempts[0].TerminalClass != "verdict" {
		t.Fatalf("terminal class = %q", attempts[0].TerminalClass)
	}
}

func TestEvaluateRetriesOnce(t *testing.T) {
	t.Parallel()
	p := &scriptedProvider{steps: []step{
		{err: &provider.Error{Class: "transport", Message: "503", Retryable: true, Status: 503}},
		{content: `{"verdict":"allow","message":"ok"}`},
	}}
	_, attempts, err := testClient(p).Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.calls != 2 || len(attempts) != 2 {
		t.Fatalf("calls=%d attempts=%d", p.calls, len(attempts))
	}
	if attempts[0].TerminalClass != "transport" || attempts[1].RetryDelay <= 0 {
		t.Fatalf("attempts = %+v", attempts)
	}
}

func TestEvaluateDoesNotRetryNonRetryable(t *testing.T) {
	t.Parallel()
	for _, class := range []string{"auth", "malformed", "refusal"} {
		t.Run(class, func(t *testing.T) {
			t.Parallel()
			p := &scriptedProvider{steps: []step{
				{err: &provider.Error{Class: class, Message: class}},
				{content: `{"verdict":"allow","message":"ok"}`},
			}}
			_, _, err := testClient(p).Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
			var failure *Failure
			if !errors.As(err, &failure) || failure.Class != class {
				t.Fatalf("want %s failure, got %v", class, err)
			}
			if p.calls != 1 {
				t.Fatalf("calls = %d, want 1", p.calls)
			}
		})
	}
}

func TestEvaluateDoesNotRetryMalformedVerdict(t *testing.T) {
	t.Parallel()
	p := &scriptedProvider{steps: []step{
		{content: `{"verdict":"allow"} trailing`},
		{content: `{"verdict":"allow","message":"ok"}`},
	}}
	_, _, err := testClient(p).Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != "malformed" {
		t.Fatalf("want malformed, got %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("calls = %d, want 1", p.calls)
	}
}

func TestEvaluateDoesNotRetryRefusal(t *testing.T) {
	t.Parallel()
	p := &scriptedProvider{steps: []step{
		{refusal: true},
		{content: `{"verdict":"allow","message":"ok"}`},
	}}
	_, attempts, err := testClient(p).Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != "refusal" {
		t.Fatalf("want refusal, got %v", err)
	}
	if p.calls != 1 || len(attempts) != 1 || attempts[0].TerminalClass != "refusal" {
		t.Fatalf("calls=%d attempts=%+v", p.calls, attempts)
	}
}

func TestEvaluateZeroBudgetDoesNotRetry(t *testing.T) {
	t.Parallel()
	p := &scriptedProvider{steps: []step{
		{err: &provider.Error{Class: "timeout", Message: "slow", Retryable: true}},
		{content: `{"verdict":"allow","message":"ok"}`},
	}}
	client := New(p, provider.Descriptor{Model: "judge", APIType: "chat_completions"}, time.Second, 0)
	client.Sleep = func(time.Duration) {}
	_, _, err := client.Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != "timeout" {
		t.Fatalf("want timeout, got %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("calls = %d, want 1", p.calls)
	}
}

func TestEvaluateExhaustsRecovery(t *testing.T) {
	t.Parallel()
	p := &scriptedProvider{steps: []step{
		{err: &provider.Error{Class: "timeout", Message: "first", Retryable: true}},
		{err: &provider.Error{Class: "timeout", Message: "second", Retryable: true}},
	}}
	_, attempts, err := testClient(p).Evaluate(context.Background(), Request{Command: "git status", Cwd: "/work"})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != "timeout" {
		t.Fatalf("want timeout, got %v", err)
	}
	if p.calls != 2 || len(attempts) != 2 {
		t.Fatalf("calls=%d attempts=%d", p.calls, len(attempts))
	}
}

func TestPrompts(t *testing.T) {
	t.Parallel()
	client := New(&scriptedProvider{}, provider.Descriptor{Model: "judge"}, time.Second, time.Second)
	client.Rubric = "RUBRIC"

	system, user := client.prompts(Request{Command: "cat <file>", Cwd: "/work"})
	if system != "RUBRIC" {
		t.Fatalf("system = %q", system)
	}
	if !strings.Contains(user, `"script_evidence":null`) {
		t.Fatalf("missing null evidence: %s", user)
	}
	if !strings.Contains(user, "No referenced files inspected") {
		t.Fatalf("missing no-evidence scope: %s", user)
	}
	if !strings.Contains(user, `"command":"cat <file>"`) {
		t.Fatalf("HTML escaped or command missing: %s", user)
	}

	_, user = client.prompts(Request{
		Command:        "bash run.sh",
		Cwd:            "/work",
		ScriptEvidence: []ScriptEvidence{{Path: "run.sh", Contents: "rm -rf /"}},
	})
	if !strings.Contains(user, `"script_evidence":{"path":"run.sh","contents":"rm -rf /"}`) {
		t.Fatalf("missing script evidence: %s", user)
	}
	if !strings.Contains(user, "One directly referenced file observed") {
		t.Fatalf("missing evidence scope: %s", user)
	}
}
