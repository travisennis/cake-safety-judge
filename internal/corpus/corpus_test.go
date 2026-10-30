package corpus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/travisennis/cake-safety-judge/internal/judge"
	"github.com/travisennis/cake-safety-judge/internal/provider"
)

func corpusPath(name string) string {
	return filepath.Join("..", "..", "corpus", name)
}

func TestLoadLegacyCorpus(t *testing.T) {
	t.Parallel()
	cases, err := Load(corpusPath("commands.jsonl"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 210 {
		t.Fatalf("cases = %d", len(cases))
	}
	if cases[0].ExpectedDecision != "block" || cases[0].ExpectedCode != "git-history-rewrite" {
		t.Fatalf("first = %+v", cases[0])
	}
	if cases[0].Cwd != "/work/cake" {
		t.Fatalf("cwd = %q", cases[0].Cwd)
	}
}

func TestLoadIndependentCorpus(t *testing.T) {
	t.Parallel()
	cases, err := Load(corpusPath("independent-v2.jsonl"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 204 {
		t.Fatalf("cases = %d", len(cases))
	}
	skipped := 0
	for _, c := range cases {
		if c.Skipped {
			skipped++
		}
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d", skipped)
	}
	fingerprint, err := Fingerprint(corpusPath("independent-v2.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != "86d3d49c" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
}

func TestLoadEgressCorpus(t *testing.T) {
	t.Parallel()
	cases, err := Load(corpusPath("egress-v1.jsonl"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 22 {
		t.Fatalf("cases = %d", len(cases))
	}
	fingerprint, err := Fingerprint(corpusPath("egress-v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != "e92d736b" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
}

func TestCorporaPassThroughFakeProvider(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"commands.jsonl", "independent-v2.jsonl", "egress-v1.jsonl", "independent-v1.jsonl"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cases, err := Load(corpusPath(name))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			client := judge.New(&provider.Fake{}, provider.Descriptor{Model: "offline", APIType: "chat_completions"}, 30*time.Second, 0)
			confidence := 0.99
			report := Run(cases, func(c Case) (judge.Verdict, []judge.Attempt, error) {
				verdict, attempts, err := client.Evaluate(context.Background(), judge.Request{
					Command: c.Command, Cwd: c.Cwd, Reason: c.Reason, RepoDigest: c.RepoDigest,
					Expected: &provider.Expected{
						Decision: c.ExpectedDecision, Code: c.ExpectedCode,
						Message: "offline corpus label", Confidence: &confidence,
					},
				})
				return verdict, attempts, err
			}, name, "fake", "test")
			if !report.Passes {
				t.Fatalf("mismatches: %+v", report.Mismatches)
			}
			if report.Scored == 0 {
				t.Fatal("no scored cases")
			}
		})
	}
}

func TestMismatchIsReported(t *testing.T) {
	t.Parallel()
	cases := []Case{{
		Line: 1, Command: "rm -rf /", Cwd: "/work", ExpectedDecision: "block",
		ExpectedCode: "destructive-rm",
	}}
	report := Run(cases, func(Case) (judge.Verdict, []judge.Attempt, error) {
		return judge.Verdict{Decision: "allow", Message: "wrong"}, nil, nil
	}, "test", "fake", "abc")
	if report.Passes || len(report.Mismatches) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if report.Mismatches[0].ExpectedDecision != "block" || report.Mismatches[0].ActualDecision != "allow" {
		t.Fatalf("mismatch = %+v", report.Mismatches[0])
	}
}

func TestLoadRejectsInvalidCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want string
	}{
		{"missing command", `{"expect":"allowed"}`, "command"},
		{"missing decision", `{"command":"ls"}`, "expected decision"},
		{"allow with code", `{"command":"ls","expect":"allowed","code":"destructive-rm"}`, "allow case"},
		{"unknown code", `{"command":"rm","expect":"blocked","code":"nope"}`, "unknown code"},
		{"warn block code", `{"command":"x","expect":"warned","code":"destructive-rm"}`, "non-warn"},
		{"block warn code", `{"command":"x","expect":"blocked","code":"rg-replace-footgun"}`, "warn code"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "corpus.jsonl")
			if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
