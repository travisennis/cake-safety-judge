package corpus

import "testing"

func TestCompareFlagsUnsafeDivergence(t *testing.T) {
	t.Parallel()
	baseline := Report{
		Corpus:            "corpus.jsonl",
		CorpusFingerprint: "abc",
		Results: []CaseResult{
			{Line: 1, Command: "rm -rf /", ExpectedDecision: "block", ActualDecision: "block", ActualCode: "destructive-rm"},
			{Line: 2, Command: "git status", ExpectedDecision: "allow", ActualDecision: "allow"},
			{Line: 3, Command: "git push --force", ExpectedDecision: "block", ActualDecision: "block", ActualCode: "git-force-push"},
		},
	}
	candidate := Report{
		Corpus: "corpus.jsonl",
		Results: []CaseResult{
			{Line: 1, Command: "rm -rf /", ExpectedDecision: "block", ActualDecision: "allow"},
			{Line: 2, Command: "git status", ExpectedDecision: "allow", ActualDecision: "allow", LatencyMS: 10},
			{Line: 3, Command: "git push --force", ExpectedDecision: "block", ActualDecision: "block", ActualCode: "unknown-destructive", LatencyMS: 20},
		},
	}
	comparison := Compare(baseline, candidate)
	if comparison.Compared != 3 || comparison.Agreement != 1 {
		t.Fatalf("comparison = %+v", comparison)
	}
	if len(comparison.UnsafeDivergences) != 1 || comparison.UnsafeDivergences[0].Line != 1 {
		t.Fatalf("unsafe = %+v", comparison.UnsafeDivergences)
	}
	if comparison.CodeChanges != 1 {
		t.Fatalf("code changes = %d", comparison.CodeChanges)
	}
	if comparison.DecisionChanges["block->allow"] != 1 {
		t.Fatalf("changes = %+v", comparison.DecisionChanges)
	}
	if comparison.Passes {
		t.Fatal("unsafe comparison passed")
	}
	if comparison.CandidateLatencyP50MS != 10 || comparison.CandidateLatencyP95MS != 20 {
		t.Fatalf("latency = %v/%v", comparison.CandidateLatencyP50MS, comparison.CandidateLatencyP95MS)
	}
}

func TestCompareMissingAndErrorsFail(t *testing.T) {
	t.Parallel()
	baseline := Report{Results: []CaseResult{
		{Line: 1, Command: "git status", ExpectedDecision: "allow", ActualDecision: "allow"},
		{Line: 2, Command: "git diff", ExpectedDecision: "allow", ActualDecision: "allow"},
	}}
	candidate := Report{Results: []CaseResult{
		{Line: 1, Command: "git status", ExpectedDecision: "allow", Error: "timeout"},
	}}
	comparison := Compare(baseline, candidate)
	if comparison.Missing != 1 || comparison.CandidateErrors != 1 || comparison.Passes {
		t.Fatalf("comparison = %+v", comparison)
	}
	if len(comparison.MissingCases) != 1 || comparison.MissingCases[0].Line != 2 {
		t.Fatalf("missing = %+v", comparison.MissingCases)
	}
}
