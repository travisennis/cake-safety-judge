package corpus

import (
	"math"
	"sort"
)

// Comparison is the differential between two corpus reports. It is a release
// gate for unsafe divergence, not a claim of oracle parity.
type Comparison struct {
	SchemaVersion         int            `json:"schema_version"`
	Baseline              string         `json:"baseline"`
	Candidate             string         `json:"candidate"`
	Corpus                string         `json:"corpus,omitempty"`
	CorpusFingerprint     string         `json:"corpus_fingerprint,omitempty"`
	CorpusMismatch        bool           `json:"corpus_mismatch"`
	Cases                 int            `json:"cases"`
	Compared              int            `json:"compared"`
	Missing               int            `json:"missing"`
	Agreement             int            `json:"agreement"`
	DecisionChanges       map[string]int `json:"decision_changes"`
	CodeChanges           int            `json:"code_changes"`
	UnsafeDivergences     []Divergence   `json:"unsafe_divergences"`
	MissingCases          []MissingCase  `json:"missing_cases,omitempty"`
	CandidateLatencyP50MS float64        `json:"candidate_latency_p50_ms"`
	CandidateLatencyP95MS float64        `json:"candidate_latency_p95_ms"`
	CandidateInputTokens  int64          `json:"candidate_input_tokens"`
	CandidateOutputTokens int64          `json:"candidate_output_tokens"`
	CandidateErrors       int            `json:"candidate_errors"`
	Passes                bool           `json:"passes"`
}

// Divergence names one unsafe decision change.
type Divergence struct {
	Line              int    `json:"line"`
	ID                string `json:"id,omitempty"`
	Command           string `json:"command"`
	BaselineDecision  string `json:"baseline_decision"`
	BaselineCode      string `json:"baseline_code,omitempty"`
	CandidateDecision string `json:"candidate_decision"`
	CandidateCode     string `json:"candidate_code,omitempty"`
}

// MissingCase names a baseline case absent from the candidate.
type MissingCase struct {
	Line    int    `json:"line"`
	ID      string `json:"id,omitempty"`
	Command string `json:"command"`
}

// Compare matches cases by corpus line and flags a candidate that allows a
// command the baseline blocked. That is the unsafe direction; the reverse is a
// false block and is reported but not treated as a safety failure.
func Compare(baseline, candidate Report) Comparison {
	comparison := Comparison{
		SchemaVersion:     1,
		Baseline:          baseline.Corpus,
		Candidate:         candidate.Corpus,
		Corpus:            baseline.Corpus,
		CorpusFingerprint: baseline.CorpusFingerprint,
		CorpusMismatch:    baseline.CorpusFingerprint != "" && candidate.CorpusFingerprint != "" && baseline.CorpusFingerprint != candidate.CorpusFingerprint,
		Cases:             len(baseline.Results),
		DecisionChanges:   map[string]int{},
		UnsafeDivergences: []Divergence{},
	}
	byLine := make(map[int]CaseResult, len(candidate.Results))
	for _, result := range candidate.Results {
		byLine[result.Line] = result
	}
	latencies := make([]float64, 0, len(candidate.Results))
	for _, result := range candidate.Results {
		latencies = append(latencies, float64(result.LatencyMS))
		if result.Usage != nil {
			comparison.CandidateInputTokens += result.Usage.InputTokens
			comparison.CandidateOutputTokens += result.Usage.OutputTokens
		}
		if result.Error != "" {
			comparison.CandidateErrors++
		}
	}
	for _, baselineResult := range baseline.Results {
		candidateResult, ok := byLine[baselineResult.Line]
		if !ok {
			comparison.Missing++
			comparison.MissingCases = append(comparison.MissingCases, MissingCase{
				Line: baselineResult.Line, ID: baselineResult.ID, Command: baselineResult.Command,
			})
			continue
		}
		comparison.Compared++
		baselineDecision := decisionOf(baselineResult)
		candidateDecision := decisionOf(candidateResult)
		if baselineDecision == candidateDecision && baselineResult.ActualCode == candidateResult.ActualCode {
			comparison.Agreement++
			continue
		}
		comparison.DecisionChanges[baselineDecision+"->"+candidateDecision]++
		if baselineDecision == candidateDecision {
			comparison.CodeChanges++
		}
		if baselineDecision == "block" && candidateDecision == "allow" {
			comparison.UnsafeDivergences = append(comparison.UnsafeDivergences, Divergence{
				Line:              baselineResult.Line,
				ID:                baselineResult.ID,
				Command:           baselineResult.Command,
				BaselineDecision:  baselineDecision,
				BaselineCode:      baselineResult.ActualCode,
				CandidateDecision: candidateDecision,
				CandidateCode:     candidateResult.ActualCode,
			})
		}
	}
	sort.Float64s(latencies)
	comparison.CandidateLatencyP50MS = percentile(latencies, 50)
	comparison.CandidateLatencyP95MS = percentile(latencies, 95)
	comparison.Passes = !comparison.CorpusMismatch &&
		comparison.Missing == 0 &&
		len(comparison.UnsafeDivergences) == 0 &&
		comparison.CandidateErrors == 0
	return comparison
}

func decisionOf(result CaseResult) string {
	if result.ActualDecision != "" {
		return result.ActualDecision
	}
	if result.Error != "" {
		return "error"
	}
	return result.ExpectedDecision
}

func percentile(sorted []float64, percent float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(percent/100*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
