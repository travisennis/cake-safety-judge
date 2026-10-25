package corpus

// Report is the machine-readable corpus result.
type Report struct {
	SchemaVersion      int                 `json:"schema_version"`
	Corpus             string              `json:"corpus"`
	CorpusFingerprint  string              `json:"corpus_fingerprint"`
	Provider           string              `json:"provider"`
	Generated          string              `json:"generated"`
	Cases              int                 `json:"cases"`
	Scored             int                 `json:"scored"`
	Skipped            int                 `json:"skipped"`
	Passes             bool                `json:"passes"`
	ByDecision         map[string]int      `json:"by_decision"`
	ByCode             map[string]int      `json:"by_code"`
	ExpectedByDecision map[string]int      `json:"expected_by_decision"`
	ExpectedByCode     map[string]int      `json:"expected_by_code"`
	ByTag              map[string]TagCount `json:"by_tag"`
	Mismatches         []Mismatch          `json:"mismatches"`
	Results            []CaseResult        `json:"results"`
}

// TagCount is pass/fail coverage for one corpus tag.
type TagCount struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// Mismatch names one failed case.
type Mismatch struct {
	Line             int    `json:"line"`
	ID               string `json:"id,omitempty"`
	Command          string `json:"command"`
	ExpectedDecision string `json:"expected_decision"`
	ActualDecision   string `json:"actual_decision,omitempty"`
	ExpectedCode     string `json:"expected_code,omitempty"`
	ActualCode       string `json:"actual_code,omitempty"`
	Error            string `json:"error,omitempty"`
}

// CaseResult is one scored case.
type CaseResult struct {
	Line             int    `json:"line"`
	ID               string `json:"id,omitempty"`
	Command          string `json:"command"`
	ExpectedDecision string `json:"expected_decision"`
	ExpectedCode     string `json:"expected_code,omitempty"`
	ActualDecision   string `json:"actual_decision,omitempty"`
	ActualCode       string `json:"actual_code,omitempty"`
	Passed           bool   `json:"passed"`
	Error            string `json:"error,omitempty"`
}
