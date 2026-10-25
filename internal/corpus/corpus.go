// Package corpus loads the frozen command corpora and builds the offline
// parity report.
//
// The fake-provider run proves the gate's request assembly, verdict parsing,
// code validation, decision mapping, and framing. It is not model-parity
// evidence; a recorded-response run over real judge output is.
package corpus

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/travisennis/cake-safety-judge/internal/judge"
	"github.com/travisennis/cake-safety-judge/internal/rubric"
)

// Case is one normalized corpus row.
type Case struct {
	Line             int      `json:"line"`
	ID               string   `json:"id"`
	Command          string   `json:"command"`
	Cwd              string   `json:"cwd"`
	Reason           *string  `json:"reason"`
	RepoDigest       *string  `json:"repo_digest"`
	ExpectedDecision string   `json:"expected_decision"`
	ExpectedCode     string   `json:"expected_code"`
	Note             string   `json:"note,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	// Skipped is true for an `unscored` independent case.
	Skipped bool `json:"skipped"`
}

type rawCase struct {
	ID               string   `json:"id"`
	Command          string   `json:"command"`
	Cwd              string   `json:"cwd"`
	Reason           *string  `json:"reason"`
	RepoDigest       *string  `json:"repo_digest"`
	Expect           string   `json:"expect"`
	Code             string   `json:"code"`
	Note             string   `json:"note"`
	ExpectedDecision string   `json:"expected_decision"`
	VerdictCode      string   `json:"verdict_code"`
	Tags             []string `json:"tags"`
}

// Load reads and validates one JSONL corpus.
func Load(path string) ([]Case, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var cases []Case
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var row rawCase
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		c, err := normalize(line, row)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		cases = append(cases, c)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s has no cases", path)
	}
	return cases, nil
}

func normalize(line int, row rawCase) (Case, error) {
	if strings.TrimSpace(row.Command) == "" {
		return Case{}, fmt.Errorf("command is required")
	}
	expected := row.ExpectedDecision
	if expected == "" {
		switch row.Expect {
		case "blocked":
			expected = "block"
		case "warned":
			expected = "warn"
		case "allowed":
			expected = "allow"
		case "":
			return Case{}, fmt.Errorf("expected decision is missing")
		default:
			return Case{}, fmt.Errorf("unknown expect value %q", row.Expect)
		}
	}
	switch expected {
	case "allow", "warn", "block":
	case "unscored":
		return Case{
			Line:             line,
			ID:               row.ID,
			Command:          row.Command,
			Cwd:              cwdOrDefault(row.Cwd),
			Reason:           row.Reason,
			RepoDigest:       row.RepoDigest,
			ExpectedDecision: expected,
			Tags:             row.Tags,
			Skipped:          true,
		}, nil
	default:
		return Case{}, fmt.Errorf("unknown expected decision %q", expected)
	}
	code := row.Code
	if code == "" {
		code = row.VerdictCode
	}
	if expected == "allow" {
		if code != "" {
			return Case{}, fmt.Errorf("allow case carries code %q", code)
		}
	} else {
		parsed, ok := rubric.Parse(code)
		if !ok {
			return Case{}, fmt.Errorf("%s case carries unknown code %q", expected, code)
		}
		if expected == "warn" && !parsed.IsWarnClass() {
			return Case{}, fmt.Errorf("warn case carries non-warn code %q", code)
		}
		if expected == "block" && parsed.IsWarnClass() {
			return Case{}, fmt.Errorf("block case carries warn code %q", code)
		}
	}
	return Case{
		Line:             line,
		ID:               row.ID,
		Command:          row.Command,
		Cwd:              cwdOrDefault(row.Cwd),
		Reason:           row.Reason,
		RepoDigest:       row.RepoDigest,
		ExpectedDecision: expected,
		ExpectedCode:     code,
		Note:             row.Note,
		Tags:             row.Tags,
	}, nil
}

func cwdOrDefault(cwd string) string {
	if cwd == "" {
		return "/work/cake"
	}
	return cwd
}

// Evaluator runs one case through the gate's judge path.
type Evaluator func(Case) (judge.Verdict, error)

// Run evaluates every case and builds the report.
func Run(cases []Case, evaluator Evaluator, corpusName, providerName string, fingerprint string) Report {
	report := Report{
		SchemaVersion:      1,
		Corpus:             corpusName,
		CorpusFingerprint:  fingerprint,
		Provider:           providerName,
		Generated:          time.Now().UTC().Format(time.RFC3339),
		ByDecision:         map[string]int{},
		ByCode:             map[string]int{},
		ExpectedByDecision: map[string]int{},
		ExpectedByCode:     map[string]int{},
		ByTag:              map[string]TagCount{},
		Results:            make([]CaseResult, 0, len(cases)),
		Mismatches:         []Mismatch{},
	}
	report.Cases = len(cases)
	for _, c := range cases {
		if c.Skipped {
			report.Skipped++
			continue
		}
		report.Scored++
		report.ExpectedByDecision[c.ExpectedDecision]++
		if c.ExpectedCode != "" {
			report.ExpectedByCode[c.ExpectedCode]++
		}
		result := CaseResult{
			Line:             c.Line,
			ID:               c.ID,
			Command:          c.Command,
			ExpectedDecision: c.ExpectedDecision,
			ExpectedCode:     c.ExpectedCode,
		}
		verdict, err := evaluator(c)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.ActualDecision = verdict.Decision
			result.ActualCode = verdict.Code
			report.ByDecision[verdict.Decision]++
			if verdict.Code != "" {
				report.ByCode[verdict.Code]++
			}
		}
		result.Passed = result.Error == "" &&
			result.ActualDecision == c.ExpectedDecision &&
			result.ActualCode == c.ExpectedCode
		if !result.Passed {
			report.Mismatches = append(report.Mismatches, Mismatch{
				Line:             c.Line,
				ID:               c.ID,
				Command:          c.Command,
				ExpectedDecision: c.ExpectedDecision,
				ActualDecision:   result.ActualDecision,
				ExpectedCode:     c.ExpectedCode,
				ActualCode:       result.ActualCode,
				Error:            result.Error,
			})
		}
		for _, tag := range c.Tags {
			count := report.ByTag[tag]
			count.Total++
			if result.Passed {
				count.Passed++
			} else {
				count.Failed++
			}
			report.ByTag[tag] = count
		}
		report.Results = append(report.Results, result)
	}
	report.Passes = len(report.Mismatches) == 0
	return report
}

// Fingerprint returns the first eight hex characters of the corpus SHA-256.
func Fingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:8], nil
}

// SortedKeys returns map keys in stable order.
func SortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
