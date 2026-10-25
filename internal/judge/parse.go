package judge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/travisennis/cake-safety-judge/internal/rubric"
)

type wireVerdict struct {
	Verdict    string   `json:"verdict"`
	Code       *string  `json:"code"`
	Message    string   `json:"message"`
	Confidence *float64 `json:"confidence"`
}

// parseVerdict applies ADR 018's strict rule: strip at most one complete
// Markdown fence with an empty or `json` tag, parse the entire payload as one
// JSON object, and validate the decision/code agreement. There is no repair.
func parseVerdict(content string) (Verdict, error) {
	payload := stripMarkdownFences(content)
	if !utf8.ValidString(payload) {
		return Verdict{}, errors.New("judge verdict is not valid UTF-8")
	}
	if err := rejectDuplicateKeys([]byte(payload)); err != nil {
		return Verdict{}, fmt.Errorf("could not parse judge verdict JSON: %w", err)
	}
	var wire wireVerdict
	if err := json.Unmarshal([]byte(payload), &wire); err != nil {
		return Verdict{}, fmt.Errorf("could not parse judge verdict JSON: %w", err)
	}
	verdict := Verdict{
		Decision:   wire.Verdict,
		Message:    wire.Message,
		Confidence: wire.Confidence,
	}
	if wire.Code != nil {
		verdict.Code = *wire.Code
	}
	if err := validateVerdict(&verdict); err != nil {
		return Verdict{}, err
	}
	return verdict, nil
}

func validateVerdict(verdict *Verdict) error {
	if strings.TrimSpace(verdict.Message) == "" {
		return errors.New("judge verdict has an empty message")
	}
	if verdict.Confidence != nil {
		value := *verdict.Confidence
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return errors.New("judge verdict confidence must be finite and between 0 and 1")
		}
	}
	switch verdict.Decision {
	case "block":
		return validateBlockCode(verdict.Code)
	case "warn":
		return validateWarnCode(verdict.Code)
	case "allow":
		if verdict.Code != "" {
			return fmt.Errorf("allow verdicts must omit the verdict code; got %q", verdict.Code)
		}
		return nil
	default:
		return fmt.Errorf("judge verdict decision %q is not block, warn, or allow", verdict.Decision)
	}
}

func validateBlockCode(value string) error {
	if value == "" {
		return errors.New("block verdicts must include a verdict code")
	}
	code, ok := rubric.Parse(value)
	if !ok {
		return fmt.Errorf("block verdicts must carry a known verdict code; got %q", value)
	}
	if code.IsWarnClass() {
		return fmt.Errorf("block verdicts must not carry the warn-class code %q", value)
	}
	return nil
}

func validateWarnCode(value string) error {
	if value == "" {
		return errors.New("warn verdicts must include a verdict code")
	}
	code, ok := rubric.Parse(value)
	if !ok {
		return fmt.Errorf("warn verdicts must carry a known verdict code; got %q", value)
	}
	if !code.IsWarnClass() {
		return fmt.Errorf("warn verdicts must carry the warn-class code; got %q", value)
	}
	return nil
}

// rejectDuplicateKeys mirrors serde's duplicate-field rejection for the
// top-level object. encoding/json keeps the last duplicate silently, which
// would let a provider smuggle a second verdict past a reader.
func rejectDuplicateKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil // let json.Unmarshal produce the real error
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("verdict object has a non-string key")
		}
		if seen[key] {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

// stripMarkdownFences removes exactly one complete fence whose opening tag is
// empty or `json` and whose closing fence is the final line. Anything else is
// returned unchanged so strict JSON parsing fails closed.
func stripMarkdownFences(payload string) string {
	trimmed := strings.TrimSpace(payload)
	opening, body, ok := strings.Cut(trimmed, "\n")
	if !ok {
		return trimmed
	}
	tag := strings.TrimRightFunc(opening, unicode.IsSpace)
	if tag != "```" && tag != "```json" {
		return trimmed
	}
	body, ok = strings.CutSuffix(body, "\n```")
	if !ok {
		return trimmed
	}
	return strings.TrimSpace(body)
}
