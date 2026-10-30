package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/travisennis/cake-safety-judge/internal/judge"
	"github.com/travisennis/cake-safety-judge/internal/protocol"
	"github.com/travisennis/cake-safety-judge/internal/provider"
	"github.com/travisennis/cake-safety-judge/internal/typesafe"
)

type attemptData struct {
	Model         string          `json:"model"`
	APIType       string          `json:"api_type"`
	Attempt       int             `json:"attempt"`
	RetryDelayMS  int64           `json:"retry_delay_ms"`
	LatencyMS     int64           `json:"latency_ms"`
	StatusCode    *int            `json:"status_code,omitempty"`
	TerminalClass string          `json:"terminal_class"`
	Usage         *provider.Usage `json:"usage,omitempty"`
}

type typesafeData struct {
	Model        string             `json:"model"`
	Mode         string             `json:"mode"`
	Probability  *float64           `json:"probability,omitempty"`
	FailureClass string             `json:"failure_class,omitempty"`
	LatencyMS    int64              `json:"latency_ms"`
	Calibration  *typesafe.Identity `json:"calibration,omitempty"`
	Recorded     bool               `json:"recorded"`
}

// Evaluate returns one decision or one error frame. The decision frame is
// validated before it is returned, so a bug cannot emit an invalid answer.
func (e *Engine) Evaluate(ctx context.Context, check protocol.CheckFrame) (protocol.DecisionFrame, *protocol.ErrorFrame) {
	evidence := make([]protocol.Evidence, 0, 3)

	if e.Typesafe != nil {
		observation := e.Typesafe.Observe(ctx, typesafe.Request{
			Command:    check.Input.Command,
			Cwd:        check.Input.Cwd,
			RepoDigest: check.Input.RepoDigest,
			Reason:     check.Input.Reason,
		})
		evidence = append(evidence, mustEvidence("typesafe_observation", typesafeData{
			Model:        e.Typesafe.Model,
			Mode:         e.TypesafeMode,
			Probability:  observation.Probability,
			FailureClass: observation.FailureClass,
			LatencyMS:    observation.Elapsed.Milliseconds(),
			Calibration:  e.TypesafeIdentity,
			Recorded:     e.TypesafeRecord != nil,
		}))
		if e.TypesafeMode == "cascade" && observation.FailureClass == "" &&
			observation.Probability != nil && *observation.Probability >= typesafe.Cutoff {
			decision := protocol.DecisionFrame{
				Protocol:     protocol.Version,
				Type:         "decision",
				ID:           check.ID,
				Decision:     "allow",
				Message:      "TypeSafe fast-approved this command.",
				Confidence:   observation.Probability,
				ShortCircuit: true,
				Evidence:     evidence,
			}
			e.diagnose(check, "allow", "TypeSafe fast approval", "", "")
			return e.finishDecision(check, decision)
		}
	}

	request := judge.Request{
		Command:    check.Input.Command,
		Cwd:        check.Input.Cwd,
		RepoDigest: check.Input.RepoDigest,
		Reason:     check.Input.Reason,
	}
	for _, script := range check.Input.ScriptEvidence {
		request.ScriptEvidence = append(request.ScriptEvidence, judge.ScriptEvidence{
			Path:     script.Path,
			Contents: script.Contents,
		})
	}

	verdict, attempts, err := e.Judge.Evaluate(ctx, request)
	if err != nil {
		e.diagnose(check, "", err.Error(), "", "")
		return protocol.DecisionFrame{}, e.failureFrame(check.ID, err)
	}
	system, user, promptErr := e.Judge.Prompts(request)
	if promptErr != nil {
		e.diagnose(check, "", promptErr.Error(), "", "")
		return protocol.DecisionFrame{}, e.failureFrame(check.ID, promptErr)
	}
	for _, attempt := range attempts {
		data := attemptData{
			Model:         e.Descriptor.Model,
			APIType:       e.Descriptor.APIType,
			Attempt:       attempt.Ordinal + 1,
			RetryDelayMS:  attempt.RetryDelay.Milliseconds(),
			LatencyMS:     attempt.Latency.Milliseconds(),
			TerminalClass: attempt.TerminalClass,
		}
		if attempt.Status != 0 {
			status := attempt.Status
			data.StatusCode = &status
		}
		if attempt.Usage != (provider.Usage{}) {
			usage := attempt.Usage
			data.Usage = &usage
		}
		evidence = append(evidence, mustEvidence("attempt", data))
	}

	decision := protocol.DecisionFrame{
		Protocol:   protocol.Version,
		Type:       "decision",
		ID:         check.ID,
		Decision:   verdict.Decision,
		Message:    verdict.Message,
		Confidence: verdict.Confidence,
		Evidence:   evidence,
	}
	if verdict.Code != "" {
		code := verdict.Code
		decision.Code = &code
	}
	e.diagnose(check, decision.Decision, decision.Message, system, user)
	return e.finishDecision(check, decision)
}

func (e *Engine) finishDecision(check protocol.CheckFrame, decision protocol.DecisionFrame) (protocol.DecisionFrame, *protocol.ErrorFrame) {
	if err := decision.Validate(); err != nil {
		return protocol.DecisionFrame{}, &protocol.ErrorFrame{
			Protocol: protocol.Version,
			Type:     "error",
			ID:       check.ID,
			Class:    "internal",
			Message:  "gate built an invalid decision: " + err.Error(),
		}
	}
	return decision, nil
}

func (e *Engine) failureFrame(id string, err error) *protocol.ErrorFrame {
	class := "internal"
	message := err.Error()
	var failure *judge.Failure
	if errors.As(err, &failure) {
		class = failure.Class
	}
	class = protocol.ErrorClass(class)
	message = judge.SanitizeMessage(e.sanitize(message))
	return &protocol.ErrorFrame{
		Protocol: protocol.Version,
		Type:     "error",
		ID:       id,
		Class:    class,
		Message:  message,
	}
}

func mustEvidence(kind string, value any) protocol.Evidence {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte("{}")
	}
	return protocol.Evidence{Kind: kind, Data: raw}
}

const diagnosticPreview = 4096

func (e *Engine) diagnose(check protocol.CheckFrame, decision, detail, system, user string) {
	if e.Log == nil || check.Options == nil || !check.Options.Diagnostic {
		return
	}
	_, _ = fmt.Fprintf(e.Log, "DIAGNOSTIC gate=safety check=%s decision=%s\n", check.ID, decision)
	_, _ = fmt.Fprintf(e.Log, "DIAGNOSTIC command=%q cwd=%q\n",
		e.sanitize(check.Input.Command), e.sanitize(check.Input.Cwd))
	if e.TypesafeIdentity != nil {
		_, _ = fmt.Fprintf(e.Log,
			"DIAGNOSTIC typesafe_identity=%s recorded=%t model=%s rubric=%s request_schema=%s context_schema=%s corpus=%s/%s cutoff=%.2f\n",
			e.TypesafeIdentity.ID, e.TypesafeRecord != nil, e.TypesafeIdentity.Model,
			e.TypesafeIdentity.RubricFingerprint, e.TypesafeIdentity.RequestSchemaFingerprint,
			e.TypesafeIdentity.ContextSchemaFingerprint, e.TypesafeIdentity.CorpusVersion,
			e.TypesafeIdentity.CorpusFingerprint, e.TypesafeIdentity.Cutoff)
	}
	_, _ = fmt.Fprintf(e.Log, "DIAGNOSTIC system_prompt=%s\n", truncate(e.sanitize(system), diagnosticPreview))
	_, _ = fmt.Fprintf(e.Log, "DIAGNOSTIC user_prompt=%s\n", truncate(e.sanitize(user), diagnosticPreview))
	if detail != "" {
		_, _ = fmt.Fprintf(e.Log, "DIAGNOSTIC detail=%s\n", truncate(e.sanitize(detail), diagnosticPreview))
	}
}

func (e *Engine) sanitize(value string) string {
	value = judge.RedactValue(value, e.Judge.APIKey)
	if e.Typesafe != nil {
		value = judge.RedactValue(value, e.Typesafe.APIKey)
	}
	return judge.SanitizeText(value)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut] + "..."
}

// SetDiagnosticWriter sets the sensitive diagnostic sink.
func (e *Engine) SetDiagnosticWriter(writer io.Writer) {
	e.Log = writer
}

// Timeout is the judge's per-attempt timeout under this engine's config.
func (e *Engine) Timeout() time.Duration {
	return e.Config.timeout()
}

// RetryBudget is the judge's recovery allowance under this engine's config.
func (e *Engine) RetryBudget() time.Duration {
	return e.Config.retryBudget()
}
