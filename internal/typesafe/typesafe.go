// Package typesafe ports cake's bounded TypeSafe observation.
//
// An observation is metadata: it never decides by itself. Under cascade mode
// the judge pipeline reads a clean probability at or above Cutoff as a fast
// approval; every failure or lower probability falls back to the judge.
package typesafe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIKeyEnv is the only credential variable the gate reads for TypeSafe.
const APIKeyEnv = "TYPESAFE_AI_API_KEY"

// DefaultEndpoint is cake's TypeSafe endpoint.
const DefaultEndpoint = "https://api.typesafe.ai/v1/systemone"

// Cutoff is the compiled fast-approval probability (ADR 034). No setting may
// lower it; a different cutoff is a new ADR with new evidence. The value is
// rounded through float32 to match Cake's stored f32 observation exactly.
const Cutoff = float64(float32(0.85))

const maxResponseBytes = 256 << 10

// Request is the action state sent to TypeSafe.
type Request struct {
	Command    string
	Cwd        string
	RepoDigest *string
	Reason     *string
}

// Observation is one TypeSafe answer or typed failure.
type Observation struct {
	Elapsed           time.Duration
	Model             string
	Probability       *float64
	UsageInputTokens  *int64
	UsageOutputTokens *int64
	FailureClass      string
}

// Failed builds a typed failure observation.
func Failed(elapsed time.Duration, class string) Observation {
	return Observation{Elapsed: elapsed, FailureClass: class}
}

// Client is one configured TypeSafe observer.
type Client struct {
	APIKey   string
	Model    string
	Timeout  time.Duration
	Endpoint string
	Rubric   string
	HTTP     *http.Client
}

// New builds a client with the default endpoint.
func New(apiKey, model string, timeout time.Duration, rubric string) *Client {
	return &Client{
		APIKey:   apiKey,
		Model:    model,
		Timeout:  timeout,
		Endpoint: DefaultEndpoint,
		Rubric:   rubric,
		HTTP: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type requestBody struct {
	Model     string           `json:"model"`
	State     requestState     `json:"state"`
	Questions requestQuestions `json:"questions"`
}

type requestState struct {
	Command         string  `json:"command"`
	Cwd             string  `json:"cwd"`
	RepoDigest      *string `json:"repo_digest"`
	UntrustedReason *string `json:"untrusted_reason"`
}

type requestQuestions struct {
	Eligible eligibilityQuestion `json:"eligible"`
}

type eligibilityQuestion struct {
	Type         string                  `json:"type"`
	Instructions eligibilityInstructions `json:"instructions"`
	Criteria     eligibilityCriteria     `json:"criteria"`
}

type eligibilityInstructions struct {
	Question        string `json:"question"`
	Interpretation  string `json:"interpretation"`
	EffectiveRubric string `json:"effective_rubric"`
}

type eligibilityCriteria struct {
	Yes string `json:"true"`
	No  string `json:"false"`
}

type responseBody struct {
	Model   string `json:"model"`
	Answers struct {
		Eligible struct {
			Type string  `json:"type"`
			Noul float64 `json:"noul"`
		} `json:"eligible"`
	} `json:"answers"`
	Usage *struct {
		InputTokens  *int64 `json:"input_tokens"`
		OutputTokens *int64 `json:"output_tokens"`
	} `json:"usage"`
}

// Observe performs one bounded observation.
func (c *Client) Observe(ctx context.Context, request Request) Observation {
	started := time.Now()
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	response, class := c.send(attemptCtx, request)
	if class != "" {
		return Failed(time.Since(started), class)
	}
	if response.Model != c.Model {
		return Failed(time.Since(started), "model_mismatch")
	}
	if response.Answers.Eligible.Type != "noul" {
		return Failed(time.Since(started), "answer_type_mismatch")
	}
	probability := response.Answers.Eligible.Noul
	if probability < 0 || probability > 1 {
		return Failed(time.Since(started), "probability_out_of_range")
	}
	// Cake stores the observation as f32; round the same way so the cutoff
	// comparison cannot differ at the boundary.
	probability = float64(float32(probability))
	observation := Observation{
		Elapsed:     time.Since(started),
		Model:       c.Model,
		Probability: &probability,
	}
	if response.Usage != nil {
		observation.UsageInputTokens = response.Usage.InputTokens
		observation.UsageOutputTokens = response.Usage.OutputTokens
	}
	return observation
}

func (c *Client) send(ctx context.Context, request Request) (*responseBody, string) {
	if strings.TrimSpace(c.APIKey) == "" {
		return nil, "missing_credentials"
	}
	if strings.TrimSpace(c.Model) == "" {
		return nil, "client_configuration"
	}
	body, err := marshalNoEscape(requestBody{
		Model: c.Model,
		State: requestState{
			Command:         request.Command,
			Cwd:             request.Cwd,
			RepoDigest:      request.RepoDigest,
			UntrustedReason: request.Reason,
		},
		Questions: requestQuestions{Eligible: eligibilityQuestion{
			Type: "noul",
			Instructions: eligibilityInstructions{
				Question:        eligibilityQuestionText,
				Interpretation:  eligibilityInterpretation,
				EffectiveRubric: c.Rubric,
			},
			Criteria: eligibilityCriteria{
				Yes: eligibilityYes,
				No:  eligibilityNo,
			},
		}},
	})
	if err != nil {
		return nil, "client_configuration"
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "client_configuration"
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+c.APIKey)

	client := c.HTTP
	if client == nil {
		client = &http.Client{}
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, "timeout"
		}
		return nil, "transport"
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "http_error"
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, "transport"
	}
	if len(raw) > maxResponseBytes {
		return nil, "response_too_large"
	}
	var decoded responseBody
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, "malformed_response"
	}
	return &decoded, ""
}

// marshalNoEscape matches serde_json's output: HTML characters stay literal.
// The TypeSafe request is calibration-bound, so its bytes must not drift with
// Go's default HTML escaping.
func marshalNoEscape(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
