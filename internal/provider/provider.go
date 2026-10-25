// Package provider implements the model transports a gate may use.
//
// A provider is deliberately narrow: it sends one prompt pair and returns the
// assistant text or a typed failure. Retry policy lives in package judge;
// envelope decoding lives here so an undecodable 2xx body is distinguishable
// from a malformed verdict.
package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Descriptor is the gate's resolved model configuration. It never carries a
// credential value; APIKey is read from the environment by the caller.
type Descriptor struct {
	Provider         string
	BaseURL          string
	APIType          string
	Model            string
	APIKeyEnv        string
	HTTPReferer      string
	XTitle           string
	Temperature      *float64
	TopP             *float64
	MaxOutputTokens  *int
	ReasoningEffort  string
	ReasoningSummary string
	ReasoningMax     *int
}

// Usage is the provider-reported token accounting.
type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}

// Request is one judge call.
type Request struct {
	System     string
	User       string
	Command    string // correlation only; never sent to a provider
	Descriptor Descriptor
	APIKey     string
	// Expected drives the deterministic fake provider. It is nil in
	// production and is never serialized into a prompt.
	Expected *Expected
}

// Expected is an offline harness label.
type Expected struct {
	Decision   string
	Code       string
	Message    string
	Confidence *float64
}

// Result is one successful provider turn.
type Result struct {
	Content   string
	Refusal   bool
	Usage     Usage
	RequestID string
	Model     string
}

// Error is a typed transport or decoding failure.
type Error struct {
	Class     string
	Message   string
	Retryable bool
	Status    int
}

func (e *Error) Error() string {
	return e.Message
}

// Provider sends one prompt pair.
type Provider interface {
	Complete(ctx context.Context, req Request) (Result, error)
}

// Live is the real HTTP provider. It supports Chat Completions and Responses.
type Live struct {
	Client *http.Client
}

// NewLive returns a live provider with redirects disabled and no automatic
// retry; the judge owns the one bounded recovery attempt.
func NewLive() *Live {
	return &Live{Client: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// Complete dispatches on the descriptor's api_type.
func (l *Live) Complete(ctx context.Context, req Request) (Result, error) {
	client := l.Client
	if client == nil {
		client = NewLive().Client
	}
	switch req.Descriptor.APIType {
	case "chat_completions":
		return completeChat(ctx, client, req)
	case "responses":
		return completeResponses(ctx, client, req)
	default:
		return Result{}, &Error{
			Class:   "config",
			Message: fmt.Sprintf("api_type %q is not chat_completions or responses", req.Descriptor.APIType),
		}
	}
}

// ClassifyError maps a provider or context error to a cake-gate/1 class.
func ClassifyError(err error) *Error {
	var providerError *Error
	if errors.As(err, &providerError) {
		return providerError
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Class: "timeout", Message: "provider call exceeded its deadline", Retryable: true}
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return &Error{Class: "timeout", Message: "provider call timed out", Retryable: true}
	}
	return &Error{Class: "network", Message: "provider transport failure", Retryable: true}
}

func classifyStatus(status int) *Error {
	message := fmt.Sprintf("provider returned HTTP %d", status)
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &Error{Class: "auth", Message: message, Status: status}
	case http.StatusTooManyRequests:
		return &Error{Class: "rate_limit", Message: message, Retryable: true, Status: status}
	case http.StatusRequestTimeout:
		return &Error{Class: "timeout", Message: message, Retryable: true, Status: status}
	case http.StatusConflict, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
		return &Error{Class: "transport", Message: message, Retryable: true, Status: status}
	default:
		return &Error{Class: "transport", Message: message, Status: status}
	}
}

func applyHeaders(request *http.Request, req Request) {
	request.Header.Set("Content-Type", "application/json")
	if req.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+req.APIKey)
	}
	if req.Descriptor.HTTPReferer != "" {
		request.Header.Set("HTTP-Referer", req.Descriptor.HTTPReferer)
	}
	if req.Descriptor.XTitle != "" {
		request.Header.Set("X-Title", req.Descriptor.XTitle)
	}
}

func endpoint(baseURL, suffix string) string {
	return strings.TrimRight(baseURL, "/") + suffix
}

func readBody(response *http.Response) ([]byte, error) {
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, &Error{Class: "network", Message: "provider response body read failed", Retryable: true}
	}
	return body, nil
}

func timeoutOr(ctx context.Context, err error) *Error {
	if ctx.Err() == context.DeadlineExceeded {
		return &Error{Class: "timeout", Message: "provider call exceeded its deadline", Retryable: true}
	}
	return ClassifyError(err)
}

// WithTimeout derives a context deadline without exceeding the parent.
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}
