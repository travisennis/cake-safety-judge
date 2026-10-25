package provider

import (
	"context"
	"encoding/json"
	"fmt"
)

// Fake is the deterministic offline provider. It echoes the harness label (or
// its configured default) as a well-formed verdict so the parser, code
// validation, decision mapping, and framing are exercised without a model.
// It never claims judgment parity.
type Fake struct {
	Decision   string
	Code       string
	Message    string
	Confidence *float64
	Err        *Error
}

// Complete implements Provider.
func (f *Fake) Complete(_ context.Context, req Request) (Result, error) {
	if f.Err != nil {
		return Result{}, f.Err
	}
	decision, code, message, confidence := f.Decision, f.Code, f.Message, f.Confidence
	if req.Expected != nil {
		decision = req.Expected.Decision
		code = req.Expected.Code
		message = req.Expected.Message
		confidence = req.Expected.Confidence
	}
	if decision == "" {
		decision = "allow"
	}
	if message == "" {
		message = fmt.Sprintf("offline fake verdict: %s", decision)
	}
	if decision == "allow" {
		code = ""
	}
	body := map[string]any{"verdict": decision, "message": message}
	if code != "" {
		body["code"] = code
	}
	if confidence != nil {
		body["confidence"] = *confidence
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return Result{}, &Error{Class: "internal", Message: "encode fake verdict: " + err.Error()}
	}
	return Result{Content: string(encoded)}, nil
}
