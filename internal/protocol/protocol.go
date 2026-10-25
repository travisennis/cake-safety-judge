// Package protocol defines the cake-gate/1 wire types and their validation.
//
// The authoritative contract is cake's docs/integrations.md (Gate protocol) and
// docs/schemas/cake-gate-1.schema.json. This package mirrors the schema's
// required fields, closed enums, and conditional requirements; it deliberately
// tolerates unknown fields so additive protocol edits do not break a gate.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Version is the only protocol version this gate speaks.
const Version = "cake-gate/1"

// MaxFrameBytes is the largest single NDJSON frame, excluding the newline.
const MaxFrameBytes = 1 << 20

// MaxEvidenceBytes is the documented per-evidence payload ceiling.
const MaxEvidenceBytes = 8 << 10

var (
	gateNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	gateVersion      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	codePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	errorClassPatt   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	evidenceKindPatt = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Describe is the object printed by the required `describe` subcommand.
type Describe struct {
	Protocol     string   `json:"protocol"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Phases       []string `json:"phases"`
	Actions      []string `json:"actions"`
	Transports   []string `json:"transports"`
	Capabilities []string `json:"capabilities"`
}

// ProviderHeaders carries the optional attribution headers a descriptor names.
type ProviderHeaders struct {
	HTTPReferer string `json:"http_referer,omitempty"`
	XTitle      string `json:"x_title,omitempty"`
}

// ModelDescriptor is one resolved model supplied by Cake. It never carries a
// credential value, only the name of the environment variable holding it.
type ModelDescriptor struct {
	Provider         string           `json:"provider,omitempty"`
	BaseURL          string           `json:"base_url"`
	APIType          string           `json:"api_type"`
	Model            string           `json:"model"`
	APIKeyEnv        string           `json:"api_key_env"`
	ProviderHeaders  *ProviderHeaders `json:"provider_headers,omitempty"`
	Temperature      *float64         `json:"temperature,omitempty"`
	TopP             *float64         `json:"top_p,omitempty"`
	MaxOutputTokens  *int             `json:"max_output_tokens,omitempty"`
	ReasoningEffort  string           `json:"reasoning_effort,omitempty"`
	ReasoningSummary string           `json:"reasoning_summary,omitempty"`
	ReasoningMax     *int             `json:"reasoning_max_tokens,omitempty"`
}

// InitSession identifies the run. Identifiers are correlation context only.
type InitSession struct {
	SessionID    string `json:"session_id,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	Cwd          string `json:"cwd"`
}

// InitFrame is sent exactly once per gate process instance.
type InitFrame struct {
	Protocol string                     `json:"protocol"`
	Type     string                     `json:"type"`
	ID       string                     `json:"id"`
	Session  InitSession                `json:"session"`
	Config   json.RawMessage            `json:"config,omitempty"`
	Models   map[string]ModelDescriptor `json:"models,omitempty"`
	Env      []string                   `json:"env,omitempty"`
}

// ReadyFrame answers a valid init frame.
type ReadyFrame struct {
	Protocol string   `json:"protocol"`
	Type     string   `json:"type"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Warnings []string `json:"warnings,omitempty"`
}

// ScriptEvidence is bounded, untrusted text Cake collected for the action.
type ScriptEvidence struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

// BashInput is the action evidence for bash.exec.
type BashInput struct {
	Command        string           `json:"command"`
	Cwd            string           `json:"cwd"`
	Reason         *string          `json:"reason"`
	RepoDigest     *string          `json:"repo_digest"`
	ScriptEvidence []ScriptEvidence `json:"script_evidence"`
}

// CheckOptions carries the diagnostic opt-in.
type CheckOptions struct {
	Diagnostic bool `json:"diagnostic"`
}

// CheckSession correlates a check with a tool call.
type CheckSession struct {
	SessionID    string `json:"session_id,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	CallID       string `json:"call_id,omitempty"`
	Turn         *int   `json:"turn,omitempty"`
}

// CheckFrame asks for one decision.
type CheckFrame struct {
	Protocol string        `json:"protocol"`
	Type     string        `json:"type"`
	ID       string        `json:"id"`
	Phase    string        `json:"phase"`
	Action   string        `json:"action"`
	Input    BashInput     `json:"input"`
	Session  *CheckSession `json:"session,omitempty"`
	Options  *CheckOptions `json:"options"`
}

// Annotation is a model-visible line prepended by Cake.
type Annotation struct {
	Placement string `json:"placement"`
	Text      string `json:"text"`
}

// Evidence is the only gate-controlled data that reaches telemetry.
type Evidence struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// DecisionFrame answers one check.
type DecisionFrame struct {
	Protocol     string       `json:"protocol"`
	Type         string       `json:"type"`
	ID           string       `json:"id"`
	Decision     string       `json:"decision"`
	Code         *string      `json:"code,omitempty"`
	Message      string       `json:"message,omitempty"`
	Confidence   *float64     `json:"confidence,omitempty"`
	Annotations  []Annotation `json:"annotations,omitempty"`
	ShortCircuit bool         `json:"short_circuit,omitempty"`
	Evidence     []Evidence   `json:"evidence,omitempty"`
}

// ErrorFrame reports a failure instead of a decision or ready frame.
type ErrorFrame struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Class    string `json:"class"`
	Message  string `json:"message"`
}

// ShutdownFrame asks the process to exit after in-flight checks finish.
type ShutdownFrame struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	ID       string `json:"id"`
}

// Frame is any decoded serve frame.
type Frame interface {
	Validate() error
}

// Decode parses one NDJSON frame and validates it.
func Decode(raw []byte) (Frame, error) {
	if len(raw) > MaxFrameBytes {
		return nil, fmt.Errorf("frame is %d bytes, limit is %d", len(raw), MaxFrameBytes)
	}
	var probe struct {
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	var frame Frame
	switch probe.Type {
	case "init":
		var f InitFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("decode init: %w", err)
		}
		frame = &f
	case "check":
		var f CheckFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("decode check: %w", err)
		}
		frame = &f
	case "decision":
		var f DecisionFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("decode decision: %w", err)
		}
		frame = &f
	case "error":
		var f ErrorFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("decode error: %w", err)
		}
		frame = &f
	case "shutdown":
		var f ShutdownFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("decode shutdown: %w", err)
		}
		frame = &f
	case "":
		return nil, errors.New("frame is missing type")
	default:
		return nil, fmt.Errorf("unknown frame type %q", probe.Type)
	}
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	return frame, nil
}

// DecodeDescribe parses and validates a describe object.
func DecodeDescribe(raw []byte) (*Describe, error) {
	var d Describe
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("decode describe: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks the describe object against the contract.
func (d *Describe) Validate() error {
	if d.Protocol != Version {
		return fmt.Errorf("describe protocol is %q, want %q", d.Protocol, Version)
	}
	if !gateNamePattern.MatchString(d.Name) {
		return fmt.Errorf("describe name %q is invalid", d.Name)
	}
	if len(d.Version) > 64 || !gateVersion.MatchString(d.Version) {
		return fmt.Errorf("describe version %q is invalid", d.Version)
	}
	if err := nonEmptyUnique(d.Phases, "phases"); err != nil {
		return err
	}
	for _, phase := range d.Phases {
		if phase != "pre_tool" && phase != "post_tool" {
			return fmt.Errorf("describe phase %q is not pre_tool or post_tool", phase)
		}
	}
	if err := nonEmptyUnique(d.Actions, "actions"); err != nil {
		return err
	}
	for _, action := range d.Actions {
		if action != "bash.exec" {
			return fmt.Errorf("describe action %q is not bash.exec", action)
		}
	}
	if err := nonEmptyUnique(d.Transports, "transports"); err != nil {
		return err
	}
	hasStdio := false
	for _, transport := range d.Transports {
		if transport != "stdio" && transport != "oneshot" {
			return fmt.Errorf("describe transport %q is invalid", transport)
		}
		if transport == "stdio" {
			hasStdio = true
		}
	}
	if !hasStdio {
		return errors.New("describe transports must contain stdio")
	}
	if d.Capabilities == nil {
		return errors.New("describe capabilities is required (it may be empty)")
	}
	seen := map[string]bool{}
	for _, capability := range d.Capabilities {
		if !gateNamePattern.MatchString(capability) {
			return fmt.Errorf("describe capability %q is invalid", capability)
		}
		if seen[capability] {
			return fmt.Errorf("describe capability %q is duplicated", capability)
		}
		seen[capability] = true
	}
	return nil
}

// Validate checks the init frame and its model descriptors.
func (f *InitFrame) Validate() error {
	if f.Protocol != Version {
		return fmt.Errorf("init protocol is %q, want %q", f.Protocol, Version)
	}
	if f.Type != "init" || f.ID != "init" {
		return errors.New("init frame must carry type and id \"init\"")
	}
	if strings.TrimSpace(f.Session.Cwd) == "" {
		return errors.New("init session.cwd is required")
	}
	if len(f.Env) > 32 {
		return fmt.Errorf("init env has %d names, limit is 32", len(f.Env))
	}
	seenEnv := map[string]bool{}
	for _, name := range f.Env {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("init env name %q is invalid", name)
		}
		if seenEnv[name] {
			return fmt.Errorf("init env name %q is duplicated", name)
		}
		seenEnv[name] = true
	}
	if f.Config != nil {
		trimmed := strings.TrimSpace(string(f.Config))
		if trimmed != "" && !strings.HasPrefix(trimmed, "{") {
			return errors.New("init config must be a JSON object")
		}
		if len(f.Config) > 64<<10 {
			return fmt.Errorf("init config is %d bytes, limit is 65536", len(f.Config))
		}
	}
	for name, descriptor := range f.Models {
		if !gateNamePattern.MatchString(name) && name != "default" {
			return fmt.Errorf("init model name %q is invalid", name)
		}
		if err := descriptor.Validate(); err != nil {
			return fmt.Errorf("init model %q: %w", name, err)
		}
	}
	return nil
}

// Validate checks a model descriptor.
func (d *ModelDescriptor) Validate() error {
	if d.BaseURL == "" {
		return errors.New("base_url is required")
	}
	if d.APIType != "chat_completions" && d.APIType != "responses" {
		return fmt.Errorf("api_type %q is not chat_completions or responses", d.APIType)
	}
	if d.Model == "" {
		return errors.New("model is required")
	}
	if !envNamePattern.MatchString(d.APIKeyEnv) {
		return fmt.Errorf("api_key_env %q is invalid", d.APIKeyEnv)
	}
	return nil
}

// Validate checks the check frame and its bounded evidence.
func (f *CheckFrame) Validate() error {
	if f.Protocol != Version {
		return fmt.Errorf("check protocol is %q, want %q", f.Protocol, Version)
	}
	if f.Type != "check" {
		return errors.New("check frame must carry type \"check\"")
	}
	if err := validID(f.ID); err != nil {
		return err
	}
	if f.Phase != "pre_tool" || f.Action != "bash.exec" {
		return fmt.Errorf("unsupported phase/action %q/%q", f.Phase, f.Action)
	}
	if strings.TrimSpace(f.Input.Cwd) == "" {
		return errors.New("check input.cwd is required")
	}
	if f.Input.ScriptEvidence == nil {
		return errors.New("check input.script_evidence is required (it may be empty)")
	}
	if len(f.Input.ScriptEvidence) > 1 {
		return fmt.Errorf("check input.script_evidence has %d items, limit is 1", len(f.Input.ScriptEvidence))
	}
	for _, evidence := range f.Input.ScriptEvidence {
		if evidence.Path == "" {
			return errors.New("script_evidence path is required")
		}
		if len(evidence.Contents) > 32<<10 {
			return fmt.Errorf("script_evidence contents is %d bytes, limit is 32768", len(evidence.Contents))
		}
	}
	if f.Options == nil {
		return errors.New("check options is required")
	}
	if f.Session != nil && f.Session.Turn != nil && *f.Session.Turn < 0 {
		return errors.New("check session.turn must be non-negative")
	}
	return nil
}

// Validate checks a decision frame, including the block/warn requirements.
func (f *DecisionFrame) Validate() error {
	if f.Protocol != Version {
		return fmt.Errorf("decision protocol is %q, want %q", f.Protocol, Version)
	}
	if f.Type != "decision" {
		return errors.New("decision frame must carry type \"decision\"")
	}
	if err := validID(f.ID); err != nil {
		return err
	}
	switch f.Decision {
	case "allow", "warn", "block", "abstain":
	default:
		return fmt.Errorf("decision %q is invalid", f.Decision)
	}
	requiresCode := f.Decision == "block" || f.Decision == "warn"
	if requiresCode {
		if f.Code == nil || !codePattern.MatchString(*f.Code) {
			return fmt.Errorf("%s decisions require a valid code", f.Decision)
		}
		if strings.TrimSpace(f.Message) == "" {
			return fmt.Errorf("%s decisions require a message", f.Decision)
		}
	} else if f.Code != nil && *f.Code != "" && !codePattern.MatchString(*f.Code) {
		return fmt.Errorf("decision code %q is invalid", *f.Code)
	}
	if len(f.Message) > 8192 {
		return fmt.Errorf("decision message is %d characters, limit is 8192", len(f.Message))
	}
	if f.Confidence != nil {
		if math.IsNaN(*f.Confidence) || math.IsInf(*f.Confidence, 0) ||
			*f.Confidence < 0 || *f.Confidence > 1 {
			return errors.New("decision confidence must be finite and between 0 and 1")
		}
	}
	if len(f.Annotations) > 8 {
		return fmt.Errorf("decision has %d annotations, limit is 8", len(f.Annotations))
	}
	for _, annotation := range f.Annotations {
		if annotation.Placement != "prepend" {
			return fmt.Errorf("annotation placement %q is invalid", annotation.Placement)
		}
		if annotation.Text == "" || len(annotation.Text) > 8192 {
			return errors.New("annotation text must be 1..8192 characters")
		}
	}
	if len(f.Evidence) > 8 {
		return fmt.Errorf("decision has %d evidence items, limit is 8", len(f.Evidence))
	}
	for _, evidence := range f.Evidence {
		if !evidenceKindPatt.MatchString(evidence.Kind) {
			return fmt.Errorf("evidence kind %q is invalid", evidence.Kind)
		}
		if len(evidence.Data) > MaxEvidenceBytes {
			return fmt.Errorf("evidence %q payload is %d bytes, limit is %d",
				evidence.Kind, len(evidence.Data), MaxEvidenceBytes)
		}
		var value any
		if err := json.Unmarshal(evidence.Data, &value); err != nil {
			return fmt.Errorf("evidence %q payload is not JSON: %w", evidence.Kind, err)
		}
	}
	return nil
}

// Validate checks a ready frame, which the gate writes after init.
func (f *ReadyFrame) Validate() error {
	if f.Protocol != Version {
		return fmt.Errorf("ready protocol is %q, want %q", f.Protocol, Version)
	}
	if f.Type != "ready" || f.ID != "init" {
		return errors.New("ready frame must carry type and id \"init\"")
	}
	if !gateNamePattern.MatchString(f.Name) {
		return fmt.Errorf("ready name %q is invalid", f.Name)
	}
	if len(f.Version) > 64 || !gateVersion.MatchString(f.Version) {
		return fmt.Errorf("ready version %q is invalid", f.Version)
	}
	if len(f.Warnings) > 8 {
		return fmt.Errorf("ready has %d warnings, limit is 8", len(f.Warnings))
	}
	for _, warning := range f.Warnings {
		if len(warning) > 1024 {
			return fmt.Errorf("ready warning is %d characters, limit is 1024", len(warning))
		}
	}
	return nil
}

// Validate checks an error frame.
func (f *ErrorFrame) Validate() error {
	if f.Protocol != Version {
		return fmt.Errorf("error protocol is %q, want %q", f.Protocol, Version)
	}
	if f.Type != "error" {
		return errors.New("error frame must carry type \"error\"")
	}
	if err := validID(f.ID); err != nil {
		return err
	}
	if !errorClassPatt.MatchString(f.Class) {
		return fmt.Errorf("error class %q is invalid", f.Class)
	}
	if len(f.Message) > 1024 {
		return fmt.Errorf("error message is %d characters, limit is 1024", len(f.Message))
	}
	return nil
}

// Validate checks a shutdown frame.
func (f *ShutdownFrame) Validate() error {
	if f.Protocol != Version {
		return fmt.Errorf("shutdown protocol is %q, want %q", f.Protocol, Version)
	}
	if f.Type != "shutdown" || f.ID != "shutdown" {
		return errors.New("shutdown frame must carry type and id \"shutdown\"")
	}
	return nil
}

// ErrorClass maps an unknown class to protocol, matching Cake's read rule.
func ErrorClass(class string) string {
	switch class {
	case "timeout", "network", "auth", "rate_limit", "transport", "malformed",
		"refusal", "config", "unsupported", "internal", "protocol":
		return class
	default:
		return "protocol"
	}
}

func validID(id string) error {
	if id == "" {
		return errors.New("frame id is required")
	}
	if len(id) > 64 {
		return fmt.Errorf("frame id is %d characters, limit is 64", len(id))
	}
	return nil
}

func nonEmptyUnique(values []string, field string) error {
	if len(values) == 0 {
		return fmt.Errorf("describe %s must be non-empty", field)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("describe %s contains an empty value", field)
		}
		if seen[value] {
			return fmt.Errorf("describe %s contains duplicate %q", field, value)
		}
		seen[value] = true
	}
	return nil
}
