package protocol

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func validDescribe() Describe {
	return Describe{
		Protocol:     Version,
		Name:         "safety",
		Version:      "0.1.0",
		Phases:       []string{"pre_tool"},
		Actions:      []string{"bash.exec"},
		Transports:   []string{"stdio"},
		Capabilities: []string{"resolved-models"},
	}
}

func TestDescribeValidate(t *testing.T) {
	t.Parallel()
	describe := validDescribe()
	if err := describe.Validate(); err != nil {
		t.Fatalf("valid describe rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Describe)
		want   string
	}{
		{"protocol", func(d *Describe) { d.Protocol = "cake-gate/2" }, "protocol"},
		{"name", func(d *Describe) { d.Name = "Safety!" }, "name"},
		{"version", func(d *Describe) { d.Version = "1.0" }, "version"},
		{"phases empty", func(d *Describe) { d.Phases = nil }, "phases"},
		{"phase value", func(d *Describe) { d.Phases = []string{"mid_tool"} }, "phase"},
		{"actions empty", func(d *Describe) { d.Actions = nil }, "actions"},
		{"action value", func(d *Describe) { d.Actions = []string{"edit.write"} }, "action"},
		{"transports empty", func(d *Describe) { d.Transports = nil }, "transports"},
		{"no stdio", func(d *Describe) { d.Transports = []string{"oneshot"} }, "stdio"},
		{"capabilities missing", func(d *Describe) { d.Capabilities = nil }, "capabilities"},
		{"capability value", func(d *Describe) { d.Capabilities = []string{"Bad"} }, "capability"},
		{"duplicate action", func(d *Describe) { d.Actions = []string{"bash.exec", "bash.exec"} }, "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			describe := validDescribe()
			tc.mutate(&describe)
			err := describe.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestInitValidate(t *testing.T) {
	t.Parallel()
	valid := InitFrame{
		Protocol: Version,
		Type:     "init",
		ID:       "init",
		Session:  InitSession{Cwd: "/work/cake"},
		Models: map[string]ModelDescriptor{
			"default": {
				BaseURL:   "https://api.example.test/v1",
				APIType:   "chat_completions",
				Model:     "judge",
				APIKeyEnv: "JUDGE_API_KEY",
			},
		},
		Env: []string{"JUDGE_API_KEY"},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid init rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*InitFrame)
	}{
		{"missing cwd", func(f *InitFrame) { f.Session.Cwd = "" }},
		{"wrong type", func(f *InitFrame) { f.Type = "check" }},
		{"wrong id", func(f *InitFrame) { f.ID = "other" }},
		{"too many env", func(f *InitFrame) {
			f.Env = make([]string, 33)
			for i := range f.Env {
				f.Env[i] = "V" + string(rune('A'+i))
			}
		}},
		{"bad env", func(f *InitFrame) { f.Env = []string{"1BAD"} }},
		{"duplicate env", func(f *InitFrame) { f.Env = []string{"A", "A"} }},
		{"bad model type", func(f *InitFrame) {
			f.Models["default"] = ModelDescriptor{BaseURL: "x", APIType: "grpc", Model: "m", APIKeyEnv: "K"}
		}},
		{"missing base url", func(f *InitFrame) {
			f.Models["default"] = ModelDescriptor{APIType: "responses", Model: "m", APIKeyEnv: "K"}
		}},
		{"config not object", func(f *InitFrame) { f.Config = json.RawMessage(`[]`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			frame := valid
			frame.Models = map[string]ModelDescriptor{"default": valid.Models["default"]}
			tc.mutate(&frame)
			if err := frame.Validate(); err == nil {
				t.Fatal("invalid init accepted")
			}
		})
	}
}

func TestCheckValidate(t *testing.T) {
	t.Parallel()
	valid := CheckFrame{
		Protocol: Version,
		Type:     "check",
		ID:       "call-1",
		Phase:    "pre_tool",
		Action:   "bash.exec",
		Input: BashInput{
			Command:        "git status --short",
			Cwd:            "/work/cake",
			ScriptEvidence: []ScriptEvidence{},
		},
		Options: &CheckOptions{},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid check rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*CheckFrame)
	}{
		{"missing id", func(f *CheckFrame) { f.ID = "" }},
		{"long id", func(f *CheckFrame) { f.ID = strings.Repeat("a", 65) }},
		{"bad phase", func(f *CheckFrame) { f.Phase = "post_tool" }},
		{"bad action", func(f *CheckFrame) { f.Action = "edit.write" }},
		{"missing cwd", func(f *CheckFrame) { f.Input.Cwd = "" }},
		{"missing evidence", func(f *CheckFrame) { f.Input.ScriptEvidence = nil }},
		{"two evidence", func(f *CheckFrame) {
			f.Input.ScriptEvidence = []ScriptEvidence{{Path: "a", Contents: "x"}, {Path: "b", Contents: "y"}}
		}},
		{"oversized evidence", func(f *CheckFrame) {
			f.Input.ScriptEvidence = []ScriptEvidence{{Path: "a", Contents: strings.Repeat("x", 32769)}}
		}},
		{"missing options", func(f *CheckFrame) { f.Options = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			frame := valid
			frame.Input.ScriptEvidence = []ScriptEvidence{}
			tc.mutate(&frame)
			if err := frame.Validate(); err == nil {
				t.Fatal("invalid check accepted")
			}
		})
	}
}

func TestDecisionValidate(t *testing.T) {
	t.Parallel()
	code := "git-force-push"
	confidence := 0.9
	validBlock := DecisionFrame{
		Protocol:   Version,
		Type:       "decision",
		ID:         "call-1",
		Decision:   "block",
		Code:       &code,
		Message:    "Use --force-with-lease.",
		Confidence: &confidence,
	}
	if err := validBlock.Validate(); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*DecisionFrame)
	}{
		{"bad decision", func(f *DecisionFrame) { f.Decision = "deny" }},
		{"block no code", func(f *DecisionFrame) { f.Code = nil }},
		{"block no message", func(f *DecisionFrame) { f.Message = "" }},
		{"bad code", func(f *DecisionFrame) { value := "Bad Code"; f.Code = &value }},
		{"confidence high", func(f *DecisionFrame) { value := 1.5; f.Confidence = &value }},
		{"confidence nan", func(f *DecisionFrame) {
			value := math.NaN()
			f.Confidence = &value
		}},
		{"too many annotations", func(f *DecisionFrame) {
			f.Annotations = make([]Annotation, 9)
		}},
		{"bad annotation", func(f *DecisionFrame) {
			f.Annotations = []Annotation{{Placement: "append", Text: "x"}}
		}},
		{"too many evidence", func(f *DecisionFrame) {
			f.Evidence = make([]Evidence, 9)
		}},
		{"bad evidence kind", func(f *DecisionFrame) {
			f.Evidence = []Evidence{{Kind: "Bad Kind", Data: json.RawMessage(`{}`)}}
		}},
		{"oversized evidence", func(f *DecisionFrame) {
			value := strings.Repeat("x", MaxEvidenceBytes+1)
			f.Evidence = []Evidence{{Kind: "attempt", Data: json.RawMessage(`"` + value + `"`)}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			frame := validBlock
			tc.mutate(&frame)
			if err := frame.Validate(); err == nil {
				t.Fatal("invalid decision accepted")
			}
		})
	}
	allowCode := ""
	allow := DecisionFrame{
		Protocol: Version, Type: "decision", ID: "call-1", Decision: "allow",
		Code: &allowCode, Message: "safe",
	}
	if err := allow.Validate(); err != nil {
		t.Fatalf("allow with empty code rejected: %v", err)
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()
	valid := `{"protocol":"cake-gate/1","type":"shutdown","id":"shutdown"}`
	if _, err := Decode([]byte(valid)); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	for _, raw := range []string{
		`{"type":""}`,
		`{"type":"unknown"}`,
		`not json`,
		`{"protocol":"cake-gate/1","type":"check"}`,
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatalf("decoded invalid frame %s", raw)
		}
	}
	if _, err := Decode([]byte(strings.Repeat("x", MaxFrameBytes+1))); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestErrorClass(t *testing.T) {
	t.Parallel()
	if got := ErrorClass("crash"); got != "protocol" {
		t.Fatalf("unknown class = %q, want protocol", got)
	}
	if got := ErrorClass("timeout"); got != "timeout" {
		t.Fatalf("known class = %q, want timeout", got)
	}
}
