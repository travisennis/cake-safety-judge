package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return raw
}

func TestFixturesValidate(t *testing.T) {
	t.Parallel()
	if _, err := DecodeDescribe(fixture(t, "describe.json")); err != nil {
		t.Fatalf("describe fixture: %v", err)
	}
	for _, name := range []string{"init.json", "check.json", "decision_block.json", "decision_allow.json", "error.json", "shutdown.json"} {
		if _, err := Decode(fixture(t, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var ready ReadyFrame
	if err := json.Unmarshal(fixture(t, "ready.json"), &ready); err != nil {
		t.Fatalf("ready fixture: %v", err)
	}
	if err := ready.Validate(); err != nil {
		t.Fatalf("ready fixture: %v", err)
	}
}

func TestDescribeFixtureHasSchemaRequiredFields(t *testing.T) {
	t.Parallel()
	var object map[string]any
	if err := json.Unmarshal(fixture(t, "describe.json"), &object); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"protocol", "name", "version", "phases", "actions", "transports", "capabilities"} {
		if _, ok := object[field]; !ok {
			t.Fatalf("describe fixture lacks required %q", field)
		}
	}
}

func TestDecisionFixtureConditionalRequirements(t *testing.T) {
	t.Parallel()
	var object map[string]any
	if err := json.Unmarshal(fixture(t, "decision_block.json"), &object); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"protocol", "type", "id", "decision", "code", "message"} {
		if _, ok := object[field]; !ok {
			t.Fatalf("block decision lacks %q", field)
		}
	}
}
