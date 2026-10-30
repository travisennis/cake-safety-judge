package gate

import "github.com/travisennis/cake-safety-judge/internal/protocol"

// Version is the gate product version reported by describe and ready.
const Version = "0.1.0"

// Describe returns the gate's declared coverage.
func Describe() protocol.Describe {
	return protocol.Describe{
		Protocol:     protocol.Version,
		Name:         "safety",
		Version:      Version,
		Phases:       []string{"pre_tool"},
		Actions:      []string{"bash.exec"},
		Transports:   []string{"stdio"},
		Capabilities: []string{"resolved-models", "shadow", "diagnostic", "calibration-identity"},
	}
}
