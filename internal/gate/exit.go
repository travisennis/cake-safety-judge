package gate

// ExitCodeForClass maps a cake-gate/1 error class to cake's documented exit
// classes for `cake bash check`. A decision, abstention, or override is 0.
func ExitCodeForClass(class string) int {
	switch class {
	case "timeout", "network", "auth", "rate_limit":
		return 2
	case "config":
		return 3
	case "transport", "malformed", "refusal", "protocol", "unsupported", "internal":
		return 1
	default:
		return 1
	}
}
