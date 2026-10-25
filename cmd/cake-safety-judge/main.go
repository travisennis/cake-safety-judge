// Command cake-safety-judge is the reference cake-gate/1 safety gate.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/travisennis/cake-safety-judge/internal/corpus"
	"github.com/travisennis/cake-safety-judge/internal/gate"
	"github.com/travisennis/cake-safety-judge/internal/judge"
	"github.com/travisennis/cake-safety-judge/internal/protocol"
	"github.com/travisennis/cake-safety-judge/internal/provider"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "describe":
		describe := gate.Describe()
		if err := describe.Validate(); err != nil {
			_, _ = fmt.Fprintf(stderr, "describe: %v\n", err)
			return 1
		}
		return encode(stdout, describe)
	case "serve":
		if err := gate.Serve(stdin, stdout, stderr, gate.Build); err != nil {
			_, _ = fmt.Fprintf(stderr, "serve: %v\n", err)
			return 2
		}
		return 0
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "corpus":
		return runCorpus(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "cake-safety-judge %s\n", gate.Version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown subcommand %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(writer io.Writer) {
	_, _ = fmt.Fprint(writer, `cake-safety-judge - cake-gate/1 command-safety gate

Usage:
  cake-safety-judge describe
  cake-safety-judge serve
  cake-safety-judge check [flags] -- <command>
  cake-safety-judge corpus [flags]
  cake-safety-judge version

Serve is the Cake transport. Check and corpus are human/offline modes.
`)
}

func encode(writer io.Writer, value any) int {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}

func encodeIndent(writer io.Writer, value any) int {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}

type descriptorFile struct {
	Models map[string]protocol.ModelDescriptor `json:"models"`
	Config json.RawMessage                     `json:"config"`
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOut := flags.Bool("json", false, "print one protocol document")
	cwd := flags.String("cwd", "", "working directory for the check (default: process cwd)")
	reason := flags.String("reason", "", "untrusted model-supplied reason")
	repoDigest := flags.String("repo-digest", "", "compact repository digest")
	rubricFile := flags.String("rubric-file", "", "append user rubric guidance from this file")
	timeout := flags.Duration("timeout", 30*time.Second, "per-attempt provider timeout")
	retryBudget := flags.Duration("retry-budget", 15*time.Second, "recovery allowance")
	diagnostic := flags.Bool("diagnostic", false, "print sensitive diagnostic detail to stderr")
	descriptorPath := flags.String("descriptor-file", "", "JSON file with models and config, as in an init frame")
	modelName := flags.String("model", "", "descriptor name to use")
	baseURL := flags.String("base-url", "", "endpoint base URL for a direct check")
	apiType := flags.String("api-type", "chat_completions", "chat_completions or responses")
	modelID := flags.String("model-name", "", "model name for a direct check")
	apiKeyEnv := flags.String("api-key-env", "", "environment variable holding the API key")
	fake := flags.Bool("fake", false, "use the deterministic offline provider")
	fakeVerdict := flags.String("fake-verdict", "allow", "fake verdict: allow, warn, or block")
	fakeCode := flags.String("fake-code", "", "fake verdict code")
	fakeMessage := flags.String("fake-message", "", "fake verdict message")
	recordPath := flags.String("record", "", "replay provider outcomes from a JSONL record file")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	command := strings.TrimSpace(strings.Join(flags.Args(), " "))
	if command == "" {
		_, _ = fmt.Fprintln(stderr, "check requires a command after --")
		return 2
	}
	checkCwd := *cwd
	if checkCwd == "" {
		processCwd, err := os.Getwd()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "check: %v\n", err)
			return 3
		}
		checkCwd = processCwd
	}

	init := protocol.InitFrame{
		Protocol: protocol.Version,
		Type:     "init",
		ID:       "init",
		Session:  protocol.InitSession{Cwd: checkCwd},
	}
	deps := gate.Dependencies{}

	switch {
	case *descriptorPath != "":
		raw, err := os.ReadFile(*descriptorPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "check: %v\n", err)
			return 3
		}
		var file descriptorFile
		if err := json.Unmarshal(raw, &file); err != nil {
			_, _ = fmt.Fprintf(stderr, "check: descriptor file: %v\n", err)
			return 3
		}
		init.Models = file.Models
		init.Config = file.Config
		if *modelName != "" {
			config := map[string]any{"model": *modelName}
			if len(file.Config) > 0 {
				var existing map[string]any
				if err := json.Unmarshal(file.Config, &existing); err == nil {
					for key, value := range existing {
						config[key] = value
					}
				}
			}
			init.Config = mustJSON(config)
		}
	case *fake:
		code := *fakeCode
		if code == "" {
			switch *fakeVerdict {
			case "block":
				code = "unknown-destructive"
			case "warn":
				code = "rg-replace-footgun"
			}
		}
		confidence := 0.99
		deps.Provider = &provider.Fake{
			Decision:   *fakeVerdict,
			Code:       code,
			Message:    *fakeMessage,
			Confidence: &confidence,
		}
		init.Models = map[string]protocol.ModelDescriptor{}
		init.Config = mustJSON(map[string]any{"endpoint": map[string]any{
			"base_url": "offline://fake",
			"api_type": "chat_completions",
			"model":    "offline",
		}})
	case *recordPath != "":
		recorder, err := provider.LoadRecordFile(*recordPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "check: %v\n", err)
			return 3
		}
		deps.Provider = recorder
		init.Models = map[string]protocol.ModelDescriptor{}
		init.Config = mustJSON(map[string]any{"endpoint": map[string]any{
			"base_url": "offline://record",
			"api_type": "chat_completions",
			"model":    "recorded",
		}})
	case *baseURL != "":
		if *modelID == "" {
			_, _ = fmt.Fprintln(stderr, "check: --model-name is required with --base-url")
			return 3
		}
		endpoint := map[string]any{
			"base_url": *baseURL,
			"api_type": *apiType,
			"model":    *modelID,
		}
		if *apiKeyEnv != "" {
			endpoint["api_key_env"] = *apiKeyEnv
		}
		config := map[string]any{
			"endpoint":          endpoint,
			"timeout_secs":      timeout.Seconds(),
			"retry_budget_secs": retryBudget.Seconds(),
		}
		if *rubricFile != "" {
			config["rubric_file"] = *rubricFile
		}
		init.Config = mustJSON(config)
		init.Models = map[string]protocol.ModelDescriptor{}
	default:
		_, _ = fmt.Fprintln(stderr, "check requires --descriptor-file, --base-url, --record, or --fake")
		return 3
	}

	engine, err := gate.BuildWith(init, deps)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "check: %v\n", err)
		return 3
	}
	if *diagnostic {
		engine.SetDiagnosticWriter(stderr)
	}

	check := protocol.CheckFrame{
		Protocol: protocol.Version,
		Type:     "check",
		ID:       "check",
		Phase:    "pre_tool",
		Action:   "bash.exec",
		Input: protocol.BashInput{
			Command:        command,
			Cwd:            checkCwd,
			ScriptEvidence: []protocol.ScriptEvidence{},
		},
		Options: &protocol.CheckOptions{Diagnostic: *diagnostic},
	}
	if *reason != "" {
		check.Input.Reason = reason
	}
	if *repoDigest != "" {
		check.Input.RepoDigest = repoDigest
	}

	started := time.Now()
	decision, failure := engine.Evaluate(context.Background(), check)
	elapsed := time.Since(started).Milliseconds()
	if failure != nil {
		if *jsonOut {
			encode(stdout, failure)
		} else {
			_, _ = fmt.Fprintf(stdout, "error (%s): %s\n", failure.Class, failure.Message)
		}
		return gate.ExitCodeForClass(failure.Class)
	}
	if *jsonOut {
		return encode(stdout, decision)
	}
	code := ""
	if decision.Code != nil {
		code = " code=" + *decision.Code
	}
	confidence := ""
	if decision.Confidence != nil {
		confidence = fmt.Sprintf(" confidence=%.2f", *decision.Confidence)
	}
	_, _ = fmt.Fprintf(stdout, "%s:%s%s latency_ms=%d %s\n",
		decision.Decision, code, confidence, elapsed, decision.Message)
	return 0
}

func runCorpus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("corpus", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("corpus", "", "JSONL corpus path")
	reportPath := flags.String("report", "", "write the JSON report here (default stdout)")
	providerName := flags.String("provider", "fake", "fake or record")
	recordPath := flags.String("record", "", "JSONL recorded provider outcomes")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "corpus: --corpus is required")
		return 2
	}
	cases, err := corpus.Load(*path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
		return 2
	}
	fingerprint, err := corpus.Fingerprint(*path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
		return 2
	}
	var p provider.Provider
	switch *providerName {
	case "fake":
		p = &provider.Fake{}
	case "record":
		if *recordPath == "" {
			_, _ = fmt.Fprintln(stderr, "corpus: --record is required with --provider record")
			return 2
		}
		recorder, err := provider.LoadRecordFile(*recordPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
			return 2
		}
		p = recorder
	default:
		_, _ = fmt.Fprintf(stderr, "corpus: unknown provider %q (use fake or record)\n", *providerName)
		return 2
	}

	client := judge.New(p, gate.DefaultDescriptor("offline-corpus"), 30*time.Second, 0)
	confidence := 0.99
	evaluator := func(c corpus.Case) (judge.Verdict, error) {
		request := judge.Request{
			Command:    c.Command,
			Cwd:        c.Cwd,
			Reason:     c.Reason,
			RepoDigest: c.RepoDigest,
			Expected: &provider.Expected{
				Decision:   c.ExpectedDecision,
				Code:       c.ExpectedCode,
				Message:    "offline corpus label",
				Confidence: &confidence,
			},
		}
		verdict, _, err := client.Evaluate(context.Background(), request)
		return verdict, err
	}

	report := corpus.Run(cases, evaluator, *path, *providerName, fingerprint)
	writer := stdout
	var file *os.File
	if *reportPath != "" {
		file, err = os.Create(*reportPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
			return 2
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	if code := encodeIndent(writer, report); code != 0 {
		return code
	}
	_, _ = fmt.Fprintf(stderr,
		"corpus=%s provider=%s fingerprint=%s cases=%d scored=%d skipped=%d passed=%d failed=%d\n",
		*path, *providerName, fingerprint, report.Cases, report.Scored, report.Skipped,
		report.Scored-len(report.Mismatches), len(report.Mismatches))
	if !report.Passes {
		for _, mismatch := range report.Mismatches {
			_, _ = fmt.Fprintf(stderr, "MISMATCH line=%d command=%q expected=%s/%s actual=%s/%s error=%s\n",
				mismatch.Line, mismatch.Command, mismatch.ExpectedDecision, mismatch.ExpectedCode,
				mismatch.ActualDecision, mismatch.ActualCode, mismatch.Error)
		}
		return 1
	}
	return 0
}

func mustJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
