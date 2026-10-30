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

	"github.com/travisennis/cake-safety-judge/internal/calibrate"
	"github.com/travisennis/cake-safety-judge/internal/corpus"
	"github.com/travisennis/cake-safety-judge/internal/gate"
	"github.com/travisennis/cake-safety-judge/internal/judge"
	"github.com/travisennis/cake-safety-judge/internal/protocol"
	"github.com/travisennis/cake-safety-judge/internal/provider"
	"github.com/travisennis/cake-safety-judge/internal/typesafe"
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
	case "calibration":
		return runCalibration(args[1:], stdout, stderr)
	case "calibrate":
		return runCalibrate(args[1:], stdout, stderr)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
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
  cake-safety-judge calibration [flags]
  cake-safety-judge calibrate [flags]
  cake-safety-judge compare [flags]
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

type calibrationOutput struct {
	Protocol string            `json:"protocol"`
	Type     string            `json:"type"`
	Identity typesafe.Identity `json:"identity"`
	Recorded bool              `json:"recorded"`
	Record   *typesafe.Record  `json:"record,omitempty"`
}

func runCalibration(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("calibration", flag.ContinueOnError)
	flags.SetOutput(stderr)
	model := flags.String("model", typesafe.RecordedModel, "TypeSafe model ID")
	rubricFile := flags.String("rubric-file", "", "append user rubric guidance from this file")
	requireRecorded := flags.Bool("require-recorded", false, "exit 1 when the identity has no recorded calibration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	systemPrompt, err := gate.LoadRubricPrompt(*rubricFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "calibration: %v\n", err)
		return 3
	}
	identity := typesafe.IdentityFor(*model, systemPrompt)
	record, ok := typesafe.RecordedFor(identity)
	output := calibrationOutput{
		Protocol: protocol.Version,
		Type:     "calibration",
		Identity: identity,
		Recorded: ok,
	}
	if ok {
		output.Record = &record
	}
	if code := encodeIndent(stdout, output); code != 0 {
		return code
	}
	if *requireRecorded && !ok {
		return 1
	}
	return 0
}

func runCalibrate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	corpusPath := flags.String("corpus", "corpus/independent-v2.jsonl", "JSONL corpus path")
	reportPath := flags.String("report", "", "write the JSON report here (default stdout)")
	model := flags.String("model", typesafe.RecordedModel, "TypeSafe model ID")
	rubricFile := flags.String("rubric-file", "", "append user rubric guidance from this file")
	repetitions := flags.Int("repetitions", 1, "observations per case")
	timeoutMS := flags.Int("timeout-ms", 1000, "TypeSafe observation deadline")
	endpoint := flags.String("endpoint", "", "TypeSafe endpoint override")
	apiKeyEnv := flags.String("api-key-env", typesafe.APIKeyEnv, "environment variable holding the TypeSafe key")
	maxCases := flags.Int("max-cases", 0, "stop after this many scored cases (0 = all)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cases, err := corpus.Load(*corpusPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "calibrate: %v\n", err)
		return 2
	}
	systemPrompt, err := gate.LoadRubricPrompt(*rubricFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "calibrate: %v\n", err)
		return 3
	}
	apiKey := os.Getenv(*apiKeyEnv)
	if strings.TrimSpace(apiKey) == "" {
		_, _ = fmt.Fprintf(stderr, "calibrate: %s is not set; this is a live TypeSafe run\n", *apiKeyEnv)
		return 3
	}
	client := typesafe.New(apiKey, *model, time.Duration(*timeoutMS)*time.Millisecond, systemPrompt)
	if *endpoint != "" {
		client.Endpoint = *endpoint
	}
	identity := typesafe.IdentityFor(*model, systemPrompt)
	report := calibrate.Run(context.Background(), cases, client, identity, calibrate.Config{
		Repetitions: *repetitions,
		Cutoff:      typesafe.Cutoff,
		MaxCases:    *maxCases,
	})

	writer := stdout
	var file *os.File
	if *reportPath != "" {
		file, err = os.Create(*reportPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "calibrate: %v\n", err)
			return 2
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	if code := encodeIndent(writer, report); code != 0 {
		return code
	}
	_, _ = fmt.Fprintf(stderr,
		"calibration identity=%s corpus=%s cases=%d scored=%d observations=%d unsafe=%d high_risk=%d failures=%d observational_any=%d/%d p50=%.0fms p95=%.0fms passes=%t\n",
		identity.ID, *corpusPath, report.Cases, report.Scored, report.Observations,
		report.UnsafeApprovals, report.HighRiskApprovals, report.Failures,
		report.ObservationalAny, report.ObservationalCases, report.LatencyP50MS, report.LatencyP95MS, report.Passes)
	if !report.Passes {
		return 1
	}
	return 0
}

func runCorpus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("corpus", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("corpus", "", "JSONL corpus path")
	reportPath := flags.String("report", "", "write the JSON report here (default stdout)")
	providerName := flags.String("provider", "fake", "fake, record, or live")
	recordPath := flags.String("record", "", "JSONL recorded provider outcomes")
	recordOut := flags.String("record-out", "", "write live provider outcomes as JSONL")
	descriptorPath := flags.String("descriptor-file", "", "JSON file with models and config, as in an init frame")
	modelName := flags.String("model", "", "descriptor name to use")
	baseURL := flags.String("base-url", "", "endpoint base URL for a direct live run")
	apiType := flags.String("api-type", "chat_completions", "chat_completions or responses")
	modelID := flags.String("model-name", "", "model name for a direct live run")
	apiKeyEnv := flags.String("api-key-env", "", "environment variable holding the API key")
	rubricFile := flags.String("rubric-file", "", "append user rubric guidance from this file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "corpus: --corpus is required")
		return 2
	}
	if *recordOut != "" && *providerName != "live" {
		_, _ = fmt.Fprintln(stderr, "corpus: --record-out requires --provider live")
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
	var client *judge.Client
	useExpected := false
	switch *providerName {
	case "fake":
		client = judge.New(&provider.Fake{}, gate.DefaultDescriptor("offline-corpus"), 30*time.Second, 0)
		useExpected = true
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
		client = judge.New(recorder, gate.DefaultDescriptor("offline-corpus"), 30*time.Second, 0)
	case "live":
		init, err := liveInit(*descriptorPath, *modelName, *baseURL, *apiType, *modelID, *apiKeyEnv, *rubricFile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
			return 3
		}
		engine, err := gate.BuildWith(init, gate.Dependencies{})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
			return 3
		}
		client = engine.Judge
		if *recordOut != "" {
			file, err := os.Create(*recordOut)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "corpus: %v\n", err)
				return 2
			}
			defer func() { _ = file.Close() }()
			client.Provider = provider.NewRecorder(client.Provider, file)
		}
		_, _ = fmt.Fprintln(stderr, "corpus: live provider; this run spends provider quota")
	default:
		_, _ = fmt.Fprintf(stderr, "corpus: unknown provider %q (use fake, record, or live)\n", *providerName)
		return 2
	}

	confidence := 0.99
	evaluator := func(c corpus.Case) (judge.Verdict, []judge.Attempt, error) {
		request := judge.Request{
			Command:    c.Command,
			Cwd:        c.Cwd,
			Reason:     c.Reason,
			RepoDigest: c.RepoDigest,
		}
		if useExpected {
			request.Expected = &provider.Expected{
				Decision:   c.ExpectedDecision,
				Code:       c.ExpectedCode,
				Message:    "offline corpus label",
				Confidence: &confidence,
			}
		}
		verdict, attempts, err := client.Evaluate(context.Background(), request)
		return verdict, attempts, err
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

func runCompare(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baselinePath := flags.String("baseline", "", "baseline corpus report")
	candidatePath := flags.String("candidate", "", "candidate corpus report")
	reportPath := flags.String("report", "", "write the JSON comparison here (default stdout)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *baselinePath == "" || *candidatePath == "" {
		_, _ = fmt.Fprintln(stderr, "compare: --baseline and --candidate are required")
		return 2
	}
	baseline, err := loadReport(*baselinePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "compare: %v\n", err)
		return 2
	}
	candidate, err := loadReport(*candidatePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "compare: %v\n", err)
		return 2
	}
	comparison := corpus.Compare(baseline, candidate)
	writer := stdout
	var file *os.File
	if *reportPath != "" {
		file, err = os.Create(*reportPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "compare: %v\n", err)
			return 2
		}
		defer func() { _ = file.Close() }()
		writer = file
	}
	if code := encodeIndent(writer, comparison); code != 0 {
		return code
	}
	_, _ = fmt.Fprintf(stderr,
		"compare baseline=%s candidate=%s compared=%d agreement=%d missing=%d corpus_mismatch=%t code_changes=%d unsafe=%d errors=%d passes=%t\n",
		*baselinePath, *candidatePath, comparison.Compared, comparison.Agreement,
		comparison.Missing, comparison.CorpusMismatch, comparison.CodeChanges,
		len(comparison.UnsafeDivergences), comparison.CandidateErrors, comparison.Passes)
	if !comparison.Passes {
		for _, divergence := range comparison.UnsafeDivergences {
			_, _ = fmt.Fprintf(stderr, "UNSAFE line=%d command=%q baseline=%s/%s candidate=%s/%s\n",
				divergence.Line, divergence.Command, divergence.BaselineDecision,
				divergence.BaselineCode, divergence.CandidateDecision, divergence.CandidateCode)
		}
		return 1
	}
	return 0
}

func loadReport(path string) (corpus.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return corpus.Report{}, err
	}
	var report corpus.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return corpus.Report{}, fmt.Errorf("%s: %w", path, err)
	}
	return report, nil
}

func liveInit(descriptorPath, modelName, baseURL, apiType, modelID, apiKeyEnv, rubricFile string) (protocol.InitFrame, error) {
	init := protocol.InitFrame{
		Protocol: protocol.Version,
		Type:     "init",
		ID:       "init",
		Session:  protocol.InitSession{Cwd: "."},
	}
	switch {
	case descriptorPath != "":
		raw, err := os.ReadFile(descriptorPath)
		if err != nil {
			return init, err
		}
		var file descriptorFile
		if err := json.Unmarshal(raw, &file); err != nil {
			return init, fmt.Errorf("descriptor file: %w", err)
		}
		init.Models = file.Models
		config := map[string]any{}
		if len(file.Config) > 0 {
			if err := json.Unmarshal(file.Config, &config); err != nil {
				return init, fmt.Errorf("descriptor file config: %w", err)
			}
		}
		if rubricFile != "" {
			config["rubric_file"] = rubricFile
		}
		if modelName != "" {
			config["model"] = modelName
		}
		if len(config) > 0 {
			init.Config = mustJSON(config)
		} else {
			init.Config = file.Config
		}
	case baseURL != "":
		if modelID == "" {
			return init, fmt.Errorf("--model-name is required with --base-url")
		}
		endpoint := map[string]any{
			"base_url": baseURL,
			"api_type": apiType,
			"model":    modelID,
		}
		if apiKeyEnv != "" {
			endpoint["api_key_env"] = apiKeyEnv
		}
		config := map[string]any{"endpoint": endpoint}
		if rubricFile != "" {
			config["rubric_file"] = rubricFile
		}
		init.Config = mustJSON(config)
	default:
		return init, fmt.Errorf("live provider requires --descriptor-file or --base-url")
	}
	return init, nil
}

func mustJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
