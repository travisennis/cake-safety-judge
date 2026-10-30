# cake-safety-judge

The reference external gate for [Cake](../cake)'s `cake-gate/1` protocol. It is a
standalone Go binary that owns the command-safety policy Cake used to run
in-process: the rubric, the model call, strict verdict parsing, bounded
recovery, the stable verdict-code vocabulary, and the optional TypeSafe
cascade.

Status: Cake's in-process judge has been deleted; this gate is the only
production `bash.exec` policy path. The gate is built, installed, and green on
the offline suite, but it is not enabled in Trav's live settings yet. Prompt
hardening, egress coverage, TypeSafe calibration, and the recorded/live
comparison harness are in place; quality measurement and enablement remain
open.

The repository is public at <https://github.com/travisennis/cake-safety-judge>.

## Why a separate process

Cake owns enforcement, trusted context assembly, process lifecycle,
composition, and telemetry. This gate owns only the decision. It never reads
the workspace to learn about an action; it evaluates the `input` frame Cake
sends and returns `allow`, `warn`, `block`, or `abstain`. Gate executables are
trusted configuration, like hooks and toolbox tools.

The authoritative contract lives in Cake:

- `cake/docs/integrations.md` — Gate protocol, composition, lifecycle, telemetry
- `cake/docs/configuration.md` — `[gates]` settings and precedence
- `cake/docs/security.md` — trust boundary and the no-gate rule
- `cake/docs/schemas/cake-gate-1.schema.json` — frame schema
- `cake/docs/adr/049-external-policy-gates-with-the-cake-gate-1-protocol.md`
- `cake/docs/adr/018-llm-judge-command-gate.md` — strict verdict parsing
- `cake/docs/adr/020-bounded-llm-judge-recovery.md` — one recovery attempt

`docs/protocol.md` in this repository is the implementer's view; if it
disagrees with Cake, Cake wins.

## Build and test

```sh
just hooks          # install the commit-msg hook (Conventional Commits)
just build          # bin/cake-safety-judge
just test           # offline Go suite, no model calls
just test-race
just vet
just corpus-check   # fake-provider run over every corpus
just ci             # fmt-check + vet + test + corpus-check
```

Requirements: Go 1.27+. The binary uses the standard library only.

## Install

```sh
just install        # ~/bin/cake-safety-judge (override with BIN_DIR)
just doctor         # run describe and report whether Cake can find it
```

Cake selects the gate named `safety` when `[tools.bash].gates` is absent and
runs `cake-safety-judge` from `PATH`; `just install` puts it there. `cake gates
list` reports whether the pipeline is active or explicitly bypassed.

## Commands

### `describe`

Prints the cached declaration Cake validates before any work:

```json
{
  "protocol": "cake-gate/1",
  "name": "safety",
  "version": "0.1.0",
  "phases": ["pre_tool"],
  "actions": ["bash.exec"],
  "transports": ["stdio"],
  "capabilities": ["resolved-models", "shadow", "diagnostic", "calibration-identity"]
}
```

### `check`

A human and offline mode; Cake never uses it as a transport.

```sh
cake-safety-judge check --json -- 'git status --short'
cake-safety-judge check --json \
  --base-url https://api.example.test/v1 \
  --model-name judge-model \
  --api-key-env JUDGE_API_KEY \
  -- 'git push --force'
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--json` | Print one `cake-gate/1` decision or error frame |
| `--descriptor-file` | JSON with `models` and `config`, as in an init frame |
| `--base-url`, `--api-type`, `--model-name`, `--api-key-env` | Direct endpoint |
| `--rubric-file` | Append user rubric guidance |
| `--timeout`, `--retry-budget` | Direct-endpoint timeout and recovery allowance |
| `--cwd`, `--reason`, `--repo-digest` | Action evidence |
| `--diagnostic` | Print the effective prompts and decision to stderr (sensitive) |
| `--fake` | Deterministic offline provider; never a parity claim |
| `--record <file>` | Replay recorded provider outcomes |

Exit codes match Cake's documented class mapping: a decision (including a
deliberate block) exits `0`; `timeout`, `network`, `auth`, and `rate_limit`
exit `2`; `transport`, `malformed`, `refusal`, `protocol`, `unsupported`, and
`internal` exit `1`; `config` exits `3`.

### `serve`

The Cake transport. It reads newline-delimited JSON on stdin and writes frames
on stdout. Diagnostics and any sensitive `--diagnostic` output go to stderr.

Lifecycle:

1. Cake sends one `init`; the gate validates config and resolves a model.
2. The gate answers `ready` (or an `error` with class `config`).
3. Cake sends `check` frames; the gate answers each with a matching `id`,
   possibly out of order, up to eight in flight.
4. Cake sends `shutdown` or closes stdin; the gate waits for in-flight checks
   and exits `0`.

Every frame is one UTF-8 JSON object, at most 1 MiB, no pretty printing.

### `corpus`

Runs the frozen corpus through the same judge path and writes a JSON report
with counts by decision, code, tag, and case, plus every mismatch.

```sh
cake-safety-judge corpus -corpus corpus/commands.jsonl -report reports/commands.json
cake-safety-judge corpus -corpus corpus/independent-v2.jsonl -report reports/independent-v2.json
cake-safety-judge corpus -corpus corpus/egress-v1.jsonl -report reports/egress-v1.json
cake-safety-judge corpus -corpus corpus/commands.jsonl \
  -provider record -record corpus/recorded.jsonl -report reports/recorded.json
```

`-provider fake` echoes the corpus label as a well-formed verdict. It proves
request assembly, strict parsing, code validation, decision mapping, evidence,
and framing; it does **not** prove model parity. Use `-provider record` with
real judge output for offline replay. `-provider live` runs the real judge and
requires `-descriptor-file` or `-base-url`; add `-record-out <file>` to capture
the run for replay. Live runs spend provider quota and are never part of CI.

### `compare`

Compares two corpus reports and fails on an unsafe divergence: a case the
baseline blocked and the candidate allowed. Missing cases and candidate errors
also fail. False blocks and code changes are reported but are not safety
failures.

```sh
cake-safety-judge compare -baseline reports/recorded.json \
  -candidate reports/live.json -report reports/comparison.json
```

### `calibration`

Prints the TypeSafe calibration identity for the embedded rubric or a
`--rubric-file`: model, effective-rubric fingerprint, request and context schema
fingerprints, corpus version/fingerprint, cutoff, and whether a recorded
calibration matches. `--require-recorded` exits `1` on a mismatch.

```sh
cake-safety-judge calibration
cake-safety-judge calibration --rubric-file .cake/judge-rubric.md --require-recorded
```

### `calibrate`

Measures the TypeSafe fast path over a corpus and writes probabilities, unsafe
approvals, observational coverage, latency, and token usage. This is a live,
paid run and is not part of CI.

```sh
cake-safety-judge calibrate -corpus corpus/independent-v2.jsonl \
  -report reports/typesafe-calibration.json
```

`-repetitions 5` matches the recorded ADR 034 protocol; the default is one
observation per case for a smoke run. `-max-cases` limits a run.

## Configuration

Cake passes `[gates.safety.config]` as JSON in `init.config`. The gate rejects
unknown keys so a typo cannot silently disable a safety setting.

```json
{
  "model": "default",
  "rubric_file": ".cake/judge-rubric.md",
  "timeout_secs": 30,
  "retry_budget_secs": 15,
  "typesafe": {
    "mode": "off",
    "model": "jev-1.13.0",
    "timeout_ms": 1000
  }
}
```

| Key | Meaning |
| --- | --- |
| `model` | Which `init.models` descriptor to use. Empty prefers `default`, then a single descriptor. |
| `rubric_file` | Appends user guidance to the embedded rubric. Relative paths resolve from the gate's invocation directory, never from `input.cwd`. |
| `timeout_secs` | Per-attempt provider deadline. Default `30`. |
| `retry_budget_secs` | Extra allowance for the one recovery attempt. Default `15`; `0` disables recovery. |
| `typesafe.mode` | `off` (default), `shadow`, or `cascade`. |
| `typesafe.model` | TypeSafe model name. Default `jev-1.13.0`. |
| `typesafe.timeout_ms` | TypeSafe observation deadline. Default `1000`. |
| `endpoint` | Explicit endpoint for a keyless local model or a direct check. |

`endpoint` fields: `base_url`, `api_type` (`chat_completions` or `responses`),
`model`, optional `api_key_env`, `http_referer`, `x_title`, `temperature`,
`top_p`, `max_output_tokens`, `reasoning_effort`, `reasoning_summary`, and
`reasoning_max_tokens`.

Credentials never cross the protocol. The gate reads the descriptor's
`api_key_env` from its own environment (Cake passes only the declared names) and
reads `TYPESAFE_AI_API_KEY` for TypeSafe. A missing model credential fails
initialization with class `config`; a missing TypeSafe credential disables the
observation with a `ready.warnings` entry and the judge still runs.

### TypeSafe

Under `cascade`, a clean TypeSafe observation at or above the compiled `0.85`
cutoff approves the command without a judge call and sets `short_circuit`; every
failure or lower probability falls back to the judge. Under `shadow`, the
observation is recorded as `typesafe_observation` evidence and never changes
the decision. The cutoff is a constant, not a setting.

Cascade is armed only when the effective identity matches a recorded
calibration: the pinned model, effective-rubric fingerprint, request and
context schema fingerprints, and corpus version/fingerprint. A custom
`rubric_file` changes the rubric fingerprint and therefore requires a new
measurement. An unrecorded identity is downgraded to `shadow` with a
`ready.warnings` entry; it never fast-approves. The current identity and the
ADR 034 record are visible from `cake-safety-judge calibration` and in every
`typesafe_observation` evidence entry. See `docs/calibration.md` for the full
identity, evidence, caveat, and re-measurement protocol.

## Verdict behavior

The gate ports Cake's judge behavior:

- The system prompt is the embedded rubric, optionally followed by
  user-supplied guidance.
- The user prompt carries `command`, `cwd`, `repo_digest`, `reason`, and
  `script_evidence` as JSON, framed as untrusted input and terminated by a
  fixed end marker.
- The packet is bounded per field and as a whole. Oversized commands, paths,
  or script evidence fail closed before provider transport; a long reason is
  truncated and marked. Credential-shaped values are replaced with typed
  `[REDACTED:...]` markers, terminal controls are encoded, and the packet
  records redactions and truncations. Diagnostics apply the same redaction.
- A verdict must be exactly one JSON object, optionally in one complete fence
  tagged empty or `json`; no trailing data, no repair.
- `block` and `warn` require a known code. Only `rg-replace-footgun` may warn.
  `allow` must omit the code.
- The operation has one bounded recovery attempt for a timeout, retryable
  transport/HTTP failure, undecodable 2xx envelope, or transport failure during
  the body read. A valid verdict, refusal, or malformed verdict is never
  retried.
- A refusal or any failure becomes an `error` frame, never `abstain`; Cake fails
  closed.

Evidence is metadata only. This gate emits `attempt` entries (model, attempt
number, latency, status, terminal class, usage) and `typesafe_observation`
entries (model, mode, probability or failure class, latency, calibration
identity, and whether that identity is recorded). It never places the command,
reason, prompt, or response text in evidence.

## Layout

```text
cmd/cake-safety-judge/   CLI dispatch
internal/protocol/       cake-gate/1 types and validation
internal/rubric/         embedded rubric and verdict codes
internal/judge/          prompt, strict parsing, bounded recovery
internal/provider/       chat_completions, responses, fake, record, recorder
internal/typesafe/       bounded observation, calibration identity, cascade input
internal/calibrate/      TypeSafe corpus calibration runner
internal/gate/           config, engine, describe, serve, exit mapping
internal/corpus/         corpus loader, evaluator, comparison, JSON report
corpus/                  frozen decision corpora, egress coverage, provenance
tests/fixtures/          schema fixtures
bench/                   recorded/live comparison commands
docs/                    protocol notes, schema copy, egress audit, calibration
```

## Roadmap

- Done: external gate, Cake extraction, prompt bounds, egress coverage, TypeSafe
  calibration identity, and the recorded/live comparison harness.
- Open: live quality measurement, TypeSafe re-measurement for any custom rubric,
  and enablement in the live settings.
- Follow-up: keep Cake's ADR 034 text aligned with this gate's recorded identity
  if the two diverge.

## License

MIT. See `LICENSE`.
