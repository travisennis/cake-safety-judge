# cake-safety-judge

The reference external gate for [Cake](../cake)'s `cake-gate/1` protocol. It is a
standalone Go binary that owns the command-safety policy Cake used to run
in-process: the rubric, the model call, strict verdict parsing, bounded
recovery, the stable verdict-code vocabulary, and the optional TypeSafe
cascade.

Status: slice 2 of the `cake-gate` initiative. The gate is built and tested
offline; it is not yet the default in Cake. Slice 3 runs it in shadow beside
the in-process judge, and slice 4 makes it the default when installed.

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
just corpus-check   # fake-provider run over both frozen corpora
just ci             # fmt-check + vet + test + corpus-check
```

Requirements: Go 1.27+. The binary uses the standard library only.

## Install

```sh
just install        # ~/bin/cake-safety-judge (override with BIN_DIR)
just doctor         # run describe and report whether Cake can find it
```

Cake auto-detects `cake-safety-judge` on `PATH` only after slice 4. Until then,
`check` and `corpus` are the usable surfaces.

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
  "capabilities": ["resolved-models", "shadow", "diagnostic"]
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
cake-safety-judge corpus -corpus corpus/commands.jsonl \
  -provider record -record corpus/recorded.jsonl -report reports/recorded.json
```

`-provider fake` echoes the corpus label as a well-formed verdict. It proves
request assembly, strict parsing, code validation, decision mapping, evidence,
and framing; it does **not** prove model parity. Use `-provider record` with
real judge output for offline parity evidence. The paid live comparison against
Cake's in-process oracle is a separate authorized run.

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

## Verdict behavior

The gate ports Cake's judge behavior:

- The system prompt is Cake's `judge_rubric.md`, embedded byte-for-byte.
- The user prompt carries `command`, `cwd`, `repo_digest`, `reason`, and
  `script_evidence` as JSON, framed as untrusted input.
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
entries (model, mode, probability or failure class, latency). It never places
the command, reason, prompt, or response text in evidence.

## Layout

```text
cmd/cake-safety-judge/   CLI dispatch
internal/protocol/       cake-gate/1 types and validation
internal/rubric/         embedded rubric and verdict codes
internal/judge/          prompt, strict parsing, bounded recovery
internal/provider/       chat_completions, responses, fake, record
internal/typesafe/       bounded observation and cascade input
internal/gate/           config, engine, describe, serve, exit mapping
internal/corpus/         corpus loader, evaluator, JSON report
corpus/                  frozen decision corpora and provenance
tests/fixtures/          schema fixtures
bench/                   benchmark notes (SLO work is slice 3)
docs/                    implementer protocol notes and schema copy
```

## Roadmap

- Slice 2 (this repository): build the gate, port rubric/corpus, offline tests.
- Slice 3: run it in shadow beside the in-process judge and measure divergence,
  latency, and cost on live sessions plus the corpus.
- Slice 4: make it the default when installed, add compatibility aliases.
- Slice 5: delete the judge internals from Cake and delegate `bash check`.

## License

MIT. See `LICENSE`.
