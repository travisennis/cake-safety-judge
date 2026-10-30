# AGENTS.md

Guidance for agents working in this repository. Read `README.md` first for
behavior and configuration; this file covers conventions and invariants.

## What this is

The reference external gate for Cake's `cake-gate/1` protocol. Cake owns
enforcement, context assembly, lifecycle, composition, and telemetry. This
repository owns only the command-safety decision: rubric, prompt, model
transport, strict verdict parsing, bounded recovery, verdict codes, and the
TypeSafe observation.

Cake's in-process judge has been deleted; this repository owns the command-safety
decision and is public at <https://github.com/travisennis/cake-safety-judge>.
Do not make Cake changes in a task here; the workspace rule is one task in one
subdirectory.

## Layout

- `cmd/cake-safety-judge/main.go` — CLI dispatch (`describe`, `check`, `serve`,
  `corpus`, `version`).
- `internal/protocol/` — frame types and validation.
- `internal/rubric/` — the embedded rubric and stable verdict-code vocabulary.
- `internal/judge/` — bounded, redacted prompt assembly, strict parsing,
  one-attempt recovery.
- `internal/provider/` — `chat_completions`, `responses`, fake, recorded, and
  recording transports.
- `internal/typesafe/` — bounded TypeSafe observation and calibration identity.
- `internal/calibrate/` — TypeSafe corpus calibration runner.
- `internal/gate/` — config resolution, engine, describe, serve loop, exit map.
- `internal/corpus/` — corpus loader, JSON report, and report comparison.
- `corpus/` — frozen Cake-derived corpora plus gate-owned egress coverage.
- `tests/fixtures/` — checked-in schema fixtures.
- `docs/cake-gate-1.schema.json` — checked-in contract schema.
- `bin/install`, `bin/doctor` — install and discovery checks.

## Commands

```sh
just hooks        # install the commit-msg hook (Conventional Commits)
just build        # bin/cake-safety-judge
just test         # offline Go suite; no model calls, no network
just test-race
just vet
just corpus-check # fake-provider run over every corpus
just schema-check # optional Python jsonschema validation of fixtures
just ci           # fmt-check, vet, test, corpus-check
just calibrate    # live TypeSafe calibration; spends quota, not in ci
just compare a b  # compare two corpus reports; unsafe divergence fails
just install      # go install
just doctor
```

## Invariants

- Stdout carries only `describe` or protocol frames. Diagnostics go to stderr;
  `--diagnostic` output is sensitive and bounded.
- Every serve frame is one UTF-8 JSON object on one line, at most 1 MiB. No
  pretty printing, no stdout noise.
- `describe` caches for the run. `init` runs once per process instance.
  Requests may be concurrent and responses may be out of order; match `id`.
- `shutdown` and closed stdin are graceful: stop reading, wait for in-flight
  checks, exit `0`. A protocol violation is process-fatal.
- This repository owns the rubric; Cake no longer embeds a copy. Changing it is
  a policy change that requires the corpus and new evidence, and it changes the
  TypeSafe calibration identity.
- Strict verdict parsing is a security property: one JSON object, at most one
  complete fence tagged empty or `json`, no trailing data, no repair.
- Retry exactly once, and only for a timeout, retryable transport/HTTP failure,
  undecodable 2xx envelope, or transport failure during the 2xx body read. Never
  retry a valid verdict, a refusal, or a malformed verdict.
- A failure is an `error` frame, never `abstain`. `abstain` means a deliberate
  no-opinion.
- Never read the workspace to learn about the action or resolve sandbox paths.
  The `input` frame is the evidence. A rubric file named in config is allowed.
- Gate config is strict: reject unknown keys. A misspelled safety setting must
  fail initialization, not be ignored.
- Credentials come from environment variables named by the descriptor or by
  `TYPESAFE_AI_API_KEY`; never put a credential in config, a prompt, a frame, or
  evidence.
- Evidence is metadata only. Never place command, reason, prompt, or response
  text in evidence.
- The judge packet is bounded and redacted. An unrepresentable packet fails
  closed before provider transport; never judge a partial packet.
- Cascade arms only when the effective identity matches a recorded calibration.
  An unrecorded identity stays shadow-only and emits a warning.
- The TypeSafe cutoff `0.85` is compiled. Do not make it configurable.
- The corpus files are frozen. Do not relabel a case to improve a run. A corpus
  change is a new version with a new fingerprint.
- The fake provider is an offline plumbing harness, not parity evidence. Do not
  describe a fake run as oracle agreement.

## Workflow

- `ahm` owns the task store for this repository (`.ahm/config.json` points at
  the home store). Create or select a task before implementation work.
- Use Conventional Commits; run `just hooks` once per clone to enforce the
  format. Keep the README and `docs/protocol.md` current with behavior changes.
- Run `just ci` before calling a change complete. Report exactly which checks
  ran; do not claim a live or paid run that did not happen.
- Do not pass `--model`, `--profile`, or `--reasoning-effort` to Cake, and do
  not run other coding agents without Trav's explicit permission.

## Style

- Standard library only for the binary.
- Comments explain why a constraint exists, not what the line does.
- Keep protocol handling and safety behavior explicit; prefer a small helper
  over a clever expression.
- Tests must be deterministic and offline. Use `httptest`, the fake provider, or
  the record provider; never a live provider.
