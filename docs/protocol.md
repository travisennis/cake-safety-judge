# `cake-gate/1` implementation notes

This is the gate implementer's view of the contract. The authoritative text is
in Cake: `docs/integrations.md` (Gate protocol), `docs/configuration.md`
(Gates), `docs/security.md` (trust boundary), and
`docs/schemas/cake-gate-1.schema.json`. If this document disagrees with Cake,
Cake wins.

## Executable interface

A gate is a trusted executable. Cake invokes it with its configured `args`,
then one of:

- `describe` — print one JSON object and exit `0`.
- `serve` — run the long-lived NDJSON protocol on stdin/stdout.
- `check` — optional; Cake never uses it as a transport.

Logs and diagnostics go to stderr. Stdout carries only the describe object or
protocol frames.

## `describe`

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

- `name` matches `[a-z0-9][a-z0-9-]{0,63}`. The `[gates.<name>]` key is the
  local instance name and may differ; composition and telemetry use the
  instance name.
- `version` is `MAJOR.MINOR.PATCH` with an optional prerelease suffix.
- `phases`, `actions`, `transports`, and `capabilities` are required;
  `capabilities` may be empty.
- This gate declares only the `stdio` transport. Cake rejects a configured
  `oneshot` transport that `describe` does not list.
- `resolved-models` means the gate accepts model descriptors; `shadow` means it
  may be configured in shadow mode; `diagnostic` means it accepts
  `options.diagnostic`.

## `init`

Sent once per process instance, before any check:

```json
{
  "protocol": "cake-gate/1",
  "type": "init",
  "id": "init",
  "session": {"session_id": "9f1c", "task_id": "4b2e", "invocation_id": "01J", "cwd": "/repo"},
  "config": {"model": "judge", "rubric_file": ".cake/judge-rubric.md"},
  "models": {
    "judge": {
      "provider": "openai",
      "base_url": "https://api.example.test/v1",
      "api_type": "chat_completions",
      "model": "judge-model",
      "api_key_env": "JUDGE_API_KEY"
    }
  },
  "env": ["JUDGE_API_KEY"]
}
```

- `config` is the gate's own table, at most 64 KiB. This gate rejects unknown
  keys.
- `models` contains only environment-backed descriptors. A file-backed run
  model yields no descriptor. The reserved name `default` is the run's resolved
  model.
- `env` lists the variables Cake passes beyond its fixed base set. The gate
  reads credentials itself; no credential value crosses the protocol.
- `session` identifiers are correlation context, never authorization. None are
  required.

The gate answers:

```json
{
  "protocol": "cake-gate/1",
  "type": "ready",
  "id": "init",
  "name": "safety",
  "version": "0.1.0",
  "warnings": []
}
```

`name` and `version` must match `describe`. Warnings are bounded to eight
entries of 1,024 characters and never change a decision. An initialization
failure is an `error` frame with class `config`; Cake removes Bash for the run.

## `check`

```json
{
  "protocol": "cake-gate/1",
  "type": "check",
  "id": "01J",
  "phase": "pre_tool",
  "action": "bash.exec",
  "input": {
    "command": "git status --short",
    "cwd": "/repo",
    "reason": null,
    "repo_digest": "git repo, branch main",
    "script_evidence": []
  },
  "session": {"session_id": "9f1c", "task_id": "4b2e", "call_id": "call_1", "turn": 3},
  "options": {"diagnostic": false}
}
```

- `input.command` is the normalized command Cake will execute.
- `input.cwd` is the resolved per-call working directory. The gate never infers
  it from its own process directory.
- `input.reason` is untrusted model intent, never authorization.
- `input.repo_digest` is Cake's compact repository line and may be `null`.
- `input.script_evidence` has zero or one item, each at most 32 KiB.
- `session` is optional for a standalone check. `options.diagnostic` is true
  only for `cake bash check --diagnostic` and only for a gate declaring the
  `diagnostic` capability.

### Prompt packet bounds

The gate never sends an unbounded or partially represented packet to a
provider. The limits apply after redaction and control-character encoding.

| Field | Limit | Over limit |
| --- | ---: | --- |
| `command` | 32 KiB | `unsupported` error before transport |
| `cwd` | 4 KiB | `unsupported` error before transport |
| `repo_digest` | 1 KiB | `unsupported` error before transport |
| `reason` | 16 KiB | truncated with a marker |
| `script_evidence.path` | 4 KiB | `unsupported` error before transport |
| `script_evidence.contents` | 32 KiB | `unsupported` error before transport |
| complete user packet | 128 KiB | `unsupported` error before transport |
| effective system prompt | 64 KiB | `config` error at init |

Invalid UTF-8 in any dynamic field is a `malformed` error. Empty `command` or
`cwd` is `malformed`. The packet carries `truncated` and `redactions` markers;
credential-shaped values become `[REDACTED:<kind>]`; terminal controls become
literal `\uXXXX` text. A fixed end marker follows the JSON object, so dynamic
text cannot reshape the wrapper. Diagnostics and error messages use the same
redaction and UTF-8-safe truncation.

## Decision

```json
{
  "protocol": "cake-gate/1",
  "type": "decision",
  "id": "01J",
  "decision": "block",
  "code": "git-force-push",
  "message": "Use git push --force-with-lease instead.",
  "confidence": 0.94,
  "annotations": [],
  "short_circuit": false,
  "evidence": [
    {"kind": "attempt", "data": {"model": "judge-model", "attempt": 1, "latency_ms": 1200, "terminal_class": "verdict"}}
  ]
}
```

- `decision` is `allow`, `warn`, `block`, or `abstain`.
- `block` and `warn` require a valid `code` and a non-empty `message`.
- `allow` must omit the code (an empty string is treated as omitted).
- `confidence` is optional and, when present, finite and in `[0, 1]`.
- `annotations` is optional; only `prepend` exists. This gate emits none: Cake
  renders a warning as `NOTICE: <message>` and a block as
  `BLOCKED\n\nReason: <message>`.
- `short_circuit` is honored only for `allow` when Cake configures
  `short_circuit_on_allow`. This gate sets it on a TypeSafe cascade approval.
- `evidence` is the only gate-controlled telemetry surface. This gate emits:
  - `attempt`: `model`, `api_type`, `attempt`, `retry_delay_ms`, `latency_ms`,
    optional `status_code`, `terminal_class`, optional `usage`.
  - `typesafe_observation`: `model`, `mode`, optional `probability`, optional
    `failure_class`, `latency_ms`, optional `calibration` (the full identity),
    and `recorded` (whether the identity matches a recorded calibration).

Evidence never carries the command, reason, prompt, or response text.

## Error

```json
{
  "protocol": "cake-gate/1",
  "type": "error",
  "id": "01J",
  "class": "timeout",
  "message": "the upstream judge call exceeded its deadline"
}
```

Bounded classes: `timeout`, `network`, `auth`, `rate_limit`, `transport`,
`malformed`, `refusal`, `config`, `unsupported`, `internal`, `protocol`. Cake
treats an unknown class as `protocol`. A failure must be an error frame, never
`abstain`.

Exit classes for `cake bash check`: `timeout`, `network`, `auth`, and
`rate_limit` exit `2`; `transport`, `malformed`, `refusal`, `protocol`,
`unsupported`, and `internal` exit `1`; `config` exits `3`; a decision exits
`0`.

## Framing and lifecycle

- One UTF-8 JSON object per line, at most 1 MiB, no unescaped control
  characters, no pretty printing.
- Requests may be concurrent; Cake keeps up to eight in flight for one gate.
  Responses may arrive out of order and are matched by `id`.
- A duplicate or unknown `id`, an unknown frame type, a protocol mismatch, an
  oversized frame, stdout noise, or an early exit is process-fatal.
- On a per-check timeout, crash, or protocol failure, Cake kills the process
  group and fails the check closed unless the gate is `fail = "open"`. The next
  check starts a fresh process and repeats `init`. Two consecutive process-level
  failures disable the gate for the run.
- A successful `ready` or completed check resets the failure count.
- `shutdown` is best effort at session end. The gate waits for in-flight checks
  and exits `0`; closed stdin does the same.

## This implementation's config

```json
{
  "model": "default",
  "rubric_file": ".cake/judge-rubric.md",
  "timeout_secs": 30,
  "retry_budget_secs": 15,
  "endpoint": {
    "base_url": "http://127.0.0.1:8080/v1",
    "api_type": "chat_completions",
    "model": "local-judge",
    "api_key_env": "LOCAL_JUDGE_KEY"
  },
  "typesafe": {
    "mode": "off",
    "model": "jev-1.13.0",
    "timeout_ms": 1000
  }
}
```

- `endpoint` is the escape hatch for a keyless local model; a descriptor is the
  normal path.
- `rubric_file` is appended to the embedded rubric. Relative paths resolve from
  the gate's invocation directory, never from `input.cwd`.
- `typesafe.mode` is `off`, `shadow`, or `cascade`. The `0.85` cutoff is
  compiled and cannot be lowered by config.
- A missing model credential is a `config` initialization failure. A missing
  `TYPESAFE_AI_API_KEY` disables the observation with a warning and the judge
  still runs.

### Calibration identity

The compiled `0.85` cutoff is bound to the exact inputs it was measured
against:

- the TypeSafe model ID;
- the effective-rubric SHA-256, including any appended user rubric;
- the fixed request-schema fingerprint;
- the ordered context-schema fingerprint (`command`, `cwd`, `repo_digest`,
  `untrusted_reason`);
- the corpus version and SHA-256 prefix;
- the cutoff itself.

The identity has a stable 16-hex ID. `cascade` arms only when the identity
matches a recorded calibration. An unrecorded identity is downgraded to
`shadow` with a `ready.warnings` entry; it never fast-approves. `shadow` and
`off` do not require a record. The released binary exposes the identity through
`cake-safety-judge calibration`, the `calibration-identity` describe capability,
the opt-in diagnostic line, and `typesafe_observation` evidence. The recorded
ADR 034 calibration covers the embedded rubric at `jev-1.13.0` and corpus
`independent-v2`/`86d3d49c`.

## Safety invariants

- The gate never reports an allow it did not obtain: a provider failure is an
  error frame.
- A packet that cannot be represented within the documented bounds fails closed
  before provider transport; a partial packet is never judged.
- The gate never reads the workspace to assemble action evidence or resolve
  sandbox paths. The `input` frame and a configured rubric file are the only
  inputs.
- The gate never executes anything; it returns a decision.
- `allow` cannot widen an earlier gate's block; Cake owns composition.
