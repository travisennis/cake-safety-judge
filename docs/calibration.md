# TypeSafe calibration identity

The `0.85` fast-approval cutoff is compiled, not configurable. It is only
meaningful for the exact inputs it was measured against, so the gate binds it to
an identity and refuses to arm cascade for an unmeasured combination.

## Identity

The identity is computed from:

- the TypeSafe model ID (`jev-1.13.0` by default);
- the SHA-256 of the effective rubric, including any appended `rubric_file`;
- the fixed request-schema fingerprint (`typesafe-eligible-v1`);
- the ordered context-schema fingerprint (`command`, `cwd`, `repo_digest`,
  `untrusted_reason`);
- the corpus version and SHA-256 prefix (`independent-v2` / `86d3d49c`);
- the cutoff (`0.85`, stored as `float64(float32(0.85))`).

The 16-hex identity ID is a SHA-256 of those fields. The default identity is
`2d6bbbd5f9910793`.

`cake-safety-judge calibration` prints the identity, whether a recorded
calibration matches, and the record. `--rubric-file` computes the identity for a
custom rubric; `--require-recorded` exits `1` on a mismatch.

## Recorded calibration

The current record is Cake ADR 034 run `1790024080`, measured on 2026-09-22
against the shipped request text after issue #613:

| Field | Value |
| --- | --- |
| Model | `jev-1.13.0` |
| Rubric fingerprint | `0542d704...cb813f4` |
| Request schema | `typesafe-eligible-v1`, `ca4bf6a8...867503` |
| Context schema | `bash-input-v1`, `bd2c9fe3...b286c5` |
| Corpus | `independent-v2`, `86d3d49c` |
| Cutoff | `0.85` |
| Repetitions | 5 |
| Unsafe approvals | 0 |
| High-risk approvals | 0 |
| Blocked observations | 440 from 88 distinct block cases |
| Observational coverage | 218/250 (87.2%) tuning; 73/85 (85.9%) held-out |
| Recommended cutoff | `0.83` (one grid step above the worst blocked observation) |

The gate's request text and rubric are pinned by fingerprint tests. The
TypeSafe request uses the same field order, the same fixed question and
interpretation, and no HTML escaping, matching Cake's `serde_json` output. A
change to any of those constants changes the identity and requires a new
measurement.

## Arming and refusal

- `cascade` arms only when `RecordedFor(identity)` succeeds.
- An unrecorded identity is downgraded to `shadow` with a `ready.warnings` entry.
  The judge still runs; the fast path does not.
- `shadow` and `off` do not require a record.
- A custom `rubric_file` changes the rubric fingerprint, so cascade with custom
  guidance needs its own measurement.

## Sampling caveat

The corpus is constructed and over-samples dangerous commands. Zero unsafe
approvals over 88 distinct block cases is a rule-of-three 95% upper bound of
about 3.4%, not a production rate. Repetitions do not tighten that bound.

## Re-measurement cadence

Re-measure whenever any identity component changes: the TypeSafe model, the
effective rubric, the request or context schema, the corpus, or the cutoff.
A different cutoff is a new decision with new evidence, not a setting.

```sh
# Smoke run (one observation per case).
cake-safety-judge calibrate -corpus corpus/independent-v2.jsonl \
  -max-cases 20 -report reports/typesafe-smoke.json

# Full recorded protocol (five repetitions; spends quota).
cake-safety-judge calibrate -corpus corpus/independent-v2.jsonl \
  -repetitions 5 -report reports/typesafe-calibration.json
```

The report records per-case probabilities, unsafe approvals (any repetition at
or above the cutoff on a blocked case), high-risk approvals, observational
coverage, the recommended cutoff, latency, and token usage. A live run requires
`TYPESAFE_AI_API_KEY` and explicit authorization.
