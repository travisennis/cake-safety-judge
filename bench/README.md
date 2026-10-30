# Benchmarks and comparison

The corpus harness is the entry point for decision evidence. The fake-provider
run proves plumbing only; a recorded or live judge run is the quality evidence.

## Offline plumbing

```sh
just corpus-check
```

This runs every corpus through the fake provider and writes
`reports/commands.json`, `reports/independent-v2.json`, and
`reports/egress-v1.json`. The fake provider echoes each row's label, so a pass
proves request assembly, strict parsing, code validation, decision mapping,
latency/usage plumbing, and framing. It is **not** model parity.

## Recorded / live comparison

A live run spends provider quota. Use a descriptor file that Cake already
resolves, or a direct endpoint:

```sh
# Live judge over a corpus; capture each provider outcome for replay.
cake-safety-judge corpus -provider live \
  -descriptor-file /path/to/descriptor.json \
  -corpus corpus/independent-v2.jsonl \
  -report reports/live.json \
  -record-out reports/live-recorded.jsonl

# Replay the same outcomes offline.
cake-safety-judge corpus -provider record \
  -record reports/live-recorded.jsonl \
  -corpus corpus/independent-v2.jsonl \
  -report reports/recorded.json

# Differential: fails on a baseline block that the candidate allowed.
cake-safety-judge compare \
  -baseline reports/recorded.json \
  -candidate reports/live.json \
  -report reports/comparison.json
```

`compare` matches cases by corpus line. It fails on missing cases, candidate
errors, and unsafe divergences (baseline `block` -> candidate `allow`). False
blocks and code changes are reported but are not safety failures. Candidate
latency percentiles and token totals are in the report.

The baseline can be a recorded report from an earlier gate build or a live
report. There is no surviving in-process oracle to compare against: Cake
deleted it in the extraction. The corpus labels are the fixed reference, and a
recorded report preserves a prior gate run.

## TypeSafe calibration

The TypeSafe fast path has its own harness:

```sh
# Current identity and whether it is recorded.
cake-safety-judge calibration

# Live measurement; spends TypeSafe quota. -repetitions 5 matches ADR 034.
cake-safety-judge calibrate -corpus corpus/independent-v2.jsonl \
  -repetitions 5 -report reports/typesafe-calibration.json
```

`calibrate` records per-case probabilities, unsafe approvals (any repetition at
or above `0.85` on a blocked case), high-risk approvals, observational coverage
(any/all repetitions), the recommended cutoff, latency, and token usage. It
exits `1` when the report has an unsafe approval or an observation failure.

## Limits

- No live result is recorded in this repository yet. A paid run requires
  Trav's explicit authorization and the same cost caps Cake's judge benchmark
  uses; do not start one from this directory without that instruction.
- The corpus is constructed and over-samples dangerous commands. A zero-unsafe
  result is a bound on this corpus, not a production rate.
- The TypeSafe calibration is bound to the model, effective rubric, request and
  context schema, corpus version/fingerprint, and cutoff. Any change is a new
  identity and needs a new measurement before cascade can arm.
