# Benchmarks

The corpus harness is the entry point for offline evidence:

```sh
just corpus-check
```

It writes `reports/commands.json` and `reports/independent-v2.json` with counts
by decision, code, tag, and case, plus every mismatch. A fake-provider pass
proves plumbing only; a recorded-provider pass is offline parity evidence.

Slice 3 adds the live comparison beside Cake's in-process judge:

- differential decisions over the frozen corpus and live sessions;
- unsafe-divergence classification and zero-tolerance counting;
- latency percentiles and token cost per decision;
- TypeSafe cascade coverage at the compiled `0.85` cutoff;
- the shadow report that slice 4 needs before enforcement.

No SLO thresholds or live results are recorded here yet. A paid run requires
Trav's explicit authorization and the same cost caps Cake's judge benchmark
uses; do not start one from this directory without that instruction.
