# Contributing

KiloCheck treats tests as part of its public evidence contract.

## Required local gate

```bash
scripts/test-all.sh
```

This runs formatting, compilation, strict Clippy, unit and property tests, and
builds every fuzz target.

## Mutation testing

```bash
scripts/mutate.sh
```

Mutation testing currently covers `kilo-core`, where deterministic domain and
validation logic lives. A surviving non-equivalent mutant is a test failure;
add a behavioral assertion rather than excluding it. Equivalent mutants may be
excluded only with a nearby explanation.

## Fuzzing

```bash
KILO_FUZZ_RUNS=100000 scripts/fuzz-smoke.sh
```

Every parser that accepts untrusted snapshot or command data should gain a fuzz
target before release. Regression artifacts belong in the applicable fuzz
corpus and must remain small enough to review.

## Property tests

Prefer invariants over lists of examples for address spaces, prefix boundaries,
normalization, evidence independence, deterministic compilation, and policy
behavior. Keep a small set of readable examples alongside properties so failure
messages retain product meaning.
