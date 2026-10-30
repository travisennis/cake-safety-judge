set positional-arguments

default:
    just --list

# Install this clone's git hooks: commit messages must be Conventional Commits.
hooks:
    git config core.hooksPath .githooks
    @echo "Installed .githooks (commit-msg)."

# Build the gate binary into bin/.
build:
    mkdir -p bin
    go build -trimpath -o bin/cake-safety-judge ./cmd/cake-safety-judge

# Run the offline suite. No model calls, no network.
test:
    go test ./...

test-race:
    go test -race ./...

fmt:
    gofmt -w cmd internal

fmt-check:
    test -z "$(gofmt -l cmd internal)"

vet:
    go vet ./...

# Prove the gate plumbing over both frozen corpora with the fake provider.
corpus-check: build
    mkdir -p reports
    ./bin/cake-safety-judge corpus -corpus corpus/commands.jsonl -report reports/commands.json
    ./bin/cake-safety-judge corpus -corpus corpus/independent-v2.jsonl -report reports/independent-v2.json
    ./bin/cake-safety-judge corpus -corpus corpus/egress-v1.jsonl -report reports/egress-v1.json

# Validate the checked-in fixtures against the cake-gate/1 schema when the
# Python jsonschema module is available; prints a skip otherwise.
schema-check:
    python3 scripts/validate_fixtures.py

ci: fmt-check vet test corpus-check

# Live TypeSafe calibration over the gold corpus. Spends quota; not part of ci.
calibrate: build
    ./bin/cake-safety-judge calibrate -corpus corpus/independent-v2.jsonl -repetitions 5 -report reports/typesafe-calibration.json

# Compare two corpus reports. Usage: just compare baseline.json candidate.json
compare baseline candidate: build
    ./bin/cake-safety-judge compare -baseline {{baseline}} -candidate {{candidate}} -report reports/comparison.json

# Install into ~/bin by default (BIN_DIR overrides). Cake selects the bare
# name from PATH; ~/bin is already on this workspace's PATH.
install:
    ./bin/install

# Run the installed binary's describe and check Cake discovery.
doctor: build
    ./bin/doctor
