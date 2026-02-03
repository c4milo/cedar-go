.PHONY: test bench bench-compare bench-baseline lint

# Run all tests
test:
	go test -race ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem -count=6 ./...

# Generate new baseline (run this before making changes)
bench-baseline:
	go test -bench=. -benchmem -count=6 ./... > benchmarks/baseline.txt

# Compare current performance against baseline
# Requires: go install golang.org/x/perf/cmd/benchstat@latest
bench-compare:
	@if [ ! -f benchmarks/baseline.txt ]; then \
		echo "Error: benchmarks/baseline.txt not found. Run 'make bench-baseline' first."; \
		exit 1; \
	fi
	go test -bench=. -benchmem -count=6 ./... > benchmarks/current.txt
	benchstat benchmarks/baseline.txt benchmarks/current.txt

# Run linters
lint:
	golangci-lint run ./...

# Run all checks (tests, benchmarks comparison, lint)
check: test lint bench-compare
