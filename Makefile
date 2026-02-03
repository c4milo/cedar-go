corpus-tests-json-schemas.tar.gz: corpus-tests.tar.gz
	@echo "Generating JSON schemas from Cedar schemas..."
	@rm -rf /tmp/corpus-tests /tmp/corpus-tests-json-schemas
	@mkdir -p /tmp/corpus-tests-json-schemas
	@tar -xzf corpus-tests.tar.gz -C /tmp/
	@for schema in /tmp/corpus-tests/*.cedarschema; do \
		basename=$$(basename $$schema .cedarschema); \
		echo "Converting $$basename.cedarschema..."; \
		cedar translate-schema --direction cedar-to-json --schema "$$schema" > "/tmp/corpus-tests-json-schemas/$$basename.cedarschema.json" 2>&1; \
	done
	@cd /tmp && tar -czf corpus-tests-json-schemas.tar.gz corpus-tests-json-schemas/
	@mv /tmp/corpus-tests-json-schemas.tar.gz .
	@rm -rf /tmp/corpus-tests /tmp/corpus-tests-json-schemas
	@echo "Done! Created corpus-tests-json-schemas.tar.gz"

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
