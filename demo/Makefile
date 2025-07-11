.PHONY: all certs run test clean shell logs help

# Default target
all: run

# Generate certificates
certs:
	@echo "Generating certificates..."
	@./scripts/generate-certs.sh

# Run the demo server locally (no Docker)
run-local: certs
	@echo "Starting SCTX demo server..."
	@cd .. && go run ./demo/main.go

# Run everything with Docker Compose
run:
	@echo "Starting SCTX demo with Docker Compose..."
	@docker-compose up --build

# Run automated tests
test:
	@echo "Running security test scenarios..."
	@docker-compose up --build --exit-code-from test-runner

# Run server and open interactive shell
shell:
	@echo "Starting services with interactive shell..."
	@docker-compose --profile interactive up -d
	@docker-compose exec test-client /bin/sh

# View logs
logs:
	@docker-compose logs -f sctx-demo

# Clean up
clean:
	@echo "Cleaning up..."
	@docker-compose down -v
	@rm -rf certs/*
	@rm -f demo-signing-*.pem

# Show help
help:
	@echo "SCTX Demo Makefile targets:"
	@echo "  make certs      - Generate test certificates using minica"
	@echo "  make run-local  - Run demo server locally (requires Go)"
	@echo "  make run        - Run full demo with Docker Compose"
	@echo "  make test       - Run automated security tests"
	@echo "  make shell      - Start services and open interactive shell"
	@echo "  make logs       - View server logs"
	@echo "  make clean      - Clean up containers and certificates"
	@echo ""
	@echo "Quick start:"
	@echo "  make test      # Run all security tests automatically"
	@echo "  make shell     # Interactive testing environment"