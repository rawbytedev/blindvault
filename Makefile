.PHONY: build test-client docker-build docker-up docker-down docker-test clean

COMPOSE ?= docker-compose.yml

build:
	go build -o ./bin/blindvault ./cmd/server

test-client:
	go build -o ./bin/testclient ./cmd/testclient

docker-build:
	docker compose -f $(COMPOSE) build

docker-up:
	docker compose -f $(COMPOSE) up -d
	@echo "Waiting for service to be ready..."
	@for i in $$(seq 1 30); do \
		if curl -sf http://localhost:8080/health >/dev/null 2>&1; then \
			echo "Service is ready"; \
			exit 0; \
		fi; \
		echo "Waiting..."; \
		sleep 2; \
	done; \
	echo "Service failed to become ready"; \
	docker compose -f $(COMPOSE) logs; \
	exit 1

docker-down:
	docker compose -f $(COMPOSE) down

docker-test: test-client docker-up
	@echo "Running end-to-end test..."
	@BLINDVAULT_URL=http://localhost:8080 ./bin/testclient
	
docker-logs:
	docker compose -f $(COMPOSE) logs -f

clean:
	rm -rf ./bin
	docker compose -f $(COMPOSE) down -v

# Full CI pipeline
ci: docker-build docker-test docker-down