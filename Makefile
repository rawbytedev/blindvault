.PHONY: build test-client docker-build docker-up docker-down docker-test clean

build:
	go build -o ./bin/blindvault ./cmd/server

test-client:
	go build -o ./bin/testclient ./cmd/testclient

docker-build:
	docker compose -f docker/docker-compose.yml build

docker-up:
	docker compose -f docker/docker-compose.yml up -d
	@echo "Waiting for service to be ready..."
	@until curl -s http://localhost:8080/health | grep -q "ok"; do \
		echo "Waiting..."; \
		sleep 2; \
	done
	@echo "Service is ready"

docker-down:
	docker compose -f docker/docker-compose.yml down

docker-test: test-client docker-up
	@echo "Running end-to-end test..."
	@BLINDVAULT_URL=http://localhost:8080 ./bin/testclient
	
docker-logs:
	docker compose -f docker/docker-compose.yml logs -f

clean:
	rm -rf ./bin
	docker compose -f docker/docker-compose.yml down -v

# Full CI pipeline
ci: docker-build docker-test docker-down