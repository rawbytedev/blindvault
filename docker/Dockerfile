# docker/Dockerfile
# Build stage
FROM golang:1.25.2-alpine AS builder

# Install build dependencies for BLST (CGO)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the binary (CGO_ENABLED=1 is required for BLST)
RUN CGO_ENABLED=1 GOOS=linux go build -o /blindvault ./cmd/server

# bluid test client
RUN CGO_ENABLED=1 GOOS=linux go build -o /testclient ./cmd/testclient

# Runtime stage
FROM alpine:latest

# Install runtime dependencies (ca-certificates for HTTPS, libc6-compat for musl CGO support)
RUN apk add --no-cache ca-certificates libc6-compat

# Create a non-root user for security
RUN adduser -D -u 1000 blindvault

WORKDIR /app

# Copy binary from builder
COPY --from=builder /blindvault /app/blindvault
COPY --from=builder /testclient /app/testclient

# Copy default config (optional, can be overridden)
COPY configs/config.yaml /app/configs/config.yaml

# Change ownership to non-root user
RUN chown -R blindvault:blindvault /app

USER blindvault

EXPOSE 8080

ENTRYPOINT ["/app/blindvault"]
CMD ["-config", "/app/configs/config.yaml"]