FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates build-base git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_CFLAGS="-O2 -D__BLST_PORTABLE__"
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/blindvault ./cmd/server
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/testclient ./cmd/testclient

FROM alpine:latest

RUN apk add --no-cache ca-certificates libc6-compat
RUN adduser -D -u 1000 blindvault

WORKDIR /app

COPY --from=builder /out/blindvault /app/blindvault
COPY --from=builder /out/testclient /app/testclient
COPY configs /app/configs

RUN chown -R blindvault:blindvault /app
USER blindvault

EXPOSE 8080
CMD ["/app/blindvault", "--config", "/app/configs/config.yaml"]