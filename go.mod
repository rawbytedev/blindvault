module blindvault

go 1.25.2

require (
	github.com/awnumar/memguard v0.23.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/redis/go-redis/v9 v9.21.0
	github.com/stretchr/testify v1.11.1
	github.com/supranational/blst v0.3.16
	golang.org/x/time v0.11.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.41.0 // indirect
	go.opentelemetry.io/otel/metric v1.41.0 // indirect
	go.opentelemetry.io/otel/trace v1.41.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/dgraph-io/badger/v4 v4.8.0
	github.com/google/uuid v1.6.0
	github.com/rs/zerolog v1.34.0
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)

replace google.golang.org/grpc => github.com/grpc/grpc-go v1.80.0
