package service

import "testing"

func SetupTestEnv(t *testing.T) map[string]string {
	env := make(map[string]string)
	env["BLINDVAULT_MODE"] = "development"
	env["ACTIVE_EPOCH"] = "2026-01"
	env["SUPPORTED_EPOCHS"] = "2026-01,2026-02"
	env["DST"] = "BCIS-TEST"
	env["AUTH_SECRET"] = "secret"
	env["JWT_ISSUER"] = "blindvault"
	env["JWT_AUDIENCE"] = "api"
	env["LISTEN_ADDR"] = "127.0.0.1:8000"
	env["REDIS_ADDR"] = "localhost:6379"
	env["REDIS_PASSWORD"] = "redispassword"
	env["REDIS_DB"] = "15"
	env["REDIS_EXPIRATION"] = "3600"
	env["REVOCATION_REDIS_ADDR"] = "localhost:6379"
	env["REVOCATION_REDIS_PASSWORD"] = "revocationpassword"
	env["REVOCATION_REDIS_DB"] = "1"
	env["USE_MEMORY_STORE"] = "false"
	env["USE_DEMO"] = "false"
	env["RATE_LIMIT_BURST"] = "10"
	env["RATE_LIMIT_REQUESTS"] = "100"
	env["MAX_CLIENTS"] = "1000"
	env["RATE_LIMIT_BURST"] = "10"
	env["RATE_LIMIT_REQUESTS"] = "100"
	env["MAX_CLIENTS"] = "1000"
	for k, v := range env {
		t.Setenv(k, v)
	}
	return env
}
