package metrics

import (
	"net/http"
	"time"
)

type MetricsReporter interface {
	RecordHTTPRequest(method, path string, status int, duration time.Duration)
	RecordIssuance(result, credentialClass string)
	RecordConsumption(result, credentialClass, epoch string)
	RecordNullifierStore(operation, result string)
	MetricsHandler() http.Handler
}
