package metrics

import (
	"net/http"
	"time"
)

// MetricsReporter defines the interface for reporting metrics in BlindVault. Implementations of this interface can be used to record various metrics related to HTTP requests, credential issuance and consumption, and nullifier storage.
type MetricsReporter interface {
	// RecordHTTPRequest records the HTTP request metrics.
	RecordHTTPRequest(method, path string, status int, duration time.Duration)
	// RecordIssuance records the issuance of a credential.
	RecordIssuance(result, credentialClass string)
	// RecordConsumption records the consumption of a credential.
	RecordConsumption(result, credentialClass, epoch string)
	// RecordNullifierStore records the storage of a nullifier.
	RecordNullifierStore(operation, result string)
	RecordRevocation(result, credentialClass string)      
    RecordUnrevocation(result, credentialClass string)
	// metricsHandler returns an HTTP handler that serves the metrics endpoint.
	MetricsHandler() http.Handler
}
