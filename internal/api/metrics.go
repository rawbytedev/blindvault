package api

import (
	"blindvault/pkg/metrics"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsCollector holds all Prometheus metrics for the service.
type MetricsCollector struct {
	// HTTP metrics
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec

	// Business metrics
	credentialIssuance    *prometheus.CounterVec
	credentialConsumption *prometheus.CounterVec

	// Storage metrics
	nullifierStoreOps *prometheus.CounterVec
}

// NewMetricsCollector creates and registers all metrics.
func NewMetricsCollector() metrics.MetricsReporter {
	m := &MetricsCollector{
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blindvault_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "blindvault_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		credentialIssuance: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blindvault_credential_issuance_total",
				Help: "Total number of credential issuance requests",
			},
			[]string{"result", "credential_class"},
		),
		credentialConsumption: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blindvault_credential_consumption_total",
				Help: "Total number of credential consumption requests",
			},
			[]string{"result", "credential_class", "epoch"},
		),
		nullifierStoreOps: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blindvault_nullifier_store_operations_total",
				Help: "Total number of nullifier store operations",
			},
			[]string{"operation", "result"},
		),
	}

	// Register all metrics with Prometheus
	prometheus.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.credentialIssuance,
		m.credentialConsumption,
		m.nullifierStoreOps,
	)

	return m
}

// MetricsHandler returns the promhttp.Handler for the /metrics endpoint.
func (m *MetricsCollector) MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// RecordHTTPRequest records an HTTP request metric.
func (m *MetricsCollector) RecordHTTPRequest(method, path string, status int, duration time.Duration) {
	m.httpRequestsTotal.WithLabelValues(method, path, strconv.Itoa(status)).Inc()
	m.httpRequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// RecordIssuance records a credential issuance attempt.
func (m *MetricsCollector) RecordIssuance(result, credentialClass string) {
	m.credentialIssuance.WithLabelValues(result, credentialClass).Inc()
}

// RecordConsumption records a credential consumption attempt.
func (m *MetricsCollector) RecordConsumption(result, credentialClass, epoch string) {
	m.credentialConsumption.WithLabelValues(result, credentialClass, epoch).Inc()
}

// RecordNullifierStore records a nullifier store operation.
func (m *MetricsCollector) RecordNullifierStore(operation, result string) {
	m.nullifierStoreOps.WithLabelValues(operation, result).Inc()
}
