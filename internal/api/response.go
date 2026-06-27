// Package api provides HTTP response helpers and error formatting for BlindVault.
package api

import (
	"blindvault/pkg/logger"
	"context"
	"encoding/json"
	"net/http"
)

// respondJSON writes a JSON response with the given status code.
func (s *Server) respondJSON(ctx context.Context, w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If we can't encode, we're in a bad state. Log and fallback.
		logger.Error(ctx).Err(err).Msg("failed to encode JSON response")
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// respondError writes a standard error response.
func (s *Server) respondError(ctx context.Context, w http.ResponseWriter, status int, msg string, details ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := ErrorResponse{
		Error: msg,
		Code:  status,
	}
	if len(details) > 0 && details[0] != "" {
		resp.Details = details[0]
	}

	// Add request ID to response header for correlation
	if reqID := w.Header().Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error(ctx).Err(err).Msg("failed to encode error response")
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
