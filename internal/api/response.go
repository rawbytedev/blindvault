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

// getContext is a helper to get the request context from the current goroutine.
// Since this is called from response helpers (which don't have context directly),
// we need to rely on the fact that we're inside a request handler.
// For better design, consider passing context to these helpers, but for simplicity,
// we'll use context.Background() and rely on the middleware to set the request_id.
func (s *Server) getContext() context.Context {
	// In production, you'd pass the context through the request.
	// This fallback is safe.
	return context.Background()
}
