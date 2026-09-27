// Package api provides HTTP response helpers and error formatting for BlindVault.
package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rawbytedev/blindvault/pkg/apperr"
	"github.com/rawbytedev/blindvault/pkg/logger"
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
func (s *Server) respondErr(ctx context.Context, w http.ResponseWriter, err error, op string) {
	code := apperr.CodeOf(err)
	status := code.HTTPStatus()

	if status >= 500 {
		// Log full detail server-side.
		logger.Error(ctx).Err(err).Str("op", op).Msg("server error")
		// Return generic message to client.
		s.respondError(ctx, w, status, http.StatusText(status))
		return
	}

	// 4xx: message is about the client's input, safe to surface.
	logger.Warn(ctx).Err(err).Str("op", op).Msg("client error")
	s.respondError(ctx, w, status, err.Error())
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
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error(ctx).Err(err).Msg("failed to encode error response")
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
