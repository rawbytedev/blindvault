package api

import (
	"blindvault/pkg/logger"
	"encoding/json"
	"net/http"
	"strings"
)

func statusIssue(err error) (int, string) {
	if err != nil {
		// Map known errors to appropriate status codes
		switch {
		case strings.Contains(err.Error(), "invalid blinded_message hex"):
			return http.StatusBadRequest, "invalid blinded message hex"
		case strings.Contains(err.Error(), "invalid blinded_message point"):
			return http.StatusBadRequest, "invalid blinded message point"
		case strings.Contains(err.Error(), "master seed error"):
			// This is a server‑side config issue, treat as 500
			return http.StatusInternalServerError, "server configuration error"
		default:
			return http.StatusInternalServerError, "issuance failed"
		}
	}
	return http.StatusOK, "success"
}

// statusConsume maps known consume-side errors to HTTP status codes and client messages.
func statusComsume(err error) (int, string) {
	if err != nil {
		// Map known errors to appropriate status codes
		switch {
		case strings.Contains(err.Error(), "unsupported key_epoch"):
			return http.StatusBadRequest, "unsupported key_epoch"
		case strings.Contains(err.Error(), "invalid signature"):
			return http.StatusBadRequest, "invalid signature"
		case strings.Contains(err.Error(), "invalid witness"):
			return http.StatusBadRequest, "invalid witness"
		case strings.Contains(err.Error(), "already redeemed"):
			return http.StatusConflict, "credential already redeemed"
		case strings.Contains(err.Error(), "master seed error"):
			// Server-side config issue
			return http.StatusInternalServerError, "server configuration error"
		default:
			return http.StatusInternalServerError, "consumption failed"
		}
	}
	return http.StatusOK, "success"
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn(ctx).Err(err).Msg("invalid issue request")
		s.metrics.RecordIssuance("failure", "unknown")
		s.respondError(ctx, w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.BlindedMessage == "" || req.CredentialClass == "" {
		s.metrics.RecordIssuance("failure", req.CredentialClass)
		s.respondError(ctx, w, http.StatusBadRequest, "missing required fields")
		return
	}

	result, err := s.credentialService.Issue(ctx, req.BlindedMessage, req.CredentialClass)
	if err != nil {
		statusCode, message := statusIssue(err)
		s.metrics.RecordIssuance("failure", req.CredentialClass)
		s.respondError(ctx, w, statusCode, message)
		return
	}
	s.metrics.RecordIssuance("success", req.CredentialClass)
	s.respondJSON(ctx, w, http.StatusOK, IssueResponse{
		BlindSignature: result.BlindSignature,
		PublicKey:      result.PublicKey,
		KeyEpoch:       result.KeyEpoch,
		Proof: DLEQProof{
			R1: result.Proof.R1,
			R2: result.Proof.R2,
			S:  result.Proof.S,
			C:  result.Proof.C,
		},
	})
}

func (s *Server) handleConsume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req ConsumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn(ctx).Err(err).Msg("invalid consume request")
		s.metrics.RecordConsumption("failure", "unknown", "unknown")
		s.respondError(ctx, w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UnblindedSignature == "" || req.Witness == "" || req.CredentialClass == "" || req.KeyEpoch == "" {
		s.metrics.RecordConsumption("failure", req.CredentialClass, req.KeyEpoch)
		s.respondError(ctx, w, http.StatusBadRequest, "missing required fields")
		return
	}

	result, err := s.credentialService.Consume(ctx, req.UnblindedSignature, req.Witness, req.CredentialClass, req.KeyEpoch)
	if err != nil {
		statusCode, message := statusComsume(err)
		s.metrics.RecordConsumption("failure", req.CredentialClass, req.KeyEpoch)
		s.respondError(ctx, w, statusCode, message)
		return
	}

	if !result.Valid {
		s.metrics.RecordConsumption("replay", req.CredentialClass, req.KeyEpoch)
		s.respondJSON(ctx, w, http.StatusConflict, ConsumeResponse{
			Valid: false,
			Error: result.Error,
		})
		return
	}
	s.metrics.RecordConsumption("success", req.CredentialClass, req.KeyEpoch)
	s.respondJSON(ctx, w, http.StatusOK, ConsumeResponse{Valid: true})
}

// handleHealth handles GET /health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.respondJSON(ctx, w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	s.metrics.MetricsHandler().ServeHTTP(w, r)
}
