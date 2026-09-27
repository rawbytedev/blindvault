package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rawbytedev/blindvault/internal/auth"
	"github.com/rawbytedev/blindvault/internal/service"
	"github.com/rawbytedev/blindvault/pkg/apperr"
	"github.com/rawbytedev/blindvault/pkg/logger"
)

// handleIssue handles POST /issue requests.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var req IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn(ctx).Err(err).Msg("invalid issue request")
		s.metrics.RecordIssuance("failure", "unknown")
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid request"), "issue")
		return
	}

	if err := req.Validate(); err != nil {
		logger.Warn(ctx).Err(err).Msg("invalid issue request data")
		s.metrics.RecordIssuance("failure", req.CredentialClass)
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid request"), "issue")
		return
	}

	result, err := s.credentialService.Issue(ctx, req.BlindedMessage, req.CredentialClass)
	if err != nil {
		s.metrics.RecordIssuance("failure", req.CredentialClass)
		s.respondErr(ctx, w, err, "issue")
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

// handleConsume handles POST /consume requests.
func (s *Server) handleConsume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req ConsumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn(ctx).Err(err).Msg("invalid consume request")
		s.metrics.RecordConsumption("failure", "unknown", "unknown")
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid request"), "consume")
		return
	}

	if err := req.Validate(); err != nil {
		logger.Warn(ctx).Err(err).Msg("invalid consume request data")
		s.metrics.RecordConsumption("failure", req.CredentialClass, req.KeyEpoch)
		// we avoid passing harmful invalidated class down
		s.respondErr(ctx, w, apperr.New(apperr.CodeInvalidArgument, "invalid request"), "consume")
		return
	}

	result, err := s.credentialService.Consume(ctx, req.UnblindedSignature, req.Witness, req.CredentialClass, req.KeyEpoch)
	if err != nil {
		s.metrics.RecordConsumption("failure", req.CredentialClass, req.KeyEpoch)
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid consume credentials"), "consume")
		return
	}
	switch result.Status {
	case service.ConsumeRevoked:
		s.metrics.RecordConsumption("revoked", req.CredentialClass, req.KeyEpoch)
		s.respondJSON(ctx, w, http.StatusConflict, ConsumeResponse{
			Valid: false,
			Error: "credential revoked",
		})
		return
	case service.ConsumeDuplicate:
		s.metrics.RecordConsumption("duplicate", req.CredentialClass, req.KeyEpoch)
		s.respondJSON(ctx, w, http.StatusConflict, ConsumeResponse{
			Valid: false,
			Error: result.Error,
		})
		return
	case service.ConsumeAccepted:
		s.metrics.RecordConsumption("success", req.CredentialClass, req.KeyEpoch)
		s.respondJSON(ctx, w, http.StatusOK, ConsumeResponse{Valid: true})
	default:
		// handles unexpected failure
		s.metrics.RecordConsumption("failure", req.CredentialClass, req.KeyEpoch)
		s.respondErr(ctx, w, apperr.New(apperr.CodeInternal, "unknown consume status"), "consume")
		return
	}
}

// handleAdminRevoke handles POST /v1/admin/revoke
func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	// Only allow authenticated admins (use stronger auth than JWT)
	// use the same JWT but with admin scope for now
	ctx := r.Context()
	claims, ok := auth.ClaimsFromContext(ctx)
	if !ok {
		// Unreachable if the middleware is wired correctly. Treat as internal.
		s.respondErr(ctx, w,
			apperr.New(apperr.CodeInternal, "claims missing from context"), "revoke")
		return
	}
	adminID := claims.Subject
	var req struct {
		CredentialClass string     `json:"credential_class"`
		KeyEpoch        string     `json:"key_epoch,omitempty"`
		Reason          string     `json:"reason"`
		RevokedUntil    *time.Time `json:"revoked_until,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid request"), "Revoke")
		return
	}
	if req.CredentialClass == "" {
		s.respondErr(ctx, w, apperr.New(apperr.CodeInvalidArgument, "credential_class required"), "Revoke")
		return
	}
	if req.Reason == "" {
		s.respondErr(ctx, w, apperr.New(apperr.CodeInvalidArgument, "reason required"), "Revoke")
		return
	}
	err := s.revocationStore.RevokeClass(req.CredentialClass, req.KeyEpoch, req.Reason, adminID, req.RevokedUntil)
	if err != nil {
		s.metrics.RecordRevocation("failure", req.CredentialClass)
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "revocation failed"), "Revoke")
		return
	}
	s.metrics.RecordRevocation("success", req.CredentialClass)
	s.respondJSON(ctx, w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleAdminUnrevoke handles DELETE /v1/admin/revoke
func (s *Server) handleAdminUnrevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		CredentialClass string `json:"credential_class"`
		KeyEpoch        string `json:"key_epoch,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid request"), "unrevoke")
		return
	}
	if req.CredentialClass == "" {
		s.respondErr(ctx, w, apperr.New(apperr.CodeInvalidArgument, "credential_class required"), "unrevoke")
		return
	}

	err := s.revocationStore.UnrevokeClass(req.CredentialClass, req.KeyEpoch)
	if err != nil {
		s.metrics.RecordUnrevocation("failure", req.CredentialClass)
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "unrevoke failed"), "unrevoke")
		return
	}
	s.metrics.RecordUnrevocation("success", req.CredentialClass)
	s.respondJSON(ctx, w, http.StatusOK, map[string]string{"status": "unrevoked"})
}

// handleAdminListRevocations handles GET /v1/admin/revocations
func (s *Server) handleAdminListRevocations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entries, err := s.revocationStore.ListRevocations()
	if err != nil {
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeInvalidArgument, err, "list failed"), "listrevoke")
		return
	}
	s.respondJSON(ctx, w, http.StatusOK, map[string]interface{}{
		"revocations": entries,
	})
}

// handleHealth handles GET /health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Check if store is healthy (e.g., Redis ping)
	if err := s.credentialService.Ping(ctx); err != nil {
		s.respondErr(ctx, w, apperr.Wrap(apperr.CodeUnavailable, err, "storage unhealthy"), "health_check")
		return
	}
	s.respondJSON(ctx, w, http.StatusOK, map[string]string{"status": "ok"})
}

// metricsHandler serves the Prometheus metrics endpoint.
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	s.metrics.MetricsHandler().ServeHTTP(w, r)
}
