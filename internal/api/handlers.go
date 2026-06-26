package api

import (
    "encoding/json"
    "net/http"
    "blindvault/pkg/logger"
)

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    var req IssueRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        logger.Warn(ctx).Err(err).Msg("invalid issue request")
        s.respondError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    if req.BlindedMessage == "" || req.CredentialClass == "" {
        s.respondError(w, http.StatusBadRequest, "missing required fields")
        return
    }

    result, err := s.credentialService.Issue(ctx, req.BlindedMessage, req.CredentialClass)
    if err != nil {
        // errors.Wrap already logs; we just need to return a user‑friendly error
        s.respondError(w, http.StatusInternalServerError, "issuance failed")
        return
    }

    s.respondJSON(w, http.StatusOK, IssueResponse{
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
        s.respondError(w, http.StatusBadRequest, "invalid request body")
        return
    }

    if req.UnblindedSignature == "" || req.Witness == "" || req.CredentialClass == "" || req.KeyEpoch == "" {
        s.respondError(w, http.StatusBadRequest, "missing required fields")
        return
    }

    result, err := s.credentialService.Consume(ctx, req.UnblindedSignature, req.Witness, req.CredentialClass, req.KeyEpoch)
    if err != nil {
        // errors.Wrap already logs
        s.respondError(w, http.StatusInternalServerError, "consumption failed")
        return
    }

    if !result.Valid {
        s.respondJSON(w, http.StatusConflict, ConsumeResponse{
            Valid: false,
            Error: result.Error,
        })
        return
    }

    s.respondJSON(w, http.StatusOK, ConsumeResponse{Valid: true})
}

// handleHealth handles GET /health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    s.respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}