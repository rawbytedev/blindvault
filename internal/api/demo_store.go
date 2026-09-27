package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/rawbytedev/blindvault/pkg/apperr"
)

type DemoStore struct {
	mu   sync.RWMutex
	data map[string]string // ticket_id -> ciphertext_hex
}

func NewDemoStore() *DemoStore {
	return &DemoStore{
		data: make(map[string]string),
	}
}

func (s *Server) handleStoreCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondErr(r.Context(), w, apperr.Wrap(apperr.CodeInvalidArgument, err, "invalid request"), "demo_store")
		return
	}
	ticketID := uuid.New()
	s.demoStore.mu.Lock()
	s.demoStore.data[ticketID.String()] = req.Ciphertext
	s.demoStore.mu.Unlock()
	s.respondJSON(r.Context(), w, http.StatusOK, map[string]string{"ticket_id": ticketID.String()})
}

func (s *Server) handleRetrieveCredential(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("ticket_id")
	s.demoStore.mu.RLock()
	ciphertext, ok := s.demoStore.data[ticketID]
	s.demoStore.mu.RUnlock()
	if !ok {
		s.respondErr(r.Context(), w, apperr.New(apperr.CodeNotFound, "ticket not found"), "demo_store")
		return
	}
	s.respondJSON(r.Context(), w, http.StatusOK, map[string]string{"ciphertext": ciphertext})
}
