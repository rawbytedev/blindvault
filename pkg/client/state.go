package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"blindvault/pkg/crypto"
)

// State stores pending blinding factors and associated data.
type State struct {
	mu       sync.RWMutex
	filePath string
	Requests map[string]*PendingRequest `json:"requests"`
}

// PendingRequest holds data needed for later unblinding.
type PendingRequest struct {
	BlindingFactor []byte `json:"blinding_factor"` // serialized scalar
	Message        []byte `json:"message"`
	Witness        []byte `json:"witness"` // compressed G1 point
}

// NewState loads or creates a state file in the user's home directory.
func NewState() (*State, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return NewStateWithDir(home)
}

// NewStateWithDir allows specifying a custom directory (used for testing).
func NewStateWithDir(dir string) (*State, error) {
	stateDir := filepath.Join(dir, ".blindvault")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "state.json")
	s := &State{
		filePath: path,
		Requests: make(map[string]*PendingRequest),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}
func (s *State) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.Requests)
}

func (s *State) save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := json.MarshalIndent(s.Requests, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0600)
}

// Store stores a pending request and returns a unique ID.
func (s *State) Store(scalar crypto.Scalar, msg []byte, witness crypto.PointG1) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := generateID()
	sk := scalar.Bytes()
	s.Requests[id] = &PendingRequest{
		BlindingFactor: sk[:],
		Message:        msg,
		Witness:        witness.Compress(),
	}
	if err := s.save(); err != nil {
		return "", err
	}
	return id, nil
}

// Get retrieves a pending request by ID.
func (s *State) Get(id string) (*PendingRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.Requests[id]
	if !ok {
		return nil, ErrRequestNotFound
	}
	return req, nil
}

// Delete removes a pending request after unblinding.
func (s *State) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Requests, id)
	return s.save()
}

func generateID() string {
	// Simple 8‑character random ID
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// fallback to timestamp
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ErrRequestNotFound indicates the ID does not exist.
var ErrRequestNotFound = errors.New("request not found")
