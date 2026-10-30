// Package api – internal tests for HTTP response helpers.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rawbytedev/blindvault/v2/pkg/apperr"
	"github.com/rawbytedev/blindvault/v2/pkg/logger"
	"github.com/rs/zerolog"
)

func TestRespondJSON_Success(t *testing.T) {
	tests := []struct {
		name   string
		status int
		data   interface{}
	}{
		{"200 with struct", http.StatusOK, struct {
			Name string `json:"name"`
		}{"alice"}},
		{"201 with map", http.StatusCreated, map[string]int{"id": 42}},
		{"202 with slice", http.StatusAccepted, []string{"a", "b"}},
		{"204 nil payload", http.StatusNoContent, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s := &Server{}

			s.respondJSON(context.Background(), rec, tc.status, tc.data)

			if rec.Code != tc.status {
				t.Errorf("status: want %d, got %d", tc.status, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type: want %q, got %q", "application/json", got)
			}

			if tc.status != http.StatusNoContent {
				var decoded interface{}
				if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
					t.Fatalf("failed to decode body: %v", err)
				}
			}
		})
	}
}

func TestRespondJSON_EncodingFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &Server{}

	s.respondJSON(context.Background(), rec, http.StatusOK, make(chan int))

	if !strings.Contains(rec.Body.String(), "internal server error") {
		t.Errorf("expected fallback body, got %q", rec.Body.String())
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected error code 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// respondErr (router: 4xx exposes message, 5xx hides it)
// ---------------------------------------------------------------------------

func TestRespondErr_ClientError(t *testing.T) {
	err := apperr.New(apperr.CodeInvalidArgument, "field 'name' is required")

	rec := httptest.NewRecorder()
	s := &Server{}
	s.respondErr(context.Background(), rec, err, "create-user")

	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("want 4xx status, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want %q, got %q", "application/json", ct)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Error != err.Error() {
		t.Errorf("want message %q, got %q", err.Error(), resp.Error)
	}
	if resp.Code != rec.Code {
		t.Errorf("want code field %d, got %d", rec.Code, resp.Code)
	}
}

func TestRespondErr_ServerError(t *testing.T) {
	err := apperr.New(apperr.CodeInternal, "db pool exhausted at line 42")

	rec := httptest.NewRecorder()
	s := &Server{}
	s.respondErr(context.Background(), rec, err, "list-users")

	if rec.Code < 500 {
		t.Fatalf("want 5xx status, got %d", rec.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := http.StatusText(rec.Code)
	if resp.Error != want {
		t.Errorf("server error must be generic: want %q, got %q", want, resp.Error)
	}
	if strings.Contains(resp.Error, "db pool") {
		t.Errorf("internal error details leaked to client: %q", resp.Error)
	}
}

func TestRespondError_Basic(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &Server{}

	s.respondError(context.Background(), rec, http.StatusBadRequest, "bad request")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: want %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want %q, got %q", "application/json", ct)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "bad request" {
		t.Errorf("message: want %q, got %q", "bad request", resp.Error)
	}
	if resp.Code != http.StatusBadRequest {
		t.Errorf("code: want %d, got %d", http.StatusBadRequest, resp.Code)
	}
	if resp.Details != "" {
		t.Errorf("details: want empty, got %q", resp.Details)
	}
}

func TestRespondError_WithDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &Server{}

	s.respondError(context.Background(), rec, http.StatusBadRequest,
		"validation failed", "name is required")

	var resp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Details != "name is required" {
		t.Errorf("details: want %q, got %q", "name is required", resp.Details)
	}
}

func TestRespondError_EmptyDetailsOmitted(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &Server{}

	s.respondError(context.Background(), rec, http.StatusBadRequest, "bad", "")

	var resp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Details != "" {
		t.Errorf("details: want empty, got %q", resp.Details)
	}
}

func TestRespondError_OnlyFirstDetailUsed(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &Server{}

	s.respondError(context.Background(), rec, http.StatusBadRequest,
		"bad", "first", "second", "third")

	var resp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Details != "first" {
		t.Errorf("details: want %q, got %q", "first", resp.Details)
	}
}

func TestRespondErr_ServerError_LogsAtErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.ErrorLevel)
	ctx := logger.WithLogger(context.Background(), &zl)

	err := apperr.New(apperr.CodeInternal, "boom")
	rec := httptest.NewRecorder()
	(&Server{}).respondErr(ctx, rec, err, "op-name")

	out := buf.String()
	t.Log(out)
	if !strings.Contains(out, `"level":"error"`) {
		t.Errorf("expected error-level log, got: %s", out)
	}
	if !strings.Contains(out, `"op":"op-name"`) {
		t.Errorf("expected op field in log, got: %s", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("expected underlying error in log, got: %s", out)
	}
}
