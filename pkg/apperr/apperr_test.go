package apperr

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test wrapping and unwrapping of errors
func TestError_Wrap_Unwrap(t *testing.T) {
	err := New(CodeInvalidArgument, "invalid input")
	require.Equal(t, err.Error(), "invalid input")
	// set wrapped error
	err.Wrapped = errors.New("underlying error")
	require.Equal(t, err.Error(), "invalid input: underlying error")

	require.Equal(t, err.Unwrap(), errors.New("underlying error"))

	wrappedErr := Wrap(CodeInvalidArgument, errors.New("new underlying error"), "invalid input")
	require.Equal(t, wrappedErr.Error(), "invalid input: new underlying error")
}

// Test that code maps to the correct HTTP status code
func TestStatusCode(t *testing.T) {
	// Test CodeInvalidArgument
	err := New(CodeInvalidArgument, "invalid input")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusBadRequest)
	// Test CodeUnauthorized
	err = New(CodeUnauthorized, "unauthorized")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusUnauthorized)
	// Test CodeForbidden
	err = New(CodeForbidden, "forbidden")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusForbidden)
	// Test CodeNotFound
	err = New(CodeNotFound, "not found")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusNotFound)
	// Test CodeAlreadyExists
	err = New(CodeAlreadyExists, "already exists")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusConflict)
	// Test CodeInternal
	err = New(CodeInternal, "internal error")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusInternalServerError)
	//	 Test CodeUnavailable
	err = New(CodeUnavailable, "service unavailable")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusServiceUnavailable)
	// Test CodeTooManyRequest
	err = New(CodeTooManyRequest, "too many requests")
	require.Equal(t, err.Code.HTTPStatus(), http.StatusTooManyRequests)
}
