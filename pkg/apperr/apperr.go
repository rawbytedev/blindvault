package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

// Code is an error category.
type Code string

const (
	CodeInvalidArgument Code = "invalid_argument"
	CodeNotFound        Code = "not_found"
	CodeAlreadyExists   Code = "already_exists"
	CodeUnauthorized    Code = "unauthorized"
	CodeForbidden       Code = "forbidden"
	CodeInternal        Code = "internal"
	CodeUnavailable     Code = "unavailable"
	CodeTooManyRequest  Code = "too_many_request"
)

// Error is the single error type used throughout the codebase.
type Error struct {
	Code    Code
	Message string
	Wrapped error // optional; underlying cause
}

func (e *Error) Error() string {
	if e.Wrapped != nil {
		return e.Message + ": " + e.Wrapped.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Wrapped }

// New creates a new error with the given code and message.
func New(code Code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// Newf is like New but formats the message.
func Newf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap attaches a code and message to an existing error.
func Wrap(code Code, err error, msg string) *Error {
	return &Error{Code: code, Message: msg, Wrapped: err}
}

// CodeOf extracts the code from any error. Defaults to CodeInternal.
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}

// HTTPStatus maps an error code to the appropriate HTTP status.
func (c Code) HTTPStatus() int {
	switch c {
	case CodeInvalidArgument:
		return http.StatusBadRequest
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeAlreadyExists:
		return http.StatusConflict
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	case CodeTooManyRequest:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}
