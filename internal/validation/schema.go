// Validation package provides functions to validate request payloads against defined schemas.
package validation

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

var schemaValidator = validator.New()

func init() {
	if err := schemaValidator.RegisterValidation("hex_len", func(fl validator.FieldLevel) bool {
		field, ok := fl.Field().Interface().(string)
		if !ok || strings.TrimSpace(field) == "" {
			return false
		}
		expected, err := strconv.Atoi(fl.Param())
		if err != nil {
			return false
		}
		decoded, err := hex.DecodeString(field)
		if err != nil {
			return false
		}
		return len(decoded) == expected
	}); err != nil {
		panic(fmt.Sprintf("failed to register hex validation: %v", err))
	}
	if err := schemaValidator.RegisterValidation("class", func(fl validator.FieldLevel) bool {
		field, ok := fl.Field().Interface().(string)
		if !ok {
			return false
		}
		return Class(field)
	}); err != nil {
		panic(fmt.Sprintf("failed to register class validation: %v", err))
	}
	if err := schemaValidator.RegisterValidation("epoch", func(fl validator.FieldLevel) bool {
		field, ok := fl.Field().Interface().(string)
		if !ok {
			return false
		}
		return Epoch(field)
	}); err != nil {
		panic(fmt.Sprintf("failed to register epoch validation: %v", err))
	}

}

func ValidateStruct(value any) error {
	if value == nil {
		return fmt.Errorf("value is nil")
	}
	return schemaValidator.Struct(value)
}

func ValidateIssueRequest(value any) error {
	return ValidateStruct(value)
}

func ValidateConsumeRequest(value any) error {
	return ValidateStruct(value)
}

func ValidateAdminRevokeRequest(value any) error {
	return ValidateStruct(value)
}

func ValidateAdminUnrevokeRequest(value any) error {
	return ValidateStruct(value)
}
