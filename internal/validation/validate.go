package validation

import (
	"regexp"
)

var (
	ReEpoch = regexp.MustCompile(`^\d{4}-\d{2}$`)
	ReClass = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)
)

// Epoch checks if the provided string matches the expected epoch format (YYYY-MM).
// Class checks if the provided string matches the expected class format (alphanumeric, underscores, hyphens, 1-64 characters).
func Epoch(s string) bool { return ReEpoch.MatchString(s) }
func Class(s string) bool { return ReClass.MatchString(s) }
