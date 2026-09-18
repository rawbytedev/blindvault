package validation

import (
	"regexp"
)

var (
	ReEpoch = regexp.MustCompile(`^\d{4}-\d{2}$`)
	ReClass = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)
)

func Epoch(s string) bool { return ReEpoch.MatchString(s) }
func Class(s string) bool { return ReClass.MatchString(s) }
