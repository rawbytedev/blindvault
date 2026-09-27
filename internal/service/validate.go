package service

import "strings"

type ValidationErrors []error

func (v *ValidationErrors) Add(err error) {
	if err != nil {
		*v = append(*v, err)
	}
}
func (v ValidationErrors) Err() error {
	if len(v) == 0 {
		return nil
	}
	if len(v) == 1 {
		return v[0]
	}
	return v
}

func (v ValidationErrors) Error() string {
	var b strings.Builder
	b.WriteString("configuration invalid:\n")
	for _, err := range v {
		b.WriteString("  - ")
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	return b.String()
}
