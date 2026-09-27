package auth

import (
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	Admin bool     `json:"admin,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// HasRole returns true if the claim contains the role or admin is true.
func (c *Claims) HasRole(role string) bool {
	if c.Admin {
		return true
	}
	if c.Roles == nil {
		return false
	}
	return slices.Contains(c.Roles, role)
}

// HasAnyRole checks for any of the given roles.
func (c *Claims) HasAnyRole(roles ...string) bool {
	if c.Admin {
		return true
	}
	for _, r := range roles {
		for _, have := range c.Roles {
			if r == have {
				return true
			}
		}
	}
	return false
}
