package api

import (
	"fmt"
	"math/rand"
	"testing"
)

// Generate a random IP address
func GenerateRandomAdress(n int) []string {
	addrs := []string{}
	for _ = range n {
		ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
		addrs = append(addrs, ip)
	}
	return addrs
}

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(10, 10, 10)
	addrs := GenerateRandomAdress(10)
	for _, addr := range addrs {
		if !rl.Allow(addr) {
			t.Errorf("Expected Allow to return true for new IP %s", addr)
		}
	}
	addr := GenerateRandomAdress(1)[0]
	if !rl.Allow(addr) {
		t.Errorf("Expected Allow to return true for new IP %s", addr)
	}
	// oldest entries is removed
	if !rl.Allow(addrs[0]) {
		t.Errorf("Expected Allow to return true for new IP %s, oldest entry was removed", addrs[0])
	}
}