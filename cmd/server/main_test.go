package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadEnvFile_NoOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.test")
	os.WriteFile(path, []byte("BLINDVAULT_MODE=production\n"), 0600)

	t.Setenv("BLINDVAULT_MODE", "development") // pre-existing
	require.NoError(t, loadEnvFile(path, false))
	require.Equal(t, "development", os.Getenv("BLINDVAULT_MODE")) // env wins
}

func TestLoadEnvFile_Override(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.test")
	os.WriteFile(path, []byte("BLINDVAULT_MODE=production\n"), 0600)

	t.Setenv("BLINDVAULT_MODE", "development")
	require.NoError(t, loadEnvFile(path, true))
	require.Equal(t, "production", os.Getenv("BLINDVAULT_MODE")) // file wins
}
