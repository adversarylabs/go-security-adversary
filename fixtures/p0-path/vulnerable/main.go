package main

import (
	"os"
	"path/filepath"
)

func openUserFile(base, userPath string) (*os.File, error) {
	// Vulnerable: join user path and open with no confinement
	return os.Open(filepath.Join(base, userPath))
}

func readUserFile(base, name string) ([]byte, error) {
	p := filepath.Join(base, name)
	return os.ReadFile(p)
}
