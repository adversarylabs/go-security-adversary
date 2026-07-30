package main

import (
	"os"
	"path/filepath"
)

func openUserFile(base, userPath string) (*os.File, error) {
	// Clean: reject paths that escape the base with IsLocal
	if !filepath.IsLocal(userPath) {
		return nil, os.ErrInvalid
	}
	return os.Open(filepath.Join(base, userPath))
}

func readUserFile(base, name string) ([]byte, error) {
	if !filepath.IsLocal(name) {
		return nil, os.ErrInvalid
	}
	p := filepath.Join(base, name)
	return os.ReadFile(p)
}
