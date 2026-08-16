package sample

import (
	"os"
	"os/exec"
	"path/filepath"
)

func publish(root, sub, target string) error {
	mountPath := filepath.Join(root, sub)
	if !filepath.IsLocal(sub) {
		return os.ErrInvalid
	}
	info, err := os.Lstat(mountPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.ErrInvalid
	}
	return exec.Command("mount", "--bind", mountPath, target).Run()
}
