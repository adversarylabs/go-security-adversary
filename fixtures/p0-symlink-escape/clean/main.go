package sample

import (
	"os"
	"path/filepath"
	"strings"
)

func publish(root, sub, target string) error {
	current := root
	for _, part := range strings.Split(sub, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return os.ErrInvalid
		}
	}
	f, err := os.OpenFile(current, os.O_RDONLY|os.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = target
	return nil
}
