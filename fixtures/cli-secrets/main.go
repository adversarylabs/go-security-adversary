package clisecrets

import (
	"fmt"
	"os"
	"os/exec"
)

func fetchSecret(token string) (string, error) {
	cmd := exec.Command("doppler", "secrets", "get", "API_KEY", "--plain", "--token", token)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("doppler failed: %s", out)
	}
	return string(out), nil
}

func clone(token, owner, repo string) error {
	url := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, repo)
	return exec.Command("git", "clone", url).Run()
}

func saveKey(path string, key []byte) error {
	return os.WriteFile(path, key, 0o644)
}
