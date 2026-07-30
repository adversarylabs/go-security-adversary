package main
import "os/exec"
func run(user string) { exec.Command("sh", "-c", "echo "+user).Run() }
