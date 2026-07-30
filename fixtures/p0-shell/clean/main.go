package main
import "os/exec"
func run(user string) { exec.Command("echo", user).Run() }
