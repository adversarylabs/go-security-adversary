package main
import "crypto/tls"
func client() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
