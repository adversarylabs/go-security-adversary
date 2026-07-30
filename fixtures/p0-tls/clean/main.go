package main
import "crypto/tls"
func client() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }
