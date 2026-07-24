package terrible

import (
	"crypto/tls"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
)

func client() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

func parse(raw string, key any) (*jwt.Token, error) {
	slog.Info("received", "token", raw)
	return jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil })
}
