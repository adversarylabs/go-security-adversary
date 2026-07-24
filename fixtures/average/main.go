package average

import "github.com/golang-jwt/jwt/v5"

func parse(raw string, key any) (*jwt.Token, error) {
	return jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil })
}
