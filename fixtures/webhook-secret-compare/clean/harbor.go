package webhook

import (
	"crypto/hmac"
	"crypto/subtle"
	"net/http"
)

type harborParser struct {
	secret string
}

func (p *harborParser) CanHandle(request *http.Request) bool {
	if p.secret == "" {
		return false
	}
	provided := request.Header.Get("Authorization")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(p.secret)) == 1
}

func verifyMAC(request *http.Request, expectedSignature []byte) bool {
	providedSignature := []byte(request.Header.Get("X-Webhook-Signature"))
	return hmac.Equal(providedSignature, expectedSignature)
}

func isJSON(request *http.Request) bool {
	return request.Header.Get("Content-Type") == "application/json"
}

func hasBearerScheme(request *http.Request, tokenType string) bool {
	return request.Header.Get("Authorization") == tokenType
}

func mutatesHeaderAlias(request *http.Request, configuredSecret string) bool {
	provided := request.Header.Get("Authorization")
	provided += "-normalized"
	return provided == configuredSecret
}

func headerReadOnlyInComment(provided, configuredSecret string) bool {
	// provided := request.Header.Get("Authorization")
	return provided == configuredSecret
}

func headerReadOnlyInString(provided, configuredSecret string) bool {
	example := `provided := request.Header.Get("X-Webhook-Signature")`
	_ = example
	return provided == configuredSecret
}
