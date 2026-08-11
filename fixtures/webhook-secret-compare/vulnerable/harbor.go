package webhook

import "net/http"

type harborParser struct {
	secret string
}

func (p *harborParser) CanHandle(request *http.Request) bool {
	if p.secret == "" {
		return false
	}
	return request.Header.Get("Authorization") == p.secret
}

func verifyWebhook(request *http.Request, configuredToken string) bool {
	provided := request.Header.Get("X-Webhook-Signature")
	return provided != configuredToken
}
