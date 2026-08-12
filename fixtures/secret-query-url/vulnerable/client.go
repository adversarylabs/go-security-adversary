package client

import (
	"fmt"
	"net/http"
	"net/url"
)

func fetch(client *http.Client, endpoint string, accessToken string) error {
	target, _ := url.Parse(endpoint)
	query := target.Query()
	query.Set("access_token", accessToken)
	target.RawQuery = query.Encode()
	req, _ := http.NewRequest(http.MethodGet, target.String(), nil)
	_, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch account: %w", err)
	}
	return nil
}
