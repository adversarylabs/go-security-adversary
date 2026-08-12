package client

import (
	"errors"
	"net/http"
	"net/url"
)

func withHeader(client *http.Client, endpoint string, accessToken string) error {
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	_, err := client.Do(req)
	return err
}

func ordinaryQuery(client *http.Client, endpoint string, page string) error {
	target, _ := url.Parse(endpoint)
	query := target.Query()
	query.Set("page", page)
	target.RawQuery = query.Encode()
	_, err := client.Get(target.String())
	return err
}

func sanitizedFailure(client *http.Client, endpoint string, apiKey string) error {
	target, _ := url.Parse(endpoint)
	query := target.Query()
	query.Set("api_key", apiKey)
	target.RawQuery = query.Encode()
	_, err := client.Get(target.String())
	if err != nil {
		return errors.New("upstream request failed")
	}
	return nil
}

func replacedHTTPError(client *http.Client, endpoint string, apiKey string) error {
	target, _ := url.Parse(endpoint)
	query := target.Query()
	query.Set("api_key", apiKey)
	target.RawQuery = query.Encode()
	_, err := client.Get(target.String())
	_, err = url.Parse(endpoint)
	return err
}

type internalClient struct{}

func (internalClient) Get(string) (*http.Response, error) { return nil, nil }

func unrelatedGet(client internalClient, endpoint string, token string) error {
	target, _ := url.Parse(endpoint)
	query := target.Query()
	query.Set("token", token)
	target.RawQuery = query.Encode()
	_, err := client.Get(target.String())
	return err
}
