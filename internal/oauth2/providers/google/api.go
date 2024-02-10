package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const AdminDirectoryGroupReadonlyScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"

type groupPage struct {
	NextPageToken string      `json:"apiResponse"`
	Groups        []groupType `json:"groups"`
}

type groupType struct {
	Email string `json:"email"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p groupPage) GetNextPageToken() string {
	return p.NextPageToken
}

type apiResponse interface {
	GetNextPageToken() string
}

// getAPI calls the Google API and decodes the response into the data struct.
func (p *Provider) getAPI(ctx context.Context, apiURL *url.URL, data apiResponse) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request context with URL %s: %w", apiURL, err)
	}

	req.Header.Add("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error calling Google api %s: %w", apiURL, err)
	} else if resp.StatusCode != http.StatusOK {
		var apiErr apiError

		respBody, err := io.ReadAll(resp.Body)
		if err == nil && bytes.HasPrefix(respBody, []byte("{")) {
			_ = json.Unmarshal(respBody, &apiErr)
		}

		return fmt.Errorf("error from Google api %s: http status code: %d; message: %s", apiURL, resp.StatusCode, apiErr.Error.Message)
	}

	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(data); err != nil {
		return fmt.Errorf("unable to decode json: %w", err)
	}

	query, err := url.ParseQuery(apiURL.RawQuery)
	if err != nil {
		return fmt.Errorf("error paring query param %s: %w", apiURL, err)
	}

	query.Set("pageToken", data.GetNextPageToken())
	apiURL.RawQuery = query.Encode()

	return nil
}
