package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/api"
)

// Client is a lightweight HTTP client for interacting with the VaultGate API Gateway.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient instantiates a new VaultGate API client.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Upload sends plaintext bytes to VaultGate for envelope encryption and S3 storage.
func (c *Client) Upload(ctx context.Context, objectID string, plaintext []byte) (*api.UploadResponse, error) {
	url := fmt.Sprintf("%s/api/v1/objects", c.baseURL)
	if objectID != "" {
		url = fmt.Sprintf("%s?id=%s", url, objectID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(plaintext))
	if err != nil {
		return nil, fmt.Errorf("client: failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if objectID != "" {
		req.Header.Set("X-Object-ID", objectID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result api.UploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("client: failed to parse upload response: %w", err)
	}

	return &result, nil
}

// Download retrieves and decrypts the object from VaultGate.
func (c *Client) Download(ctx context.Context, objectID string) ([]byte, *api.DownloadMetadata, error) {
	url := fmt.Sprintf("%s/api/v1/objects/%s", c.baseURL, objectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("client: failed to create download request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("client: download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, c.parseError(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("client: failed to read download response body: %w", err)
	}

	createdAt, _ := http.ParseTime(resp.Header.Get("X-VaultGate-Created-At"))
	meta := &api.DownloadMetadata{
		ObjectID:  resp.Header.Get("X-VaultGate-Object-ID"),
		KMSKeyID:  resp.Header.Get("X-VaultGate-KMS-Key-ID"),
		Algorithm: resp.Header.Get("X-VaultGate-Algorithm"),
		CreatedAt: createdAt,
	}

	return data, meta, nil
}

// ReWrap requests server-side envelope key rotation under a new KMS master key.
func (c *Client) ReWrap(ctx context.Context, objectID string, newKMSKeyID string) (*api.ReWrapResponse, error) {
	url := fmt.Sprintf("%s/api/v1/objects/%s/rewrap", c.baseURL, objectID)
	body, _ := json.Marshal(api.ReWrapRequest{NewKMSKeyID: newKMSKeyID})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("client: failed to create rewrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: rewrap request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result api.ReWrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("client: failed to parse rewrap response: %w", err)
	}

	return &result, nil
}

// Delete removes the encrypted object from storage.
func (c *Client) Delete(ctx context.Context, objectID string) error {
	url := fmt.Sprintf("%s/api/v1/objects/%s", c.baseURL, objectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("client: failed to create delete request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("client: delete request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseError(resp)
	}

	return nil
}

// Health checks the health and readiness of the VaultGate server.
func (c *Client) Health(ctx context.Context) (*api.HealthResponse, error) {
	url := fmt.Sprintf("%s/api/v1/health", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("client: failed to create health request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: health check request failed: %w", err)
	}
	defer resp.Body.Close()

	var result api.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("client: failed to parse health response: %w", err)
	}

	return &result, nil
}

// parseError reads structured JSON error from HTTP responses.
func (c *Client) parseError(resp *http.Response) error {
	var errResp api.ErrorResponse
	bodyBytes, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(bodyBytes, &errResp); err == nil && errResp.Error != "" {
		return fmt.Errorf("server error (%d %s): [%s] %s", resp.StatusCode, http.StatusText(resp.StatusCode), errResp.Code, errResp.Error)
	}
	return fmt.Errorf("server error (%d %s): %s", resp.StatusCode, http.StatusText(resp.StatusCode), strings.TrimSpace(string(bodyBytes)))
}
