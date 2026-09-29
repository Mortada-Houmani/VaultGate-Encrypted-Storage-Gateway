package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/crypto"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// MockKMSForAPI provides an in-memory KMS mock for API tests.
type MockKMSForAPI struct {
	keyID       string
	masterKey   []byte
	denyDecrypt bool
}

func NewMockKMSForAPI(keyID string) *MockKMSForAPI {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &MockKMSForAPI{
		keyID:     keyID,
		masterKey: k,
	}
}

func (m *MockKMSForAPI) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	plainKey := make([]byte, 32)
	if _, err := rand.Read(plainKey); err != nil {
		return nil, err
	}

	iv, _ := crypto.GenerateIV()
	aad := []byte(params.EncryptionContext["object_id"])
	ct, tag, err := crypto.Encrypt(plainKey, m.masterKey, iv, aad)
	if err != nil {
		return nil, err
	}

	wrapped := append(iv, append(tag, ct...)...)
	return &kms.GenerateDataKeyOutput{
		KeyId:          aws.String(m.keyID),
		Plaintext:      plainKey,
		CiphertextBlob: wrapped,
	}, nil
}

func (m *MockKMSForAPI) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.denyDecrypt {
		return nil, &mockSmithyErr{code: "AccessDeniedException", message: "User is not authorized to perform: kms:Decrypt"}
	}

	blob := params.CiphertextBlob
	if len(blob) < 28 {
		return nil, &mockSmithyErr{code: "InvalidCiphertextException", message: "Ciphertext is malformed"}
	}

	iv := blob[:12]
	tag := blob[12:28]
	ct := blob[28:]
	aad := []byte(params.EncryptionContext["object_id"])

	plainKey, err := crypto.Decrypt(ct, m.masterKey, iv, tag, aad)
	if err != nil {
		return nil, &mockSmithyErr{code: "InvalidCiphertextException", message: "Context mismatch or integrity failure"}
	}

	return &kms.DecryptOutput{
		KeyId:     aws.String(m.keyID),
		Plaintext: plainKey,
	}, nil
}

type mockSmithyErr struct {
	code    string
	message string
}

func (m *mockSmithyErr) ErrorCode() string    { return m.code }
func (m *mockSmithyErr) ErrorMessage() string { return m.message }
func (m *mockSmithyErr) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}
func (m *mockSmithyErr) Error() string { return m.code + ": " + m.message }

// MockS3ForAPI provides an in-memory S3 mock.
type MockS3ForAPI struct {
	objects map[string]*mockS3Obj
}

type mockS3Obj struct {
	data     []byte
	metadata map[string]string
}

func NewMockS3ForAPI() *MockS3ForAPI {
	return &MockS3ForAPI{
		objects: make(map[string]*mockS3Obj),
	}
}

func (m *MockS3ForAPI) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	body, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	metaCopy := make(map[string]string)
	for k, v := range params.Metadata {
		metaCopy[k] = v
	}
	m.objects[*params.Key] = &mockS3Obj{
		data:     body,
		metadata: metaCopy,
	}
	return &s3.PutObjectOutput{}, nil
}

func (m *MockS3ForAPI) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	obj, exists := m.objects[*params.Key]
	if !exists {
		return nil, &s3types.NoSuchKey{
			Message: aws.String("The specified key does not exist."),
		}
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(obj.data)),
		Metadata:      obj.metadata,
		ContentLength: aws.Int64(int64(len(obj.data))),
	}, nil
}

func (m *MockS3ForAPI) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(m.objects, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *MockS3ForAPI) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	obj, exists := m.objects[*params.Key]
	if !exists {
		return nil, &s3types.NotFound{
			Message: aws.String("Not Found"),
		}
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(obj.data))),
		Metadata:      obj.metadata,
	}, nil
}

func (m *MockS3ForAPI) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

// setupTestServer wires together the mock KMS, mock S3 storage, and API router for testing.
func setupTestServer(t *testing.T) (*httptest.Server, *MockKMSForAPI, storage.Storage) {
	mockKMS := NewMockKMSForAPI("arn:aws:kms:us-east-1:123456789012:key/vaultgate-test")
	envService := envelope.NewService(mockKMS, "arn:aws:kms:us-east-1:123456789012:key/vaultgate-test")
	mockS3 := NewMockS3ForAPI()
	s3Storage := storage.NewS3Storage(mockS3, "vaultgate-test-bucket")

	gw := NewGatewayService(envService, s3Storage)
	handler := NewHandler(gw)
	router := NewRouter(handler)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return server, mockKMS, s3Storage
}

func TestAPI_UploadAndDownload_Binary_RoundTrip(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	plaintext := []byte("Sensitive Exam Question: What is zero trust architecture?")

	// 1. Upload binary payload
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/objects", bytes.NewReader(plaintext))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Object-ID", "exam-q-101")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Upload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 201 Created, got %d: %s", resp.StatusCode, string(body))
	}

	var upResp UploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&upResp); err != nil {
		t.Fatalf("failed to decode upload response: %v", err)
	}

	if upResp.ObjectID != "exam-q-101" {
		t.Errorf("expected object_id exam-q-101, got %s", upResp.ObjectID)
	}
	if upResp.PlaintextSize != len(plaintext) {
		t.Errorf("expected plaintext size %d, got %d", len(plaintext), upResp.PlaintextSize)
	}
	if upResp.Algorithm != "AES-256-GCM" {
		t.Errorf("expected algorithm AES-256-GCM, got %s", upResp.Algorithm)
	}

	// 2. Download and verify plaintext bytes
	getResp, err := client.Get(server.URL + "/api/v1/objects/exam-q-101")
	if err != nil {
		t.Fatalf("Download request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("expected status 200 OK, got %d: %s", getResp.StatusCode, string(body))
	}

	downloaded, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("failed to read downloaded body: %v", err)
	}

	if !bytes.Equal(downloaded, plaintext) {
		t.Errorf("downloaded content mismatch: got %q, want %q", string(downloaded), string(plaintext))
	}

	if objID := getResp.Header.Get("X-VaultGate-Object-ID"); objID != "exam-q-101" {
		t.Errorf("expected header X-VaultGate-Object-ID to be exam-q-101, got %s", objID)
	}
	if algo := getResp.Header.Get("X-VaultGate-Algorithm"); algo != "AES-256-GCM" {
		t.Errorf("expected header X-VaultGate-Algorithm to be AES-256-GCM, got %s", algo)
	}
}

func TestAPI_UploadAndDownload_JSON_RoundTrip(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	secretPayload := "Top Secret Financial Records: $4,200,000"
	b64Data := base64.StdEncoding.EncodeToString([]byte(secretPayload))

	jsonBody := JSONUploadRequest{
		ObjectID: "fin-2026-q3",
		Data:     b64Data,
		Encoding: "base64",
	}
	bodyBytes, _ := json.Marshal(jsonBody)

	resp, err := client.Post(server.URL+"/objects", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("POST /objects failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201 Created, got %d: %s", resp.StatusCode, string(b))
	}

	// Download via direct /objects/{id} route
	getResp, err := client.Get(server.URL + "/objects/fin-2026-q3")
	if err != nil {
		t.Fatalf("GET /objects/fin-2026-q3 failed: %v", err)
	}
	defer getResp.Body.Close()

	downloaded, _ := io.ReadAll(getResp.Body)
	if string(downloaded) != secretPayload {
		t.Errorf("content mismatch: got %q, want %q", string(downloaded), secretPayload)
	}
}

func TestAPI_Upload_Multipart(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("object_id", "report.pdf")
	part, _ := writer.CreateFormFile("file", "report.pdf")
	fileContent := []byte("%PDF-1.7 Test Encrypted Document Content")
	_, _ = part.Write(fileContent)
	_ = writer.Close()

	resp, err := client.Post(server.URL+"/api/v1/objects", writer.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("Multipart upload failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}

	// Download
	getResp, err := client.Get(server.URL + "/api/v1/objects/report.pdf")
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	defer getResp.Body.Close()

	data, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(data, fileContent) {
		t.Errorf("multipart content mismatch: got %s, want %s", string(data), string(fileContent))
	}
}

func TestAPI_Download_NotFound(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	resp, err := client.Get(server.URL + "/api/v1/objects/missing-item-id")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404 Not Found, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Code != "OBJECT_NOT_FOUND" {
		t.Errorf("expected code OBJECT_NOT_FOUND, got %s", errResp.Code)
	}
}

func TestAPI_Download_KMSAccessDenied(t *testing.T) {
	server, mockKMS, _ := setupTestServer(t)
	client := server.Client()

	// 1. Upload object
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/objects?id=secure-file", bytes.NewReader([]byte("Classified Data")))
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload failed: %v", err)
	}
	resp.Body.Close()

	// 2. Revoke KMS Decrypt permission
	mockKMS.denyDecrypt = true

	// 3. Attempt download -> Must return 403 Forbidden
	getResp, err := client.Get(server.URL + "/api/v1/objects/secure-file")
	if err != nil {
		t.Fatalf("download request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on KMS permission revocation, got %d", getResp.StatusCode)
	}

	var errResp ErrorResponse
	_ = json.NewDecoder(getResp.Body).Decode(&errResp)
	if errResp.Code != "ACCESS_DENIED" {
		t.Errorf("expected code ACCESS_DENIED, got %s", errResp.Code)
	}
}

func TestAPI_Download_CiphertextTampering(t *testing.T) {
	server, _, s3Storage := setupTestServer(t)
	client := server.Client()

	// 1. Upload valid object
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/objects?id=tamper-test", bytes.NewReader([]byte("Authentic Integrity Protected Data")))
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload failed: %v", err)
	}
	resp.Body.Close()

	// 2. Tamper with the raw ciphertext stored in S3 (simulating unauthorized bit-flip attack in storage)
	ctx := context.Background()
	env, err := s3Storage.GetEncryptedObject(ctx, "tamper-test")
	if err != nil {
		t.Fatalf("failed to fetch object from storage: %v", err)
	}
	env.Ciphertext[0] ^= 0xFF // Flip bits in ciphertext
	if err := s3Storage.PutEncryptedObject(ctx, env); err != nil {
		t.Fatalf("failed to put tampered object: %v", err)
	}

	// 3. Attempt download -> Must fail authentication / integrity check (400 Bad Request)
	getResp, err := client.Get(server.URL + "/api/v1/objects/tamper-test")
	if err != nil {
		t.Fatalf("download request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for tampered ciphertext, got %d", getResp.StatusCode)
	}

	var errResp ErrorResponse
	_ = json.NewDecoder(getResp.Body).Decode(&errResp)
	if errResp.Code != "TAMPER_DETECTED" {
		t.Errorf("expected code TAMPER_DETECTED, got %s", errResp.Code)
	}
}

func TestAPI_Upload_EmptyPayload(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/objects", bytes.NewReader([]byte{}))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 Bad Request for empty payload, got %d", resp.StatusCode)
	}

	var errResp ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Code != "EMPTY_PAYLOAD" {
		t.Errorf("expected code EMPTY_PAYLOAD, got %s", errResp.Code)
	}
}

func TestAPI_DeleteAndHead(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	// 1. Upload
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/objects?id=lifecycle-doc", bytes.NewReader([]byte("Lifecycle payload")))
	resp, _ := client.Do(req)
	resp.Body.Close()

	// 2. HEAD object -> 200 OK
	headReq, _ := http.NewRequest(http.MethodHead, server.URL+"/api/v1/objects/lifecycle-doc", nil)
	headResp, err := client.Do(headReq)
	if err != nil || headResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HEAD 200 OK, got %v", headResp.StatusCode)
	}
	headResp.Body.Close()

	// 3. DELETE object -> 200 OK
	delReq, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/objects/lifecycle-doc", nil)
	delResp, err := client.Do(delReq)
	if err != nil || delResp.StatusCode != http.StatusOK {
		t.Fatalf("expected DELETE 200 OK, got %v", delResp.StatusCode)
	}
	delResp.Body.Close()

	// 4. Subsequent HEAD -> 404 Not Found
	headResp2, _ := client.Do(headReq)
	if headResp2.StatusCode != http.StatusNotFound {
		t.Errorf("expected HEAD 404 after delete, got %d", headResp2.StatusCode)
	}
	headResp2.Body.Close()
}

func TestAPI_HealthCheck(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	resp, err := client.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if health.Status != "ok" {
		t.Errorf("expected status ok, got %s", health.Status)
	}
}

func TestAPI_CORS_Options(t *testing.T) {
	server, _, _ := setupTestServer(t)
	client := server.Client()

	req, _ := http.NewRequest(http.MethodOptions, server.URL+"/api/v1/objects", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for OPTIONS, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: *, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}
