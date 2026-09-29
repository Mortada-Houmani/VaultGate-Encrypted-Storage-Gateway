package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/storage"
)

var (
	// ErrEmptyPayload is returned when an upload request contains no data.
	ErrEmptyPayload = errors.New("api: object payload cannot be empty")
)

// UploadResponse contains the metadata returned upon successful envelope encryption and S3 persistence.
type UploadResponse struct {
	ObjectID       string    `json:"object_id"`
	S3Key          string    `json:"s3_key"`
	S3Bucket       string    `json:"s3_bucket"`
	KMSKeyID       string    `json:"kms_key_id"`
	PlaintextSize  int       `json:"plaintext_size"`
	CiphertextSize int       `json:"ciphertext_size"`
	Algorithm      string    `json:"algorithm"`
	CreatedAt      time.Time `json:"created_at"`
}

// DownloadMetadata contains non-sensitive metadata returned alongside decrypted content.
type DownloadMetadata struct {
	ObjectID  string    `json:"object_id"`
	S3Key     string    `json:"s3_key"`
	KMSKeyID  string    `json:"kms_key_id"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
}

// HealthResponse represents the health status of the gateway and its connected backends.
type HealthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Storage   map[string]string `json:"storage"`
}

// GatewayService orchestrates envelope encryption (KMS) and encrypted object persistence (S3).
type GatewayService struct {
	envService *envelope.Service
	storage    storage.Storage
}

// NewGatewayService instantiates the gateway service.
func NewGatewayService(envService *envelope.Service, storage storage.Storage) *GatewayService {
	return &GatewayService{
		envService: envService,
		storage:    storage,
	}
}

// Upload encrypts the payload using KMS envelope encryption and persists it to S3.
func (s *GatewayService) Upload(ctx context.Context, objectID string, plaintext []byte) (*UploadResponse, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPayload
	}

	if objectID == "" {
		id, err := generateRandomID()
		if err != nil {
			return nil, fmt.Errorf("api: failed to generate object ID: %w", err)
		}
		objectID = id
	}

	// 1. Envelope Encrypt (KMS GenerateDataKey + AES-256-GCM + immediate memory zeroization)
	env, err := s.envService.WrapAndEncrypt(ctx, objectID, plaintext)
	if err != nil {
		return nil, err
	}

	// 2. Persist Ciphertext & Cryptographic Metadata Headers to S3
	err = s.storage.PutEncryptedObject(ctx, env)
	if err != nil {
		return nil, err
	}

	return &UploadResponse{
		ObjectID:       env.ObjectID,
		S3Key:          env.S3Key,
		S3Bucket:       s.storage.BucketName(),
		KMSKeyID:       env.KMSKeyID,
		PlaintextSize:  len(plaintext),
		CiphertextSize: len(env.Ciphertext),
		Algorithm:      storage.AlgorithmAES256GCM,
		CreatedAt:      env.CreatedAt,
	}, nil
}

// Download fetches the encrypted blob from S3 and unwraps the data key via KMS to decrypt the plaintext.
func (s *GatewayService) Download(ctx context.Context, objectID string) ([]byte, *DownloadMetadata, error) {
	if objectID == "" {
		return nil, nil, fmt.Errorf("%w: objectID cannot be empty", envelope.ErrInvalidEnvelope)
	}

	// 1. Fetch Ciphertext and Envelope Metadata from S3
	env, err := s.storage.GetEncryptedObject(ctx, objectID)
	if err != nil {
		return nil, nil, err
	}

	// 2. Decrypt wrapped data key via KMS and decrypt ciphertext with AES-256-GCM
	plaintext, err := s.envService.DecryptAndUnwrap(ctx, env)
	if err != nil {
		return nil, nil, err
	}

	meta := &DownloadMetadata{
		ObjectID:  env.ObjectID,
		S3Key:     env.S3Key,
		KMSKeyID:  env.KMSKeyID,
		Algorithm: storage.AlgorithmAES256GCM,
		CreatedAt: env.CreatedAt,
	}

	return plaintext, meta, nil
}

// Delete removes the encrypted object from S3.
func (s *GatewayService) Delete(ctx context.Context, objectID string) error {
	return s.storage.DeleteEncryptedObject(ctx, objectID)
}

// Head checks object existence and returns ciphertext size.
func (s *GatewayService) Head(ctx context.Context, objectID string) (int64, error) {
	return s.storage.HeadEncryptedObject(ctx, objectID)
}

// CheckHealth checks connectivity to S3 and returns system status.
func (s *GatewayService) CheckHealth(ctx context.Context) *HealthResponse {
	storageStatus := "healthy"
	if err := s.storage.CheckHealth(ctx); err != nil {
		storageStatus = fmt.Sprintf("unhealthy: %v", err)
	}

	overallStatus := "ok"
	if storageStatus != "healthy" {
		overallStatus = "degraded"
	}

	return &HealthResponse{
		Status:    overallStatus,
		Version:   "1.0.0",
		Timestamp: time.Now().UTC(),
		Storage: map[string]string{
			"bucket": s.storage.BucketName(),
			"status": storageStatus,
		},
	}
}

// generateRandomID generates a cryptographically random 16-byte hex identifier (32 chars).
func generateRandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
