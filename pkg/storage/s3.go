package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

var (
	// ErrObjectNotFound is returned when an object is not found in the S3 bucket.
	ErrObjectNotFound = errors.New("storage: object not found in S3")

	// ErrStorageAccessDenied is returned when S3 rejects Put/Get/Delete due to IAM permissions.
	ErrStorageAccessDenied = errors.New("storage: access denied to S3 bucket or object")

	// ErrMissingMetadata is returned when essential envelope encryption metadata is missing in S3 headers.
	ErrMissingMetadata = errors.New("storage: missing envelope encryption metadata in S3 object headers")

	// ErrCorruptMetadata is returned when metadata headers cannot be decoded (e.g. invalid hex/base64).
	ErrCorruptMetadata = errors.New("storage: corrupt envelope metadata in S3 headers")

	// ErrS3Failure is returned when an unexpected S3 API error occurs.
	ErrS3Failure = errors.New("storage: S3 operation failed")
)

// S3 Metadata Key constants (lowercase as expected by AWS SDK Go v2 Metadata map)
const (
	MetaKeyIV           = "iv"
	MetaKeyAuthTag      = "auth-tag"
	MetaKeyEncryptedKey = "encrypted-data-key"
	MetaKeyKMSKeyID     = "kms-key-id"
	MetaKeyObjectID     = "object-id"
	MetaKeyAlgorithm    = "algorithm"
	MetaKeyCreatedAt    = "created-at"

	AlgorithmAES256GCM = "AES-256-GCM"
)

// S3API defines the subset of AWS S3 operations required for storing encrypted objects.
// Using this interface allows offline unit testing with mocks.
type S3API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// Storage is the interface for persisting and retrieving encrypted envelope objects.
type Storage interface {
	PutEncryptedObject(ctx context.Context, env *envelope.EncryptedEnvelope) error
	GetEncryptedObject(ctx context.Context, objectID string) (*envelope.EncryptedEnvelope, error)
	DeleteEncryptedObject(ctx context.Context, objectID string) error
	HeadEncryptedObject(ctx context.Context, objectID string) (int64, error)
	CheckHealth(ctx context.Context) error
	BucketName() string
}

// S3Storage persists ciphertext blobs in S3 and encodes cryptographic envelope metadata
// into S3 user-defined object metadata headers (x-amz-meta-*).
type S3Storage struct {
	client S3API
	bucket string
}

// NewS3Storage instantiates an S3 encrypted object storage provider.
func NewS3Storage(client S3API, bucket string) *S3Storage {
	return &S3Storage{
		client: client,
		bucket: bucket,
	}
}

// BucketName returns the configured S3 bucket name.
func (s *S3Storage) BucketName() string {
	return s.bucket
}

// PutEncryptedObject uploads ciphertext to S3 and attaches all envelope metadata as object headers.
func (s *S3Storage) PutEncryptedObject(ctx context.Context, env *envelope.EncryptedEnvelope) error {
	if env == nil || env.ObjectID == "" {
		return fmt.Errorf("%w: envelope or object ID is nil", envelope.ErrInvalidEnvelope)
	}

	metadata := map[string]string{
		MetaKeyIV:           hex.EncodeToString(env.IV),
		MetaKeyAuthTag:      hex.EncodeToString(env.AuthTag),
		MetaKeyEncryptedKey: base64.StdEncoding.EncodeToString(env.EncryptedDataKey),
		MetaKeyKMSKeyID:     env.KMSKeyID,
		MetaKeyObjectID:     env.ObjectID,
		MetaKeyAlgorithm:    AlgorithmAES256GCM,
		MetaKeyCreatedAt:    env.CreatedAt.UTC().Format(time.RFC3339Nano),
	}

	s3Key := env.S3Key
	if s3Key == "" {
		s3Key = fmt.Sprintf("objects/%s", env.ObjectID)
	}

	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s3Key),
		Body:        bytes.NewReader(env.Ciphertext),
		Metadata:    metadata,
		ContentType: aws.String("application/octet-stream"),
	}

	_, err := s.client.PutObject(ctx, input)
	if err != nil {
		return s.mapS3Error(err)
	}

	return nil
}

// GetEncryptedObject retrieves the ciphertext blob and envelope metadata headers from S3.
func (s *S3Storage) GetEncryptedObject(ctx context.Context, objectID string) (*envelope.EncryptedEnvelope, error) {
	if objectID == "" {
		return nil, fmt.Errorf("%w: objectID cannot be empty", envelope.ErrInvalidEnvelope)
	}

	s3Key := fmt.Sprintf("objects/%s", objectID)
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, s.mapS3Error(err)
	}
	defer output.Body.Close()

	ciphertext, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read object body from S3: %v", ErrS3Failure, err)
	}

	// Reconstruct Envelope from Metadata
	meta := output.Metadata
	ivHex := getMetadataValue(meta, MetaKeyIV)
	authTagHex := getMetadataValue(meta, MetaKeyAuthTag)
	encKeyB64 := getMetadataValue(meta, MetaKeyEncryptedKey)
	kmsKeyID := getMetadataValue(meta, MetaKeyKMSKeyID)

	if ivHex == "" || authTagHex == "" || encKeyB64 == "" {
		return nil, fmt.Errorf("%w: missing required cryptographic headers (iv, auth-tag, or encrypted-key)", ErrMissingMetadata)
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid IV hex encoding: %v", ErrCorruptMetadata, err)
	}

	authTag, err := hex.DecodeString(authTagHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid AuthTag hex encoding: %v", ErrCorruptMetadata, err)
	}

	encDataKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid EncryptedDataKey base64 encoding: %v", ErrCorruptMetadata, err)
	}

	createdAt := time.Now().UTC()
	if createdStr := getMetadataValue(meta, MetaKeyCreatedAt); createdStr != "" {
		if parsed, parseErr := time.Parse(time.RFC3339Nano, createdStr); parseErr == nil {
			createdAt = parsed
		}
	}

	return &envelope.EncryptedEnvelope{
		ObjectID:         objectID,
		S3Key:            s3Key,
		Ciphertext:       ciphertext,
		IV:               iv,
		AuthTag:          authTag,
		EncryptedDataKey: encDataKey,
		KMSKeyID:         kmsKeyID,
		CreatedAt:        createdAt,
	}, nil
}

// DeleteEncryptedObject deletes the object from S3.
func (s *S3Storage) DeleteEncryptedObject(ctx context.Context, objectID string) error {
	if objectID == "" {
		return fmt.Errorf("%w: objectID cannot be empty", envelope.ErrInvalidEnvelope)
	}

	s3Key := fmt.Sprintf("objects/%s", objectID)
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	_, err := s.client.DeleteObject(ctx, input)
	if err != nil {
		return s.mapS3Error(err)
	}

	return nil
}

// HeadEncryptedObject retrieves object existence and size without downloading the body.
func (s *S3Storage) HeadEncryptedObject(ctx context.Context, objectID string) (int64, error) {
	if objectID == "" {
		return 0, fmt.Errorf("%w: objectID cannot be empty", envelope.ErrInvalidEnvelope)
	}

	s3Key := fmt.Sprintf("objects/%s", objectID)
	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	output, err := s.client.HeadObject(ctx, input)
	if err != nil {
		return 0, s.mapS3Error(err)
	}

	if output.ContentLength != nil {
		return *output.ContentLength, nil
	}
	return 0, nil
}

// CheckHealth verifies connectivity to the S3 bucket.
func (s *S3Storage) CheckHealth(ctx context.Context) error {
	input := &s3.HeadBucketInput{
		Bucket: aws.String(s.bucket),
	}
	_, err := s.client.HeadBucket(ctx, input)
	if err != nil {
		return s.mapS3Error(err)
	}
	return nil
}

// getMetadataValue retrieves a metadata field checking case-insensitive keys
// and handling potential "x-amz-meta-" prefixes.
func getMetadataValue(meta map[string]string, key string) string {
	if meta == nil {
		return ""
	}
	keyLower := strings.ToLower(key)
	for k, v := range meta {
		cleanK := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
		if cleanK == keyLower {
			return v
		}
	}
	return ""
}

// mapS3Error classifies AWS S3 errors into domain errors (ErrObjectNotFound, ErrStorageAccessDenied, ErrS3Failure).
func (s *S3Storage) mapS3Error(err error) error {
	if err == nil {
		return nil
	}

	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %s", ErrObjectNotFound, notFound.ErrorMessage())
	}

	var noSuchKey *s3types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return fmt.Errorf("%w: %s", ErrObjectNotFound, noSuchKey.ErrorMessage())
	}

	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return fmt.Errorf("%w: %s", ErrObjectNotFound, noSuchBucket.ErrorMessage())
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NotFound", "NoSuchKey", "NoSuchBucket", "404":
			return fmt.Errorf("%w: %s", ErrObjectNotFound, apiErr.ErrorMessage())
		case "AccessDenied", "Forbidden", "403":
			return fmt.Errorf("%w: %s", ErrStorageAccessDenied, apiErr.ErrorMessage())
		default:
			return fmt.Errorf("%w: %s: %s", ErrS3Failure, apiErr.ErrorCode(), apiErr.ErrorMessage())
		}
	}

	return fmt.Errorf("%w: %v", ErrS3Failure, err)
}
