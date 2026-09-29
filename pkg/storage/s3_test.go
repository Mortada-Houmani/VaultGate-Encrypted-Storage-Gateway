package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// mockSmithyAPIError implements smithy.APIError for testing AWS error mapping.
type mockSmithyAPIError struct {
	code    string
	message string
}

func (m *mockSmithyAPIError) ErrorCode() string    { return m.code }
func (m *mockSmithyAPIError) ErrorMessage() string { return m.message }
func (m *mockSmithyAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}
func (m *mockSmithyAPIError) Error() string { return m.code + ": " + m.message }

// MockS3Client provides an in-memory S3 simulation for unit tests.
type MockS3Client struct {
	objects       map[string]*mockS3Object
	putErr        error
	getErr        error
	deleteErr     error
	headObjectErr error
	headBucketErr error
}

type mockS3Object struct {
	data     []byte
	metadata map[string]string
}

func NewMockS3Client() *MockS3Client {
	return &MockS3Client{
		objects: make(map[string]*mockS3Object),
	}
}

func (m *MockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}

	body, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}

	metaCopy := make(map[string]string)
	for k, v := range params.Metadata {
		metaCopy[k] = v
	}

	key := *params.Key
	m.objects[key] = &mockS3Object{
		data:     body,
		metadata: metaCopy,
	}

	return &s3.PutObjectOutput{}, nil
}

func (m *MockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	key := *params.Key
	obj, exists := m.objects[key]
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

func (m *MockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}

	delete(m.objects, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *MockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.headObjectErr != nil {
		return nil, m.headObjectErr
	}

	key := *params.Key
	obj, exists := m.objects[key]
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

func (m *MockS3Client) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.headBucketErr != nil {
		return nil, m.headBucketErr
	}
	return &s3.HeadBucketOutput{}, nil
}

func (m *MockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	key := *params.Key
	obj, exists := m.objects[key]
	if !exists {
		return nil, &s3types.NoSuchKey{
			Message: aws.String("The specified key does not exist."),
		}
	}

	metaCopy := make(map[string]string)
	for k, v := range params.Metadata {
		metaCopy[k] = v
	}

	m.objects[key] = &mockS3Object{
		data:     obj.data,
		metadata: metaCopy,
	}

	return &s3.CopyObjectOutput{}, nil
}

func TestS3Storage_PutAndGet_RoundTrip(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-vaultgate-bucket")

	if storage.BucketName() != "test-vaultgate-bucket" {
		t.Fatalf("expected bucket test-vaultgate-bucket, got %s", storage.BucketName())
	}

	env := &envelope.EncryptedEnvelope{
		ObjectID:         "doc-001",
		S3Key:            "objects/doc-001",
		Ciphertext:       []byte("super-secret-ciphertext-payload"),
		IV:               []byte("123456789012"),
		AuthTag:          []byte("1234567890123456"),
		EncryptedDataKey: []byte("kms-wrapped-key-bytes"),
		KMSKeyID:         "arn:aws:kms:us-east-1:123456789012:key/test-key",
		CreatedAt:        time.Now().UTC().Truncate(time.Millisecond),
	}

	ctx := context.Background()
	err := storage.PutEncryptedObject(ctx, env)
	if err != nil {
		t.Fatalf("PutEncryptedObject failed: %v", err)
	}

	// Verify GetEncryptedObject retrieves the envelope correctly
	recovered, err := storage.GetEncryptedObject(ctx, "doc-001")
	if err != nil {
		t.Fatalf("GetEncryptedObject failed: %v", err)
	}

	if recovered.ObjectID != env.ObjectID {
		t.Errorf("ObjectID mismatch: got %s, want %s", recovered.ObjectID, env.ObjectID)
	}
	if !bytes.Equal(recovered.Ciphertext, env.Ciphertext) {
		t.Errorf("Ciphertext mismatch: got %s, want %s", recovered.Ciphertext, env.Ciphertext)
	}
	if !bytes.Equal(recovered.IV, env.IV) {
		t.Errorf("IV mismatch: got %x, want %x", recovered.IV, env.IV)
	}
	if !bytes.Equal(recovered.AuthTag, env.AuthTag) {
		t.Errorf("AuthTag mismatch: got %x, want %x", recovered.AuthTag, env.AuthTag)
	}
	if !bytes.Equal(recovered.EncryptedDataKey, env.EncryptedDataKey) {
		t.Errorf("EncryptedDataKey mismatch: got %v, want %v", recovered.EncryptedDataKey, env.EncryptedDataKey)
	}
	if recovered.KMSKeyID != env.KMSKeyID {
		t.Errorf("KMSKeyID mismatch: got %s, want %s", recovered.KMSKeyID, env.KMSKeyID)
	}
}

func TestS3Storage_Get_NotFound(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-bucket")

	_, err := storage.GetEncryptedObject(context.Background(), "non-existent")
	if err == nil {
		t.Fatal("expected error for non-existent object, got nil")
	}
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound, got: %v", err)
	}
}

func TestS3Storage_Get_MissingMetadata(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-bucket")

	// Store raw object without envelope headers
	mockClient.objects["objects/bad-obj"] = &mockS3Object{
		data:     []byte("some data"),
		metadata: map[string]string{}, // Missing iv, auth-tag, etc.
	}

	_, err := storage.GetEncryptedObject(context.Background(), "bad-obj")
	if err == nil {
		t.Fatal("expected error for missing metadata, got nil")
	}
	if !errors.Is(err, ErrMissingMetadata) {
		t.Errorf("expected ErrMissingMetadata, got: %v", err)
	}
}

func TestS3Storage_Get_CorruptMetadata(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-bucket")

	// 1. Invalid IV hex
	mockClient.objects["objects/bad-iv"] = &mockS3Object{
		data: []byte("some data"),
		metadata: map[string]string{
			MetaKeyIV:           "not-a-valid-hex!!",
			MetaKeyAuthTag:      hex.EncodeToString([]byte("1234567890123456")),
			MetaKeyEncryptedKey: base64.StdEncoding.EncodeToString([]byte("wrapped-key")),
		},
	}

	_, err := storage.GetEncryptedObject(context.Background(), "bad-iv")
	if !errors.Is(err, ErrCorruptMetadata) {
		t.Errorf("expected ErrCorruptMetadata for bad IV, got: %v", err)
	}

	// 2. Invalid AuthTag hex
	mockClient.objects["objects/bad-tag"] = &mockS3Object{
		data: []byte("some data"),
		metadata: map[string]string{
			MetaKeyIV:           hex.EncodeToString([]byte("123456789012")),
			MetaKeyAuthTag:      "invalid-tag-hex@@",
			MetaKeyEncryptedKey: base64.StdEncoding.EncodeToString([]byte("wrapped-key")),
		},
	}

	_, err = storage.GetEncryptedObject(context.Background(), "bad-tag")
	if !errors.Is(err, ErrCorruptMetadata) {
		t.Errorf("expected ErrCorruptMetadata for bad AuthTag, got: %v", err)
	}

	// 3. Invalid EncryptedDataKey base64
	mockClient.objects["objects/bad-key"] = &mockS3Object{
		data: []byte("some data"),
		metadata: map[string]string{
			MetaKeyIV:           hex.EncodeToString([]byte("123456789012")),
			MetaKeyAuthTag:      hex.EncodeToString([]byte("1234567890123456")),
			MetaKeyEncryptedKey: "invalid===base64===",
		},
	}

	_, err = storage.GetEncryptedObject(context.Background(), "bad-key")
	if !errors.Is(err, ErrCorruptMetadata) {
		t.Errorf("expected ErrCorruptMetadata for bad EncryptedDataKey, got: %v", err)
	}
}

func TestS3Storage_InvalidInputs(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-bucket")
	ctx := context.Background()

	// Nil envelope on Put
	if err := storage.PutEncryptedObject(ctx, nil); err == nil {
		t.Error("expected error for nil envelope on Put")
	}

	// Empty objectID on Put
	if err := storage.PutEncryptedObject(ctx, &envelope.EncryptedEnvelope{}); err == nil {
		t.Error("expected error for empty objectID on Put")
	}

	// Empty objectID on Get
	if _, err := storage.GetEncryptedObject(ctx, ""); err == nil {
		t.Error("expected error for empty objectID on Get")
	}

	// Empty objectID on Delete
	if err := storage.DeleteEncryptedObject(ctx, ""); err == nil {
		t.Error("expected error for empty objectID on Delete")
	}

	// Empty objectID on Head
	if _, err := storage.HeadEncryptedObject(ctx, ""); err == nil {
		t.Error("expected error for empty objectID on Head")
	}
}

func TestS3Storage_DeleteAndHead(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-bucket")
	ctx := context.Background()

	env := &envelope.EncryptedEnvelope{
		ObjectID:         "doc-to-del",
		Ciphertext:       []byte("delete-me-payload"),
		IV:               []byte("123456789012"),
		AuthTag:          []byte("1234567890123456"),
		EncryptedDataKey: []byte("wrapped-key"),
		CreatedAt:        time.Now().UTC(),
	}

	if err := storage.PutEncryptedObject(ctx, env); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify HeadObject returns correct size
	size, err := storage.HeadEncryptedObject(ctx, "doc-to-del")
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}
	if size != int64(len("delete-me-payload")) {
		t.Errorf("expected size %d, got %d", len("delete-me-payload"), size)
	}

	// Delete
	if err := storage.DeleteEncryptedObject(ctx, "doc-to-del"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Subsequent Get must return ErrObjectNotFound
	_, err = storage.GetEncryptedObject(ctx, "doc-to-del")
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound after delete, got: %v", err)
	}
}

func TestS3Storage_ErrorMapping(t *testing.T) {
	ctx := context.Background()

	// 1. AccessDenied error
	mockClient := NewMockS3Client()
	mockClient.putErr = &mockSmithyAPIError{code: "AccessDenied", message: "User is not authorized to perform PutObject"}
	storage := NewS3Storage(mockClient, "test-bucket")

	env := &envelope.EncryptedEnvelope{
		ObjectID:         "denied-obj",
		Ciphertext:       []byte("data"),
		IV:               []byte("123456789012"),
		AuthTag:          []byte("1234567890123456"),
		EncryptedDataKey: []byte("key"),
	}

	err := storage.PutEncryptedObject(ctx, env)
	if !errors.Is(err, ErrStorageAccessDenied) {
		t.Errorf("expected ErrStorageAccessDenied, got: %v", err)
	}

	// 2. CheckHealth HeadBucket error
	mockClient.headBucketErr = &mockSmithyAPIError{code: "NoSuchBucket", message: "The bucket does not exist"}
	err = storage.CheckHealth(ctx)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound for missing bucket, got: %v", err)
	}
}

func TestS3Storage_UpdateEnvelopeMetadata(t *testing.T) {
	mockClient := NewMockS3Client()
	storage := NewS3Storage(mockClient, "test-bucket")
	ctx := context.Background()

	env := &envelope.EncryptedEnvelope{
		ObjectID:         "doc-update-meta",
		Ciphertext:       []byte("stable-ciphertext-never-changed"),
		IV:               []byte("123456789012"),
		AuthTag:          []byte("1234567890123456"),
		EncryptedDataKey: []byte("wrapped-key-v1"),
		KMSKeyID:         "arn:aws:kms:us-east-1:123456789012:key/key-v1",
		CreatedAt:        time.Now().UTC(),
	}

	if err := storage.PutEncryptedObject(ctx, env); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Update metadata (e.g. after KMS ReWrap to key-v2)
	updatedEnv := &envelope.EncryptedEnvelope{
		ObjectID:         "doc-update-meta",
		S3Key:            "objects/doc-update-meta",
		IV:               env.IV,
		AuthTag:          env.AuthTag,
		EncryptedDataKey: []byte("wrapped-key-v2-re-encrypted"),
		KMSKeyID:         "arn:aws:kms:us-east-1:123456789012:key/key-v2",
		CreatedAt:        env.CreatedAt,
	}

	if err := storage.UpdateEnvelopeMetadata(ctx, updatedEnv); err != nil {
		t.Fatalf("UpdateEnvelopeMetadata failed: %v", err)
	}

	// Retrieve object and assert that ciphertext is preserved and metadata is updated
	recovered, err := storage.GetEncryptedObject(ctx, "doc-update-meta")
	if err != nil {
		t.Fatalf("GetEncryptedObject failed: %v", err)
	}

	if !bytes.Equal(recovered.Ciphertext, []byte("stable-ciphertext-never-changed")) {
		t.Errorf("Ciphertext was altered during metadata update! Got %s", string(recovered.Ciphertext))
	}
	if recovered.KMSKeyID != "arn:aws:kms:us-east-1:123456789012:key/key-v2" {
		t.Errorf("expected KMSKeyID key-v2, got %s", recovered.KMSKeyID)
	}
	if !bytes.Equal(recovered.EncryptedDataKey, []byte("wrapped-key-v2-re-encrypted")) {
		t.Errorf("expected updated data key, got %s", string(recovered.EncryptedDataKey))
	}
}
