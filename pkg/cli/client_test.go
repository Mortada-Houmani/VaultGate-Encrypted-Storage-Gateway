package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/api"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/crypto"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type MockKMSForClient struct {
	keyID     string
	masterKey []byte
}

func (m *MockKMSForClient) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	plainKey := make([]byte, 32)
	_, _ = rand.Read(plainKey)
	iv, _ := crypto.GenerateIV()
	aad := []byte(params.EncryptionContext["object_id"])
	ct, tag, _ := crypto.Encrypt(plainKey, m.masterKey, iv, aad)
	wrapped := append(iv, append(tag, ct...)...)
	return &kms.GenerateDataKeyOutput{
		KeyId:          aws.String(m.keyID),
		Plaintext:      plainKey,
		CiphertextBlob: wrapped,
	}, nil
}

func (m *MockKMSForClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	blob := params.CiphertextBlob
	iv := blob[:12]
	tag := blob[12:28]
	ct := blob[28:]
	aad := []byte(params.EncryptionContext["object_id"])
	plainKey, err := crypto.Decrypt(ct, m.masterKey, iv, tag, aad)
	if err != nil {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException", Message: "Context mismatch"}
	}
	return &kms.DecryptOutput{
		KeyId:     aws.String(m.keyID),
		Plaintext: plainKey,
	}, nil
}

func (m *MockKMSForClient) ReEncrypt(ctx context.Context, params *kms.ReEncryptInput, optFns ...func(*kms.Options)) (*kms.ReEncryptOutput, error) {
	blob := params.CiphertextBlob
	iv := blob[:12]
	tag := blob[12:28]
	ct := blob[28:]
	aad := []byte(params.SourceEncryptionContext["object_id"])
	plainKey, err := crypto.Decrypt(ct, m.masterKey, iv, tag, aad)
	if err != nil {
		return nil, err
	}
	newIV, _ := crypto.GenerateIV()
	destAAD := []byte(params.DestinationEncryptionContext["object_id"])
	newCT, newTag, _ := crypto.Encrypt(plainKey, m.masterKey, newIV, destAAD)
	newBlob := append(newIV, append(newTag, newCT...)...)
	destKeyID := m.keyID
	if params.DestinationKeyId != nil {
		destKeyID = *params.DestinationKeyId
	}
	return &kms.ReEncryptOutput{
		KeyId:          aws.String(destKeyID),
		CiphertextBlob: newBlob,
	}, nil
}

type MockS3ForClient struct {
	objects map[string][]byte
	meta    map[string]map[string]string
}

func NewMockS3ForClient() *MockS3ForClient {
	return &MockS3ForClient{
		objects: make(map[string][]byte),
		meta:    make(map[string]map[string]string),
	}
}

func (m *MockS3ForClient) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(params.Body)
	m.objects[*params.Key] = buf.Bytes()
	m.meta[*params.Key] = params.Metadata
	return &s3.PutObjectOutput{}, nil
}

func (m *MockS3ForClient) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	data, exists := m.objects[*params.Key]
	if !exists {
		return nil, &s3types.NoSuchKey{Message: aws.String("NoSuchKey")}
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(data)),
		Metadata:      m.meta[*params.Key],
		ContentLength: aws.Int64(int64(len(data))),
	}, nil
}

func (m *MockS3ForClient) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(m.objects, *params.Key)
	delete(m.meta, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *MockS3ForClient) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	data, exists := m.objects[*params.Key]
	if !exists {
		return nil, &s3types.NotFound{Message: aws.String("NotFound")}
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(data))),
		Metadata:      m.meta[*params.Key],
	}, nil
}

func (m *MockS3ForClient) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func (m *MockS3ForClient) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	data, exists := m.objects[*params.Key]
	if !exists {
		return nil, &s3types.NoSuchKey{Message: aws.String("NoSuchKey")}
	}
	m.meta[*params.Key] = params.Metadata
	m.objects[*params.Key] = data
	return &s3.CopyObjectOutput{}, nil
}

func setupClientTestServer(t *testing.T) (*httptest.Server, *Client) {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	mockKMS := &MockKMSForClient{keyID: "arn:aws:kms:us-east-1:123456789012:key/test", masterKey: k}
	envService := envelope.NewService(mockKMS, mockKMS.keyID)
	mockS3 := NewMockS3ForClient()
	s3Storage := storage.NewS3Storage(mockS3, "test-bucket")

	gw := api.NewGatewayService(envService, s3Storage)
	handler := api.NewHandler(gw)
	router := api.NewRouter(handler)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	client := NewClient(server.URL)
	return server, client
}

func TestClient_Lifecycle(t *testing.T) {
	_, client := setupClientTestServer(t)
	ctx := context.Background()

	// 1. Health
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	if health.Status != "ok" {
		t.Errorf("expected status ok, got %s", health.Status)
	}

	// 2. Upload
	payload := []byte("Top Confidential Document: AI Algorithm Blueprint")
	upRes, err := client.Upload(ctx, "blueprint-01", payload)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	if upRes.ObjectID != "blueprint-01" {
		t.Errorf("expected object ID blueprint-01, got %s", upRes.ObjectID)
	}

	// 3. Download
	downData, meta, err := client.Download(ctx, "blueprint-01")
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if !bytes.Equal(downData, payload) {
		t.Errorf("decrypted data mismatch: got %s, want %s", string(downData), string(payload))
	}
	if meta.ObjectID != "blueprint-01" {
		t.Errorf("expected meta object ID blueprint-01, got %s", meta.ObjectID)
	}

	// 4. ReWrap
	reRes, err := client.ReWrap(ctx, "blueprint-01", "arn:aws:kms:us-east-1:123456789012:key/rotated-key")
	if err != nil {
		t.Fatalf("ReWrap failed: %v", err)
	}
	if reRes.NewKMSKeyID != "arn:aws:kms:us-east-1:123456789012:key/rotated-key" {
		t.Errorf("expected new key ID, got %s", reRes.NewKMSKeyID)
	}

	// 5. Delete
	if err := client.Delete(ctx, "blueprint-01"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 6. Download after delete -> Error
	_, _, err = client.Download(ctx, "blueprint-01")
	if err == nil {
		t.Fatal("expected error downloading deleted object, got nil")
	}
}
