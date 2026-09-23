package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/crypto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
)

// MockKMSClient implements KMSAPI for fast, deterministic unit testing without AWS network calls.
type MockKMSClient struct {
	MasterKeyID   string
	AllowGenerate bool
	AllowDecrypt  bool

	// storedKeys maps [CiphertextBlob string] -> stored key data for verification
	storedKeys map[string]storedKey
}

type storedKey struct {
	plaintextKey []byte
	context      map[string]string
}

func NewMockKMSClient(masterKeyID string) *MockKMSClient {
	return &MockKMSClient{
		MasterKeyID:   masterKeyID,
		AllowGenerate: true,
		AllowDecrypt:  true,
		storedKeys:    make(map[string]storedKey),
	}
}

func (m *MockKMSClient) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if !m.AllowGenerate {
		return nil, &smithy.GenericAPIError{
			Code:    "AccessDeniedException",
			Message: "User is not authorized to perform: kms:GenerateDataKey",
		}
	}

	plaintextKey := make([]byte, crypto.KeySize)
	if _, err := rand.Read(plaintextKey); err != nil {
		return nil, fmt.Errorf("mock: failed to generate key: %w", err)
	}

	// In a real KMS, CiphertextBlob is the data key encrypted under the master key.
	// For the mock, we generate a synthetic encrypted blob and record it in storedKeys.
	ciphertextBlob := make([]byte, 48)
	if _, err := rand.Read(ciphertextBlob); err != nil {
		return nil, fmt.Errorf("mock: failed to generate blob: %w", err)
	}

	keyCopy := make([]byte, len(plaintextKey))
	copy(keyCopy, plaintextKey)

	contextCopy := make(map[string]string)
	for k, v := range params.EncryptionContext {
		contextCopy[k] = v
	}

	m.storedKeys[string(ciphertextBlob)] = storedKey{
		plaintextKey: keyCopy,
		context:      contextCopy,
	}

	return &kms.GenerateDataKeyOutput{
		KeyId:          aws.String(m.MasterKeyID),
		Plaintext:      plaintextKey,
		CiphertextBlob: ciphertextBlob,
	}, nil
}

func (m *MockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if !m.AllowDecrypt {
		return nil, &smithy.GenericAPIError{
			Code:    "AccessDeniedException",
			Message: "User: arn:aws:iam::123456789012:user/unauthorized is not authorized to perform: kms:Decrypt",
		}
	}

	record, exists := m.storedKeys[string(params.CiphertextBlob)]
	if !exists {
		return nil, &smithy.GenericAPIError{
			Code:    "InvalidCiphertextException",
			Message: "The ciphertext references a key that does not exist or cannot be decrypted.",
		}
	}

	// Verify cryptographic binding via EncryptionContext
	if len(record.context) != len(params.EncryptionContext) {
		return nil, &smithy.GenericAPIError{
			Code:    "InvalidCiphertextException",
			Message: "EncryptionContext count mismatch",
		}
	}

	for k, expectedVal := range record.context {
		actualVal, ok := params.EncryptionContext[k]
		if !ok || actualVal != expectedVal {
			return nil, &smithy.GenericAPIError{
				Code:    "InvalidCiphertextException",
				Message: fmt.Sprintf("EncryptionContext mismatch for key '%s'", k),
			}
		}
	}

	// Return a copy of the plaintext key
	keyReturn := make([]byte, len(record.plaintextKey))
	copy(keyReturn, record.plaintextKey)

	return &kms.DecryptOutput{
		KeyId:     aws.String(m.MasterKeyID),
		Plaintext: keyReturn,
	}, nil
}

func TestEnvelope_RoundTrip(t *testing.T) {
	masterKey := "arn:aws:kms:eu-central-1:772607727749:key/vaultgate-master"
	mockKMS := NewMockKMSClient(masterKey)
	service := NewService(mockKMS, masterKey)

	ctx := context.Background()
	objectID := "exam-paper-2026-cs101"
	originalData := []byte("CONFIDENTIAL: Lebanese University Computer Science Exam Questions")

	// 1. Wrap and Encrypt
	env, err := service.WrapAndEncrypt(ctx, objectID, originalData)
	if err != nil {
		t.Fatalf("WrapAndEncrypt failed: %v", err)
	}

	if env.ObjectID != objectID {
		t.Errorf("Expected ObjectID %s, got %s", objectID, env.ObjectID)
	}
	if len(env.EncryptedDataKey) == 0 {
		t.Error("EncryptedDataKey is empty")
	}
	if len(env.IV) != crypto.IVSize {
		t.Errorf("Expected IV length %d, got %d", crypto.IVSize, len(env.IV))
	}
	if len(env.AuthTag) != crypto.TagSize {
		t.Errorf("Expected AuthTag length %d, got %d", crypto.TagSize, len(env.AuthTag))
	}
	if bytes.Equal(env.Ciphertext, originalData) {
		t.Error("Ciphertext is identical to plaintext! Encryption failed.")
	}

	// 2. Decrypt and Unwrap
	decrypted, err := service.DecryptAndUnwrap(ctx, env)
	if err != nil {
		t.Fatalf("DecryptAndUnwrap failed: %v", err)
	}

	if !bytes.Equal(decrypted, originalData) {
		t.Fatalf("Decrypted data does not match original! Got %s, want %s", string(decrypted), string(originalData))
	}
}

func TestEnvelope_AccessDenied(t *testing.T) {
	masterKey := "arn:aws:kms:eu-central-1:772607727749:key/vaultgate-master"
	mockKMS := NewMockKMSClient(masterKey)
	service := NewService(mockKMS, masterKey)

	ctx := context.Background()
	objectID := "sensitive-salary-data"
	plaintext := []byte("Executive compensations")

	// Encrypt successfully while authorized
	env, err := service.WrapAndEncrypt(ctx, objectID, plaintext)
	if err != nil {
		t.Fatalf("WrapAndEncrypt failed: %v", err)
	}

	// SIMULATE IAM REVOCATION: Attacker dumps S3 bucket but has no kms:Decrypt permission
	mockKMS.AllowDecrypt = false

	_, err = service.DecryptAndUnwrap(ctx, env)
	if err == nil {
		t.Fatal("Expected DecryptAndUnwrap to fail with AccessDenied, but it succeeded!")
	}

	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Expected error wrapping ErrAccessDenied, got: %v", err)
	}
}

func TestEnvelope_EncryptionContextTamperRejection(t *testing.T) {
	masterKey := "arn:aws:kms:eu-central-1:772607727749:key/vaultgate-master"
	mockKMS := NewMockKMSClient(masterKey)
	service := NewService(mockKMS, masterKey)

	ctx := context.Background()

	// Encrypt Object A
	envA, err := service.WrapAndEncrypt(ctx, "object-a-public-notice", []byte("Public notice: Exam postponed"))
	if err != nil {
		t.Fatalf("WrapAndEncrypt failed: %v", err)
	}

	// Attacker tries to use Object A's encrypted key to decrypt under Object B's identity
	tamperedEnv := *envA
	tamperedEnv.ObjectID = "object-b-secret-answers"

	_, err = service.DecryptAndUnwrap(ctx, &tamperedEnv)
	if err == nil {
		t.Fatal("Expected DecryptAndUnwrap to reject mismatched ObjectID/EncryptionContext, but it succeeded!")
	}

	if !errors.Is(err, ErrEncryptionContextMismatch) {
		t.Fatalf("Expected ErrEncryptionContextMismatch, got: %v", err)
	}
}

func TestEnvelope_CiphertextTamperRejection(t *testing.T) {
	masterKey := "arn:aws:kms:eu-central-1:772607727749:key/vaultgate-master"
	mockKMS := NewMockKMSClient(masterKey)
	service := NewService(mockKMS, masterKey)

	ctx := context.Background()
	env, err := service.WrapAndEncrypt(ctx, "record-123", []byte("Original grade: B"))
	if err != nil {
		t.Fatalf("WrapAndEncrypt failed: %v", err)
	}

	// Attacker tampers with ciphertext directly in S3
	env.Ciphertext[0] ^= 0x01

	_, err = service.DecryptAndUnwrap(ctx, env)
	if err == nil {
		t.Fatal("Expected DecryptAndUnwrap to fail on tampered ciphertext, but it succeeded!")
	}
}

func TestEnvelope_InvalidInputs(t *testing.T) {
	masterKey := "arn:aws:kms:eu-central-1:772607727749:key/vaultgate-master"
	mockKMS := NewMockKMSClient(masterKey)
	service := NewService(mockKMS, masterKey)
	ctx := context.Background()

	t.Run("empty object id", func(t *testing.T) {
		_, err := service.WrapAndEncrypt(ctx, "", []byte("test"))
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Expected ErrInvalidEnvelope, got: %v", err)
		}
	})

	t.Run("nil envelope", func(t *testing.T) {
		_, err := service.DecryptAndUnwrap(ctx, nil)
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Expected ErrInvalidEnvelope, got: %v", err)
		}
	})
}
