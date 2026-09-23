package envelope

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/crypto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// KMSAPI defines the subset of AWS KMS operations required for envelope encryption.
// Using this interface allows clean dependency injection and offline unit testing without real AWS calls.
type KMSAPI interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Service manages the envelope encryption lifecycle: asking KMS for wrapped data keys,
// encrypting/decrypting file payloads with AES-256-GCM, and enforcing memory zeroization.
type Service struct {
	kmsClient KMSAPI
	kmsKeyID  string
}

// NewService instantiates an envelope encryption orchestrator with a KMS client and master key ID/ARN.
func NewService(kmsClient KMSAPI, kmsKeyID string) *Service {
	return &Service{
		kmsClient: kmsClient,
		kmsKeyID:  kmsKeyID,
	}
}

// WrapAndEncrypt implements the upload envelope encryption workflow:
//  1. Calls KMS GenerateDataKey to acquire a random 256-bit AES key bound to {"object_id": objectID}.
//  2. Encrypts the plaintext using AES-256-GCM with the plaintext data key and a fresh 96-bit IV.
//  3. Implements memory zeroization (ZeroBytes) to immediately wipe the plaintext data key from RAM.
//  4. Returns the EncryptedEnvelope containing ciphertext, IV, auth tag, and KMS-encrypted data key.
func (s *Service) WrapAndEncrypt(ctx context.Context, objectID string, plaintext []byte) (*EncryptedEnvelope, error) {
	if objectID == "" {
		return nil, fmt.Errorf("%w: objectID cannot be empty", ErrInvalidEnvelope)
	}

	// 1. Request a 256-bit data key from KMS with cryptographic binding
	genInput := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(s.kmsKeyID),
		KeySpec: types.DataKeySpecAes256,
		EncryptionContext: map[string]string{
			"object_id": objectID,
		},
	}

	genOut, err := s.kmsClient.GenerateDataKey(ctx, genInput)
	if err != nil {
		return nil, s.mapKMSError(err)
	}

	plaintextDataKey := genOut.Plaintext
	// CRITICAL SECURITY CONTROL: Zero out plaintext key from memory immediately upon exit
	defer crypto.ZeroBytes(plaintextDataKey)

	// 2. Generate a random 96-bit (12-byte) IV
	iv, err := crypto.GenerateIV()
	if err != nil {
		return nil, fmt.Errorf("envelope: failed to generate IV: %w", err)
	}

	// 3. Encrypt payload with AES-256-GCM, binding objectID as Additional Authenticated Data (AAD)
	ciphertext, authTag, err := crypto.Encrypt(plaintext, plaintextDataKey, iv, []byte(objectID))
	if err != nil {
		return nil, fmt.Errorf("envelope: payload encryption failed: %w", err)
	}

	kmsKeyID := s.kmsKeyID
	if genOut.KeyId != nil {
		kmsKeyID = *genOut.KeyId
	}

	return &EncryptedEnvelope{
		ObjectID:         objectID,
		S3Key:            fmt.Sprintf("objects/%s", objectID),
		Ciphertext:       ciphertext,
		IV:               iv,
		AuthTag:          authTag,
		EncryptedDataKey: genOut.CiphertextBlob,
		KMSKeyID:         kmsKeyID,
		CreatedAt:        time.Now().UTC(),
	}, nil
}

// DecryptAndUnwrap implements the download envelope decryption workflow:
//  1. Validates the envelope metadata.
//  2. Calls KMS Decrypt to unwrap the encrypted data key, verifying the cryptographic context.
//  3. Decrypts the ciphertext using AES-256-GCM.
//  4. Immediately zeroes out the plaintext data key from memory.
//  5. Returns the original decrypted file bytes.
func (s *Service) DecryptAndUnwrap(ctx context.Context, env *EncryptedEnvelope) ([]byte, error) {
	if env == nil || len(env.EncryptedDataKey) == 0 || len(env.IV) == 0 || len(env.AuthTag) == 0 {
		return nil, ErrInvalidEnvelope
	}

	// 1. Call KMS to decrypt the wrapped data key
	decInput := &kms.DecryptInput{
		CiphertextBlob: env.EncryptedDataKey,
		KeyId:          aws.String(s.kmsKeyID),
		EncryptionContext: map[string]string{
			"object_id": env.ObjectID,
		},
	}

	decOut, err := s.kmsClient.Decrypt(ctx, decInput)
	if err != nil {
		return nil, s.mapKMSError(err)
	}

	plaintextDataKey := decOut.Plaintext
	// CRITICAL SECURITY CONTROL: Zero out plaintext key from memory immediately upon exit
	defer crypto.ZeroBytes(plaintextDataKey)

	// 2. Decrypt ciphertext with AES-256-GCM and verify integrity tag
	plaintext, err := crypto.Decrypt(env.Ciphertext, plaintextDataKey, env.IV, env.AuthTag, []byte(env.ObjectID))
	if err != nil {
		return nil, fmt.Errorf("envelope: decryption failed: %w", err)
	}

	return plaintext, nil
}

// mapKMSError classifies AWS KMS errors into explicit domain errors (e.g. AccessDenied vs ContextMismatch).
func (s *Service) mapKMSError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException", "AccessDenied":
			return fmt.Errorf("%w: %s", ErrAccessDenied, apiErr.ErrorMessage())
		case "InvalidCiphertextException":
			return fmt.Errorf("%w: %s", ErrEncryptionContextMismatch, apiErr.ErrorMessage())
		default:
			return fmt.Errorf("%w: %s: %s", ErrKMSFailure, apiErr.ErrorCode(), apiErr.ErrorMessage())
		}
	}
	return fmt.Errorf("%w: %v", ErrKMSFailure, err)
}
