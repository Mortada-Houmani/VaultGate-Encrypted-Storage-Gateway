package envelope

import (
	"errors"
	"time"
)

var (
	// ErrAccessDenied is returned when KMS rejects Decrypt due to missing or revoked IAM permissions.
	ErrAccessDenied = errors.New("envelope: access denied; caller lacks KMS Decrypt permission")

	// ErrInvalidEnvelope is returned when an envelope payload is missing mandatory fields.
	ErrInvalidEnvelope = errors.New("envelope: invalid envelope; missing required metadata")

	// ErrEncryptionContextMismatch is returned when the object ID or context does not match KMS authenticated data.
	ErrEncryptionContextMismatch = errors.New("envelope: encryption context mismatch; key cannot be decrypted for this object")

	// ErrKMSFailure is returned when an unexpected KMS API error occurs.
	ErrKMSFailure = errors.New("envelope: KMS operation failed")
)

// EncryptedEnvelope contains the encrypted payload and all cryptographic metadata
// required to safely reconstruct and decrypt the object in S3.
//
// No plaintext data or plaintext key material is EVER stored inside this struct.
type EncryptedEnvelope struct {
	// ObjectID is the unique identifier for the stored resource (e.g. UUID, filename, exam ID).
	ObjectID string `json:"object_id"`

	// S3Key is the path under which the ciphertext is stored in the S3 bucket.
	S3Key string `json:"s3_key"`

	// Ciphertext is the AES-256-GCM encrypted content bytes.
	Ciphertext []byte `json:"-"`

	// IV is the 96-bit (12-byte) AES-GCM initialization vector.
	IV []byte `json:"iv"`

	// AuthTag is the 128-bit (16-byte) AES-GCM authentication tag.
	AuthTag []byte `json:"auth_tag"`

	// EncryptedDataKey is the 256-bit AES data key, wrapped by AWS KMS under the master key.
	// Safe to store alongside the ciphertext because it requires KMS Decrypt permissions to unlock.
	EncryptedDataKey []byte `json:"encrypted_data_key"`

	// KMSKeyID identifies the master KMS key (ARN or alias) that encrypted the data key.
	KMSKeyID string `json:"kms_key_id"`

	// CreatedAt is the timestamp when the object was encrypted and sealed.
	CreatedAt time.Time `json:"created_at"`
}
