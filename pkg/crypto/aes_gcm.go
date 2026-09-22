package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize is the required byte size for AES-256 keys (32 bytes = 256 bits).
	KeySize = 32

	// IVSize is the standard recommended byte size for AES-GCM nonces (12 bytes = 96 bits).
	// Using exactly 12 bytes avoids GHASH computational overhead on the IV and aligns
	// with NIST SP 800-38D recommendations.
	IVSize = 12

	// TagSize is the standard authentication tag size produced by AES-GCM (16 bytes = 128 bits).
	TagSize = 16
)

var (
	// ErrInvalidKeySize is returned when an encryption key is not exactly 32 bytes.
	ErrInvalidKeySize = errors.New("crypto: invalid key size; expected 32 bytes for AES-256")

	// ErrInvalidIVSize is returned when an IV is not exactly 12 bytes.
	ErrInvalidIVSize = errors.New("crypto: invalid IV size; expected 12 bytes for AES-GCM")

	// ErrInvalidTagSize is returned when an auth tag is not exactly 16 bytes.
	ErrInvalidTagSize = errors.New("crypto: invalid tag size; expected 16 bytes")

	// ErrAuthenticationFailed is returned when ciphertext or auth tag verification fails.
	ErrAuthenticationFailed = errors.New("crypto: authentication failed; ciphertext or tag was tampered with")
)

// GenerateKey generates a cryptographically secure 256-bit (32-byte) AES key
// using the operating system's CSPRNG (crypto/rand).
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate random key: %w", err)
	}
	return key, nil
}

// GenerateIV generates a cryptographically secure 96-bit (12-byte) Initialization Vector (IV).
// For AES-GCM, an IV must never be repeated with the same data key.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate random IV: %w", err)
	}
	return iv, nil
}

// Encrypt performs AES-256-GCM authenticated encryption on plaintext using the supplied
// 256-bit key and 96-bit IV. It accepts optional additional authenticated data (AAD)
// which is cryptographically authenticated but not encrypted.
//
// Returns the raw ciphertext and the 16-byte authentication tag separately,
// matching the VaultGate storage metadata schema.
func Encrypt(plaintext, key, iv, additionalData []byte) (ciphertext []byte, authTag []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, ErrInvalidKeySize
	}
	if len(iv) != IVSize {
		return nil, nil, ErrInvalidIVSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to initialize AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to initialize GCM mode: %w", err)
	}

	// gcm.Seal encrypts the plaintext and appends the 16-byte auth tag at the end.
	sealed := gcm.Seal(nil, iv, plaintext, additionalData)

	// Split sealed output into separate ciphertext and auth tag
	splitIdx := len(sealed) - TagSize
	ciphertext = make([]byte, splitIdx)
	copy(ciphertext, sealed[:splitIdx])

	authTag = make([]byte, TagSize)
	copy(authTag, sealed[splitIdx:])

	return ciphertext, authTag, nil
}

// Decrypt verifies the integrity and authenticity of the ciphertext using AES-256-GCM
// and returns the original plaintext. If any bit of the ciphertext, IV, auth tag,
// or additional authenticated data (AAD) has been modified, decryption fails loudly
// and returns ErrAuthenticationFailed.
func Decrypt(ciphertext, key, iv, authTag, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(iv) != IVSize {
		return nil, ErrInvalidIVSize
	}
	if len(authTag) != TagSize {
		return nil, ErrInvalidTagSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize GCM mode: %w", err)
	}

	// Reassemble the sealed buffer expected by Go's cipher.AEAD: [ciphertext || authTag]
	sealed := make([]byte, len(ciphertext)+len(authTag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], authTag)

	plaintext, err := gcm.Open(nil, iv, sealed, additionalData)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	return plaintext, nil
}
