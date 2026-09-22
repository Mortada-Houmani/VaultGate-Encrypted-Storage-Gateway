package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	testCases := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{
			name:      "simple string",
			plaintext: []byte("Hello, VaultGate! Secure envelope storage gateway."),
			aad:       []byte("metadata-context-1234"),
		},
		{
			name:      "empty plaintext",
			plaintext: []byte(""),
			aad:       nil,
		},
		{
			name:      "large 1MB binary payload",
			plaintext: make([]byte, 1024*1024),
			aad:       []byte("object-large-blob"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.plaintext) > 100 {
				_, _ = rand.Read(tc.plaintext)
			}

			key, err := GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			defer ZeroBytes(key)

			iv, err := GenerateIV()
			if err != nil {
				t.Fatalf("GenerateIV failed: %v", err)
			}

			ciphertext, tag, err := Encrypt(tc.plaintext, key, iv, tc.aad)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if len(tag) != TagSize {
				t.Fatalf("Expected tag size %d, got %d", TagSize, len(tag))
			}

			decrypted, err := Decrypt(ciphertext, key, iv, tag, tc.aad)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Fatalf("Decrypted plaintext does not match original! Got %d bytes, want %d bytes", len(decrypted), len(tc.plaintext))
			}
		})
	}
}

func TestDecrypt_TamperDetection(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer ZeroBytes(key)

	iv, err := GenerateIV()
	if err != nil {
		t.Fatalf("GenerateIV failed: %v", err)
	}

	plaintext := []byte("Sensitive exam document contents: Final Grade A+")
	aad := []byte("object-id: lu-exam-2026-001")

	ciphertext, tag, err := Encrypt(plaintext, key, iv, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	t.Run("flip single bit in ciphertext", func(t *testing.T) {
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		// Flip the first bit of the first byte
		tamperedCiphertext[0] ^= 0x01

		_, err := Decrypt(tamperedCiphertext, key, iv, tag, aad)
		if err == nil {
			t.Fatal("Expected decryption to fail on tampered ciphertext, but it succeeded!")
		}
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("Expected ErrAuthenticationFailed, got: %v", err)
		}
	})

	t.Run("flip single bit in auth tag", func(t *testing.T) {
		tamperedTag := make([]byte, len(tag))
		copy(tamperedTag, tag)
		tamperedTag[len(tamperedTag)-1] ^= 0x01

		_, err := Decrypt(ciphertext, key, iv, tamperedTag, aad)
		if err == nil {
			t.Fatal("Expected decryption to fail on tampered tag, but it succeeded!")
		}
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("Expected ErrAuthenticationFailed, got: %v", err)
		}
	})

	t.Run("tamper with additional authenticated data (AAD)", func(t *testing.T) {
		tamperedAAD := []byte("object-id: lu-exam-2026-999-DIFFERENT")

		_, err := Decrypt(ciphertext, key, iv, tag, tamperedAAD)
		if err == nil {
			t.Fatal("Expected decryption to fail on tampered AAD, but it succeeded!")
		}
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("Expected ErrAuthenticationFailed, got: %v", err)
		}
	})

	t.Run("tamper with IV", func(t *testing.T) {
		tamperedIV := make([]byte, len(iv))
		copy(tamperedIV, iv)
		tamperedIV[0] ^= 0x01

		_, err := Decrypt(ciphertext, key, tamperedIV, tag, aad)
		if err == nil {
			t.Fatal("Expected decryption to fail on tampered IV, but it succeeded!")
		}
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("Expected ErrAuthenticationFailed, got: %v", err)
		}
	})
}

func TestDecrypt_WrongKeyRejection(t *testing.T) {
	keyA, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer ZeroBytes(keyA)

	keyB, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer ZeroBytes(keyB)

	iv, _ := GenerateIV()
	plaintext := []byte("Top secret payroll figures")

	ciphertext, tag, err := Encrypt(plaintext, keyA, iv, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ciphertext, keyB, iv, tag, nil)
	if err == nil {
		t.Fatal("Expected decryption with wrong key to fail, but it succeeded!")
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Expected ErrAuthenticationFailed, got: %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	validKey := make([]byte, KeySize)
	validIV := make([]byte, IVSize)
	validTag := make([]byte, TagSize)

	t.Run("invalid key size on encrypt", func(t *testing.T) {
		_, _, err := Encrypt([]byte("test"), []byte("short-key"), validIV, nil)
		if !errors.Is(err, ErrInvalidKeySize) {
			t.Fatalf("Expected ErrInvalidKeySize, got: %v", err)
		}
	})

	t.Run("invalid IV size on encrypt", func(t *testing.T) {
		_, _, err := Encrypt([]byte("test"), validKey, []byte("short-iv"), nil)
		if !errors.Is(err, ErrInvalidIVSize) {
			t.Fatalf("Expected ErrInvalidIVSize, got: %v", err)
		}
	})

	t.Run("invalid key size on decrypt", func(t *testing.T) {
		_, err := Decrypt([]byte("ciphertext"), []byte("short-key"), validIV, validTag, nil)
		if !errors.Is(err, ErrInvalidKeySize) {
			t.Fatalf("Expected ErrInvalidKeySize, got: %v", err)
		}
	})

	t.Run("invalid IV size on decrypt", func(t *testing.T) {
		_, err := Decrypt([]byte("ciphertext"), validKey, []byte("short-iv"), validTag, nil)
		if !errors.Is(err, ErrInvalidIVSize) {
			t.Fatalf("Expected ErrInvalidIVSize, got: %v", err)
		}
	})

	t.Run("invalid tag size on decrypt", func(t *testing.T) {
		_, err := Decrypt([]byte("ciphertext"), validKey, validIV, []byte("short-tag"), nil)
		if !errors.Is(err, ErrInvalidTagSize) {
			t.Fatalf("Expected ErrInvalidTagSize, got: %v", err)
		}
	})
}

func TestZeroBytes(t *testing.T) {
	secret := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ZeroBytes(secret)

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("Expected byte at index %d to be 0, got %d", i, b)
		}
	}
}
