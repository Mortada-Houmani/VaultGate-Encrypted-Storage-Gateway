//go:build integration

package envelope

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// TestKMS_RealAWS runs only when -tags=integration is provided.
// It verifies that WrapAndEncrypt and DecryptAndUnwrap function flawlessly against real AWS KMS.
func TestKMS_RealAWS(t *testing.T) {
	keyID := os.Getenv("VAULTGATE_KMS_KEY_ID")
	if keyID == "" {
		t.Skip("Skipping live AWS integration test: VAULTGATE_KMS_KEY_ID is not set")
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS configuration: %v", err)
	}

	client := kms.NewFromConfig(cfg)
	service := NewService(client, keyID)

	objectID := "live-test-doc-001"
	plaintext := []byte("Verified against real AWS KMS service in eu-central-1")

	// 1. Wrap and Encrypt
	env, err := service.WrapAndEncrypt(ctx, objectID, plaintext)
	if err != nil {
		t.Fatalf("WrapAndEncrypt against real AWS KMS failed: %v", err)
	}

	t.Logf("Successfully encrypted via KMS! Wrapped key blob size: %d bytes", len(env.EncryptedDataKey))

	// 2. Decrypt and Unwrap
	decrypted, err := service.DecryptAndUnwrap(ctx, env)
	if err != nil {
		t.Fatalf("DecryptAndUnwrap against real AWS KMS failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypted payload does not match original! Got: %s", string(decrypted))
	}
	t.Log("Successfully decrypted via KMS! Round-trip verified against live AWS.")
}
