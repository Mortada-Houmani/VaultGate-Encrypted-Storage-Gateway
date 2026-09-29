package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/api"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	Port           string
	Region         string
	S3Bucket       string
	KMSKeyID       string
	EndpointURL    string // Optional, e.g. for LocalStack (http://localhost:4566)
}

func loadConfig() Config {
	port := getEnv("PORT", "8080")
	region := getEnv("AWS_REGION", "us-east-1")
	s3Bucket := getEnv("S3_BUCKET_NAME", "vaultgate-encrypted-storage-dev")
	kmsKeyID := getEnv("KMS_KEY_ID", "alias/vaultgate-master-key-dev")
	endpointURL := os.Getenv("AWS_ENDPOINT_URL")

	return Config{
		Port:        port,
		Region:      region,
		S3Bucket:    s3Bucket,
		KMSKeyID:    kmsKeyID,
		EndpointURL: endpointURL,
	}
}

func main() {
	cfg := loadConfig()

	log.Println("================================================================")
	log.Println("  VaultGate — Client-Side Encrypted Storage Gateway (v1.0.0)   ")
	log.Println("================================================================")
	log.Printf("[Config] Port:           %s", cfg.Port)
	log.Printf("[Config] AWS Region:     %s", cfg.Region)
	log.Printf("[Config] S3 Bucket:      %s", cfg.S3Bucket)
	log.Printf("[Config] KMS Key ID:     %s", cfg.KMSKeyID)
	if cfg.EndpointURL != "" {
		log.Printf("[Config] Custom Endpoint:%s (LocalStack Mode)", cfg.EndpointURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Load AWS SDK configuration
	var optFns []func(*config.LoadOptions) error
	optFns = append(optFns, config.WithRegion(cfg.Region))

	if cfg.EndpointURL != "" {
		// LocalStack custom endpoint resolver
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:       "aws",
				URL:               cfg.EndpointURL,
				SigningRegion:     cfg.Region,
				HostnameImmutable: true,
			}, nil
		})
		optFns = append(optFns, config.WithEndpointResolverWithOptions(customResolver))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load AWS configuration: %v", err)
	}

	// Initialize AWS Service Clients
	kmsClient := kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		if cfg.EndpointURL != "" {
			o.BaseEndpoint = aws.String(cfg.EndpointURL)
		}
	})

	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.EndpointURL != "" {
			o.BaseEndpoint = aws.String(cfg.EndpointURL)
			o.UsePathStyle = true // Essential for LocalStack S3 addressing
		}
	})

	// Initialize VaultGate Services
	envelopeService := envelope.NewService(kmsClient, cfg.KMSKeyID)
	storageService := storage.NewS3Storage(s3Client, cfg.S3Bucket)
	gatewayService := api.NewGatewayService(envelopeService, storageService)
	handler := api.NewHandler(gatewayService)
	router := api.NewRouter(handler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful Shutdown Channel
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("[HTTP] Listening on http://0.0.0.0:%s", cfg.Port)
		serverErrors <- server.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", err)
		}

	case sig := <-shutdown:
		log.Printf("[SHUTDOWN] Received signal %v, gracefully shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("[ERROR] Graceful shutdown failed: %v, forcing close", err)
			_ = server.Close()
		}
		log.Println("[SHUTDOWN] VaultGate server stopped cleanly.")
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
