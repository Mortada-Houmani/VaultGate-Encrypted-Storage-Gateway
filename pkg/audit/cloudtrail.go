package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// AuditEvent represents a normalized, human-readable KMS / VaultGate security audit entry.
type AuditEvent struct {
	EventID           string            `json:"event_id"`
	EventName         string            `json:"event_name"` // "GenerateDataKey", "Decrypt", "ReEncrypt"
	EventTime         time.Time         `json:"event_time"`
	Username          string            `json:"username"`
	UserARN           string            `json:"user_arn"`
	SourceIPAddress   string            `json:"source_ip_address"`
	KMSKeyID          string            `json:"kms_key_id"`
	ObjectID          string            `json:"object_id,omitempty"`
	EncryptionContext map[string]string `json:"encryption_context,omitempty"`
	ErrorCode         string            `json:"error_code,omitempty"`
	ErrorMessage      string            `json:"error_message,omitempty"`
}

// CloudTrailAPI defines the subset of AWS CloudTrail operations needed to inspect audit logs.
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// CloudTrailRawRecord mirrors the JSON payload format embedded inside CloudTrailEvent.
type CloudTrailRawRecord struct {
	EventVersion string `json:"eventVersion"`
	UserIdentity struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		ARN         string `json:"arn"`
		AccountID   string `json:"accountId"`
		UserName    string `json:"userName"`
	} `json:"userIdentity"`
	EventTime         string `json:"eventTime"`
	EventSource       string `json:"eventSource"`
	EventName         string `json:"eventName"`
	SourceIPAddress   string `json:"sourceIPAddress"`
	RequestParameters struct {
		KeyID             string            `json:"keyId"`
		EncryptionContext map[string]string `json:"encryptionContext"`
	} `json:"requestParameters"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// Service provides methods to query CloudTrail for KMS audit activity.
type Service struct {
	client CloudTrailAPI
}

// NewService instantiates a CloudTrail audit service.
func NewService(client CloudTrailAPI) *Service {
	return &Service{client: client}
}

// LookupKMSEvents queries CloudTrail for recent KMS Decrypt, GenerateDataKey, and ReEncrypt calls.
func (s *Service) LookupKMSEvents(ctx context.Context, keyID string, maxResults int32) ([]*AuditEvent, error) {
	if s.client == nil {
		return nil, fmt.Errorf("audit: CloudTrail client is not initialized")
	}

	if maxResults <= 0 {
		maxResults = 50
	}

	input := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int32(maxResults),
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyReadOnly,
				AttributeValue: aws.String("false"),
			},
		},
	}

	output, err := s.client.LookupEvents(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("audit: failed to lookup CloudTrail events: %w", err)
	}

	var events []*AuditEvent
	for _, rawEvent := range output.Events {
		event := s.parseEvent(rawEvent)
		if event != nil {
			// Filter by keyID if provided
			if keyID != "" && event.KMSKeyID != "" && event.KMSKeyID != keyID {
				continue
			}
			events = append(events, event)
		}
	}

	return events, nil
}

// parseEvent converts an AWS CloudTrail event into a structured AuditEvent.
func (s *Service) parseEvent(raw types.Event) *AuditEvent {
	ae := &AuditEvent{
		EventID:         aws.ToString(raw.EventId),
		EventName:       aws.ToString(raw.EventName),
		EventTime:       aws.ToTime(raw.EventTime),
		Username:        aws.ToString(raw.Username),
		SourceIPAddress: "unknown",
	}

	if raw.CloudTrailEvent != nil {
		var record CloudTrailRawRecord
		if err := json.Unmarshal([]byte(*raw.CloudTrailEvent), &record); err == nil {
			if record.UserIdentity.ARN != "" {
				ae.UserARN = record.UserIdentity.ARN
			}
			if record.SourceIPAddress != "" {
				ae.SourceIPAddress = record.SourceIPAddress
			}
			if record.RequestParameters.KeyID != "" {
				ae.KMSKeyID = record.RequestParameters.KeyID
			}
			if len(record.RequestParameters.EncryptionContext) > 0 {
				ae.EncryptionContext = record.RequestParameters.EncryptionContext
				if id, ok := record.RequestParameters.EncryptionContext["object_id"]; ok {
					ae.ObjectID = id
				}
			}
			ae.ErrorCode = record.ErrorCode
			ae.ErrorMessage = record.ErrorMessage
		}
	}

	return ae
}
