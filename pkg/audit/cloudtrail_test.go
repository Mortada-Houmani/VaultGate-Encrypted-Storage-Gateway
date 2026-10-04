package audit

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type MockCloudTrailClient struct {
	events []types.Event
	err    error
}

func (m *MockCloudTrailClient) LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &cloudtrail.LookupEventsOutput{
		Events: m.events,
	}, nil
}

func TestAuditService_LookupKMSEvents(t *testing.T) {
	rawJSON := `{
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "AssumedRole",
			"principalId": "AROA1234567890:vaultgate-gateway",
			"arn": "arn:aws:iam::123456789012:role/vaultgate-gateway-role",
			"accountId": "123456789012"
		},
		"eventTime": "2026-10-04T12:00:00Z",
		"eventSource": "kms.amazonaws.com",
		"eventName": "Decrypt",
		"sourceIPAddress": "192.168.1.100",
		"requestParameters": {
			"keyId": "arn:aws:kms:us-east-1:123456789012:key/test-master-key",
			"encryptionContext": {
				"object_id": "exam-2026-cs101"
			}
		}
	}`

	eventTime := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	mockClient := &MockCloudTrailClient{
		events: []types.Event{
			{
				EventId:         aws.String("evt-001"),
				EventName:       aws.String("Decrypt"),
				EventTime:       aws.Time(eventTime),
				Username:        aws.String("vaultgate-gateway-role"),
				CloudTrailEvent: aws.String(rawJSON),
			},
		},
	}

	service := NewService(mockClient)
	ctx := context.Background()

	events, err := service.LookupKMSEvents(ctx, "", 10)
	if err != nil {
		t.Fatalf("LookupKMSEvents failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.EventID != "evt-001" {
		t.Errorf("expected EventID evt-001, got %s", e.EventID)
	}
	if e.EventName != "Decrypt" {
		t.Errorf("expected EventName Decrypt, got %s", e.EventName)
	}
	if e.UserARN != "arn:aws:iam::123456789012:role/vaultgate-gateway-role" {
		t.Errorf("expected UserARN vaultgate-gateway-role, got %s", e.UserARN)
	}
	if e.ObjectID != "exam-2026-cs101" {
		t.Errorf("expected ObjectID exam-2026-cs101, got %s", e.ObjectID)
	}
	if e.SourceIPAddress != "192.168.1.100" {
		t.Errorf("expected SourceIPAddress 192.168.1.100, got %s", e.SourceIPAddress)
	}
}

func TestAuditService_FilterByKeyID(t *testing.T) {
	mockClient := &MockCloudTrailClient{
		events: []types.Event{
			{
				EventId:         aws.String("evt-001"),
				EventName:       aws.String("Decrypt"),
				CloudTrailEvent: aws.String(`{"requestParameters":{"keyId":"key-A"}}`),
			},
			{
				EventId:         aws.String("evt-002"),
				EventName:       aws.String("Decrypt"),
				CloudTrailEvent: aws.String(`{"requestParameters":{"keyId":"key-B"}}`),
			},
		},
	}

	service := NewService(mockClient)
	ctx := context.Background()

	// Filter by key-A
	eventsA, err := service.LookupKMSEvents(ctx, "key-A", 10)
	if err != nil {
		t.Fatalf("LookupKMSEvents failed: %v", err)
	}
	if len(eventsA) != 1 || eventsA[0].EventID != "evt-001" {
		t.Errorf("expected only evt-001 for key-A, got: %v", eventsA)
	}
}
