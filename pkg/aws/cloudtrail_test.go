package aws

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/logzero/logzero/pkg/parser"
)

func TestIngestFromReader(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCount int
		expectErr     bool
	}{
		{
			name: "raw JSON array",
			input: `[
				{"eventSource": "s3.amazonaws.com", "eventName": "GetObject"},
				{"eventSource": "dynamodb.amazonaws.com", "eventName": "GetItem"}
			]`,
			expectedCount: 2,
			expectErr:     false,
		},
		{
			name: "records wrapper format",
			input: `{
				"Records": [
					{"eventSource": "s3.amazonaws.com", "eventName": "PutObject"},
					{"eventSource": "kms.amazonaws.com", "eventName": "Decrypt"}
				]
			}`,
			expectedCount: 2,
			expectErr:     false,
		},
		{
			name: "NDJSON format",
			input: `{"eventSource": "s3.amazonaws.com", "eventName": "ListBucket"}
{"eventSource": "sqs.amazonaws.com", "eventName": "SendMessage"}`,
			expectedCount: 2,
			expectErr:     false,
		},
		{
			name:          "empty input",
			input:         "",
			expectedCount: 0,
			expectErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := parser.NewActionAggregator()
			count, err := IngestFromReader(strings.NewReader(tt.input), agg)
			if tt.expectErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if count != tt.expectedCount {
				t.Errorf("expected count %d, got %d", tt.expectedCount, count)
			}
		})
	}
}

func TestIngestFromReader_PayloadLimit(t *testing.T) {
	oversized := bytes.Repeat([]byte("a"), MaxReadSizeBytes+10)
	agg := parser.NewActionAggregator()
	_, err := IngestFromReader(bytes.NewReader(oversized), agg)
	if err == nil {
		t.Fatal("expected error on oversized payload, got nil")
	}
}

func TestIngestFromFile(t *testing.T) {
	tempDir := t.TempDir()
	fixtureFile := filepath.Join(tempDir, "events.json")

	content := `[{"eventSource": "s3.amazonaws.com", "eventName": "GetObject"}]`
	if err := os.WriteFile(fixtureFile, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	agg := parser.NewActionAggregator()
	count, err := IngestFromFile(fixtureFile, agg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 event, got %d", count)
	}

	// Non-existent file
	_, err = IngestFromFile(filepath.Join(tempDir, "missing.json"), agg)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}

	// Empty path
	_, err = IngestFromFile("", agg)
	if err == nil {
		t.Error("expected error for empty path, got nil")
	}
}
