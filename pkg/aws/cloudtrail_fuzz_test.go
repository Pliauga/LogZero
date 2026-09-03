package aws

import (
	"bytes"
	"testing"

	"github.com/logzero/logzero/pkg/parser"
)

func FuzzIngestFromReader(f *testing.F) {
	// Seed corpus with valid CloudTrail JSON, wrapper, and NDJSON payloads
	f.Add([]byte(`{"eventSource":"s3.amazonaws.com","eventName":"GetObject"}`))
	f.Add([]byte(`{"Records":[{"eventSource":"dynamodb.amazonaws.com","eventName":"GetItem"}]}`))
	f.Add([]byte(`{"eventSource":"kms.amazonaws.com","eventName":"Decrypt"}` + "\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		agg := parser.NewActionAggregator()
		// Guarantees arbitrary, corrupted, or malformed input streams never panic
		_, _ = IngestFromReader(bytes.NewReader(data), agg)
	})
}