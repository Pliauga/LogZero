package aws

import (
	"bytes"
	"testing"

	"github.com/logzero/logzero/pkg/parser"
)

func FuzzParseCloudTrailLog(f *testing.F) {
	f.Add([]byte(`{"Records":[{"eventVersion":"1.08","eventName":"GetObject","eventSource":"s3.amazonaws.com"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		agg := parser.NewActionAggregator()
		_, _ = IngestFromReader(bytes.NewReader(data), agg)
	})
}
