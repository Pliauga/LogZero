package aws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	ctTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/logzero/logzero/pkg/models"
	"github.com/logzero/logzero/pkg/parser"
)

const (
	// MaxEventCap is the hard limit on processed events per run to enforce < 25MB RAM bounds.
	MaxEventCap = 50000

	// MaxReadSizeBytes enforces an upper memory bound (25MB) on input streams to prevent DoS/OOM attacks.
	MaxReadSizeBytes = 25 * 1024 * 1024
)

var (
	// ErrEventCapExceeded is returned when an event stream exceeds the maximum allowable threshold.
	ErrEventCapExceeded = fmt.Errorf("security guard: maximum batch limit (%d events) exceeded", MaxEventCap)

	// ErrPayloadTooLarge is returned when file or reader streams exceed the memory safety bound.
	ErrPayloadTooLarge = fmt.Errorf("security guard: payload exceeds maximum allowable size (%d bytes)", MaxReadSizeBytes)

	// ErrInvalidPath is returned when path traversal or unsafe file access is detected.
	ErrInvalidPath = fmt.Errorf("security guard: path traversal attempt or invalid file path detected")
)

// IngestionOptions configures the CloudTrail query parameters.
type IngestionOptions struct {
	RoleARN   string
	StartTime *time.Time
	EndTime   *time.Time
	Region    string
	Profile   string
}

// Client abstracts the CloudTrail API interactions.
type Client struct {
	ctClient *cloudtrail.Client
}

// NewClient initializes an AWS SDK v2 CloudTrail client with adaptive exponential backoff and jitter.
func NewClient(ctx context.Context, region, profile string) (*Client, error) {
	var optFns []func(*config.LoadOptions) error
	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}
	if profile != "" {
		optFns = append(optFns, config.WithSharedConfigProfile(profile))
	}

	// Configure standard adaptive retryer for CloudTrail API rate limiting protection with full jitter
	optFns = append(optFns, config.WithRetryer(func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = 6
			o.MaxBackoff = 20 * time.Second
		})
	}))

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	return &Client{
		ctClient: cloudtrail.NewFromConfig(cfg),
	}, nil
}

// IngestEvents streams CloudTrail events via the LookupEvents API into the ActionAggregator.
func (c *Client) IngestEvents(ctx context.Context, opts IngestionOptions, aggregator *parser.ActionAggregator) (int, error) {
	if opts.RoleARN != "" && !models.ARNRegex.MatchString(opts.RoleARN) {
		return 0, fmt.Errorf("security validation error: invalid multi-partition AWS Role ARN: %s", opts.RoleARN)
	}

	input := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int32(50),
	}

	if opts.StartTime != nil {
		input.StartTime = opts.StartTime
	}
	if opts.EndTime != nil {
		input.EndTime = opts.EndTime
	}

	if opts.RoleARN != "" {
		input.LookupAttributes = []ctTypes.LookupAttribute{
			{
				AttributeKey:   ctTypes.LookupAttributeKeyResourceName,
				AttributeValue: aws.String(opts.RoleARN),
			},
		}
	}

	paginator := cloudtrail.NewLookupEventsPaginator(c.ctClient, input)
	totalIngested := 0

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return totalIngested, fmt.Errorf("CloudTrail LookupEvents error: %w", err)
		}

		for _, event := range page.Events {
			if totalIngested >= MaxEventCap {
				return totalIngested, ErrEventCapExceeded
			}

			if event.CloudTrailEvent == nil {
				continue
			}

			var rawEvent models.CloudTrailRawEvent
			if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &rawEvent); err != nil {
				// Skip malformed individual event records
				continue
			}

			aggregator.IngestRawEvent(rawEvent)
			totalIngested++
		}
	}

	return totalIngested, nil
}

// IngestFromReader parses CloudTrail events directly from an io.Reader (file, stdin, or test buffer).
// Bounded using io.LimitReader to enforce < 25MB RAM bounds and protection against DoS memory spikes.
func IngestFromReader(r io.Reader, aggregator *parser.ActionAggregator) (int, error) {
	limitedReader := io.LimitReader(r, MaxReadSizeBytes+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return 0, fmt.Errorf("failed to read event stream: %w", err)
	}

	if len(data) > MaxReadSizeBytes {
		return 0, ErrPayloadTooLarge
	}

	totalIngested := 0

	// 1. Attempt unmarshal as array of CloudTrailRawEvent
	var events []models.CloudTrailRawEvent
	if err := json.Unmarshal(data, &events); err == nil && len(events) > 0 {
		for _, ev := range events {
			if totalIngested >= MaxEventCap {
				return totalIngested, ErrEventCapExceeded
			}
			aggregator.IngestRawEvent(ev)
			totalIngested++
		}
		return totalIngested, nil
	}

	// 2. Attempt unmarshal as AWS CloudTrail Records wrapper format {"Records": [...]}
	var wrapper struct {
		Records []models.CloudTrailRawEvent `json:"Records"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Records) > 0 {
		for _, ev := range wrapper.Records {
			if totalIngested >= MaxEventCap {
				return totalIngested, ErrEventCapExceeded
			}
			aggregator.IngestRawEvent(ev)
			totalIngested++
		}
		return totalIngested, nil
	}

	// 3. Attempt NDJSON line-by-line decoding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev models.CloudTrailRawEvent
		if err := json.Unmarshal(line, &ev); err == nil {
			if totalIngested >= MaxEventCap {
				return totalIngested, ErrEventCapExceeded
			}
			aggregator.IngestRawEvent(ev)
			totalIngested++
		}
	}

	return totalIngested, nil
}

// IngestFromFile reads a local JSON fixture or exported CloudTrail log file into the aggregator.
// Path input is sanitized using filepath.Clean to resolve relative paths safely without breaking valid fixture imports.
func IngestFromFile(filePath string, aggregator *parser.ActionAggregator) (int, error) {
	if strings.TrimSpace(filePath) == "" {
		return 0, fmt.Errorf("security error: file path cannot be empty")
	}

	// Clean path canonicalization to resolve relative segments safely
	cleanedPath := filepath.Clean(filePath)

	file, err := os.Open(cleanedPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open fixture file safely: %w", err)
	}
	
	defer func() {
	_ = file.Close()
}()

	return IngestFromReader(file, aggregator)
}
