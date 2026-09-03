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
	MaxEventCap      = 50000
	MaxReadSizeBytes = 25 * 1024 * 1024
)

var (
	ErrEventCapExceeded = fmt.Errorf("maximum event limit (%d events) exceeded", MaxEventCap)
	ErrPayloadTooLarge  = fmt.Errorf("payload exceeds maximum allowable size (%d bytes)", MaxReadSizeBytes)
)

type IngestionOptions struct {
	RoleARN   string
	StartTime *time.Time
	EndTime   *time.Time
	Region    string
	Profile   string
}

type Client struct {
	ctClient *cloudtrail.Client
}

func NewClient(ctx context.Context, region, profile string) (*Client, error) {
	var optFns []func(*config.LoadOptions) error
	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}
	if profile != "" {
		optFns = append(optFns, config.WithSharedConfigProfile(profile))
	}

	optFns = append(optFns, config.WithRetryer(func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = 6
			o.MaxBackoff = 20 * time.Second
		})
	}))

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return &Client{
		ctClient: cloudtrail.NewFromConfig(cfg),
	}, nil
}

func (c *Client) IngestEvents(ctx context.Context, opts IngestionOptions, aggregator *parser.ActionAggregator) (int, error) {
	if opts.RoleARN != "" && !models.IsValidARN(opts.RoleARN) {
		return 0, fmt.Errorf("invalid role ARN: %s", opts.RoleARN)
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
			return totalIngested, fmt.Errorf("lookup events: %w", err)
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
				continue
			}

			aggregator.IngestRawEvent(rawEvent)
			totalIngested++
		}
	}

	return totalIngested, nil
}

func IngestFromReader(r io.Reader, aggregator *parser.ActionAggregator) (int, error) {
	limitedReader := io.LimitReader(r, MaxReadSizeBytes+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return 0, fmt.Errorf("reading event stream: %w", err)
	}

	if len(data) > MaxReadSizeBytes {
		return 0, ErrPayloadTooLarge
	}

	totalIngested := 0

	// 1. JSON array of events
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

	// 2. CloudTrail {"Records": [...]} wrapper format
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

	// 3. NDJSON (newline-delimited JSON)
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

func IngestFromFile(filePath string, aggregator *parser.ActionAggregator) (int, error) {
	if strings.TrimSpace(filePath) == "" {
		return 0, fmt.Errorf("file path cannot be empty")
	}

	cleanedPath := filepath.Clean(filePath)
	file, err := os.Open(cleanedPath)
	if err != nil {
		return 0, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	return IngestFromReader(file, aggregator)
}
