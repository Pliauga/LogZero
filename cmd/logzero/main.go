package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/logzero/logzero/pkg/aws"
	"github.com/logzero/logzero/pkg/parser"
	"github.com/logzero/logzero/pkg/synthesis"
	"github.com/spf13/cobra"
)

var (
	roleARN    string
	since      string
	timeWindow string
	startTime  string
	endTime    string
	filePath   string
	output     string
	format     string
	blockName  string
	region     string
	profile    string
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logzero",
		Short: "Synthesize least-privilege Terraform IAM policies from AWS CloudTrail events",
		Long: `logzero is a zero-egress, client-side CLI tool that observes AWS CloudTrail
API event streams (live or offline fixtures) and generates tightened, least-privilege
Terraform IAM policy documents (data "aws_iam_policy_document").`,
		RunE: runRootCmd,
	}

	cmd.Flags().StringVarP(&roleARN, "role-arn", "r", "", "Target IAM Role ARN or Name to filter CloudTrail events")
	cmd.Flags().StringVarP(&since, "since", "s", "1h", "Lookback duration from now (e.g. 15m, 1h, 24h)")
	cmd.Flags().StringVarP(&timeWindow, "time-window", "w", "", "Alias for --since lookback duration (e.g. 15m, 1h, 24h)")
	cmd.Flags().StringVar(&startTime, "start-time", "", "RFC3339 start timestamp (e.g. 2026-09-05T12:00:00Z)")
	cmd.Flags().StringVar(&endTime, "end-time", "", "RFC3339 end timestamp (e.g. 2026-09-05T13:00:00Z)")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to offline CloudTrail JSON fixture/log export file")
	cmd.Flags().StringVarP(&output, "output", "o", "-", "Output file path (use '-' or leave empty for stdout)")
	cmd.Flags().StringVar(&format, "format", "hcl", "Output format: 'hcl' (Terraform) or 'json'")
	cmd.Flags().StringVarP(&blockName, "name", "n", "tightened_policy", "Terraform data block identifier name")
	cmd.Flags().StringVar(&region, "region", "", "AWS Region override")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS Profile to use from credentials chain")

	return cmd
}

func runRootCmd(cmd *cobra.Command, args []string) error {
	startTimer := time.Now()
	aggregator := parser.NewActionAggregator()
	var totalEvents int

	// Support --time-window as alias for --since
	effectiveSince := since
	if timeWindow != "" {
		effectiveSince = timeWindow
	}

	if filePath != "" {
		// Offline Ingestion Mode
		fmt.Fprintf(os.Stderr, "==> Ingesting CloudTrail events from offline fixture: %s\n", filePath)
		count, err := aws.IngestFromFile(filePath, aggregator)
		if err != nil {
			return fmt.Errorf("ingestion failed: %w", err)
		}
		totalEvents = count
	} else {
		// Live AWS CloudTrail Lookup Mode
		ctx := context.Background()
		client, err := aws.NewClient(ctx, region, profile)
		if err != nil {
			return fmt.Errorf("AWS initialization failed: %w", err)
		}

		opts := aws.IngestionOptions{
			RoleARN: roleARN,
			Region:  region,
			Profile: profile,
		}

		now := time.Now().UTC()
		if startTime != "" {
			t, err := time.Parse(time.RFC3339, startTime)
			if err != nil {
				return fmt.Errorf("invalid --start-time format (must be RFC3339): %w", err)
			}
			opts.StartTime = &t
		} else if effectiveSince != "" {
			d, err := time.ParseDuration(effectiveSince)
			if err != nil {
				return fmt.Errorf("invalid --since / --time-window duration format: %w", err)
			}
			t := now.Add(-d)
			opts.StartTime = &t
		}

		if endTime != "" {
			t, err := time.Parse(time.RFC3339, endTime)
			if err != nil {
				return fmt.Errorf("invalid --end-time format (must be RFC3339): %w", err)
			}
			opts.EndTime = &t
		}

		fmt.Fprintf(os.Stderr, "==> Querying AWS CloudTrail (window: %v to %v)...\n",
			formatTimePtr(opts.StartTime), formatTimePtr(opts.EndTime))

		count, err := client.IngestEvents(ctx, opts, aggregator)
		if err != nil {
			return fmt.Errorf("AWS CloudTrail query error: %w", err)
		}
		totalEvents = count
	}

	statements := aggregator.Statements()
	if len(statements) == 0 {
		return fmt.Errorf("no valid, authorized API actions observed in the specified window")
	}

	var payload []byte
	var err error

	switch format {
	case "json":
		payload, err = synthesis.GenerateJSONPolicy(statements)
	case "hcl":
		fallthrough
	default:
		payload, err = synthesis.GenerateHCLPolicy(blockName, statements)
	}

	if err != nil {
		return fmt.Errorf("policy synthesis error: %w", err)
	}

	if err := synthesis.WriteOutput(output, payload, os.Stdout); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	elapsed := time.Since(startTimer)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	fmt.Fprintf(os.Stderr, "\n[Summary]\n")
	fmt.Fprintf(os.Stderr, "  • Ingested Events:     %d\n", totalEvents)
	fmt.Fprintf(os.Stderr, "  • Unique Actions:      %d\n", aggregator.TotalUniqueActions())
	fmt.Fprintf(os.Stderr, "  • Synthesized Blocks:  %d\n", len(statements))
	fmt.Fprintf(os.Stderr, "  • Memory (Allocated):  %.2f MB\n", float64(memStats.Alloc)/1024/1024)
	fmt.Fprintf(os.Stderr, "  • Elapsed Time:        %v\n", elapsed)

	return nil
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "unbounded"
	}
	return t.Format(time.RFC3339)
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
