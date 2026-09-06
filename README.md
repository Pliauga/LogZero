# 🚧 Work in Progress (WIP)

> **Project Status:** This project is currently in active development. Features are incomplete, and things will change or break. Not ready for use!

# LogZero

LogZero is a zero-egress CLI tool that observes AWS CloudTrail API events (live or offline log fixtures) and synthesizes tightened, least-privilege Terraform IAM policy documents (`data "aws_iam_policy_document"` HCL or IAM JSON).

## Key Features

- **Offline & Live Ingestion**: Process local CloudTrail JSON exports or query the AWS CloudTrail API directly.
- **Deterministic HCL Generation**: Synthesizes clean Terraform data blocks using HashiCorp's `hclwrite` engine.
- **Zero Egress**: All parsing, normalization, and policy generation happen locally in memory.

## Installation

```bash
go install github.com/logzero/logzero/cmd/logzero@latest
```

## CLI Usage

### 1. Offline JSON Fixture
```bash
# Generate Terraform HCL from a local CloudTrail export
logzero --file ./testdata/sample_cloudtrail.json --output policy.tf --name app_policy
```

### 2. Live AWS CloudTrail Query
```bash
# Query the last 2 hours of events for a specific IAM role
logzero --role-arn "arn:aws:iam::123456789012:role/AppRole" --since 2h --format hcl
```

## Library Example

```go
package main

import (
	"fmt"

	"github.com/logzero/logzero/pkg/aws"
	"github.com/logzero/logzero/pkg/parser"
	"github.com/logzero/logzero/pkg/synthesis"
)

func main() {
	aggregator := parser.NewActionAggregator()

	// Ingest events from a local CloudTrail JSON fixture
	count, err := aws.IngestFromFile("events.json", aggregator)
	if err != nil {
		panic(err)
	}

	statements := aggregator.Statements()
	hclBytes, err := synthesis.GenerateHCLPolicy("tightened_policy", statements)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Processed %d events.\n\n%s\n", count, string(hclBytes))
}
```
