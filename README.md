# LogZero

LogZero is a high-performance, zero-egress IAM policy evaluation and compliance audit engine written in Go.

It parses AWS IAM policy documents, evaluates syntax and semantic access paths, and reports misconfigurations or overly permissive wildcards locally without sending data off-host.

## Core Capabilities

- **Zero External Egress**: Evaluates policy ASTs entirely in-memory.
- **Static Analysis Integration**: Runs natively alongside SAST tools (`gosec`, `govulncheck`).
- **Structured Output**: Produces deterministic JSON reports for local CLI pipelines.

## Project Status: Active Development 🚧 This project is currently a work in progress. APIs, features, and file structures may change without warning. It is not ready for production use.

## Quickstart

### Installation

```bash
go install github.com/Pliauga/LogZero/cmd/logzero@latest
```

### Basic Example

```go
package main

import (
	"fmt"
	"log"

	"github.com/Pliauga/LogZero/pkg/engine"
)

func main() {
	// Initialize the audit engine with default security rules
	auditor := engine.New()
	
	// Run local evaluation on a target policy directory
	report, err := auditor.EvaluateDir("./policies")
	if err != nil {
		log.Fatalf("Audit failed: %v", err)
	}

	fmt.Printf("Audit complete. Issues found: %d
", len(report.Issues))
}
```

## CI/CD Audit Pipeline

Automated testing and SAST scanning run on every push via GitHub Actions. See `.github/workflows/security.yml` for configuration details.
