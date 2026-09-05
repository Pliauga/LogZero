package synthesis

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/logzero/logzero/pkg/models"
	"github.com/zclconf/go-cty/cty"
)

var (
	// ErrPathTraversal is returned when an output file path attempts to traverse parent directories.
	ErrPathTraversal = errors.New("security guard: directory traversal tokens ('..') detected in output path")
	// ErrEmptyStatements is returned when there are no valid statements to synthesize.
	ErrEmptyStatements = errors.New("no valid IAM statements to synthesize")
)

// ValidateOutputPath sanitizes the output file path and prevents directory traversal attacks.
func ValidateOutputPath(rawPath string) (string, error) {
	if rawPath == "" || rawPath == "-" {
		return "", nil // Represents stdout
	}

	cleaned := filepath.Clean(rawPath)

	// Check for path traversal components
	parts := strings.Split(cleaned, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return "", fmt.Errorf("%w: %s", ErrPathTraversal, rawPath)
		}
	}

	return cleaned, nil
}

// GenerateHCLPolicy builds a clean `data "aws_iam_policy_document"` Terraform AST block using hclwrite.
func GenerateHCLPolicy(dataBlockName string, statements []models.IAMStatement) ([]byte, error) {
	if len(statements) == 0 {
		return nil, ErrEmptyStatements
	}

	if dataBlockName == "" {
		dataBlockName = "tightened_policy"
	}

	f := hclwrite.NewEmptyFile()
	rootBody := f.Body()

	// data "aws_iam_policy_document" "<dataBlockName>"
	dataBlock := rootBody.AppendNewBlock("data", []string{"aws_iam_policy_document", dataBlockName})
	dataBody := dataBlock.Body()

	for _, stmt := range statements {
		stmtBlock := dataBody.AppendNewBlock("statement", nil)
		stmtBody := stmtBlock.Body()

		// effect = "Allow"
		stmtBody.SetAttributeValue("effect", cty.StringVal(stmt.Effect))

		// actions = ["s3:GetObject", ...]
		var actionVals []cty.Value
		for _, action := range stmt.Actions {
			actionVals = append(actionVals, cty.StringVal(action))
		}
		if len(actionVals) > 0 {
			stmtBody.SetAttributeValue("actions", cty.ListVal(actionVals))
		}

		// resources = ["arn:aws:...", ...]
		var resVals []cty.Value
		for _, res := range stmt.Resources {
			resVals = append(resVals, cty.StringVal(res))
		}
		if len(resVals) > 0 {
			stmtBody.SetAttributeValue("resources", cty.ListVal(resVals))
		}
	}

	return hclwrite.Format(f.Bytes()), nil
}

// GenerateJSONPolicy builds a standard AWS IAM Policy Document JSON payload.
func GenerateJSONPolicy(statements []models.IAMStatement) ([]byte, error) {
	if len(statements) == 0 {
		return nil, ErrEmptyStatements
	}

	doc := models.IAMPolicyDocument{
		Version:   "2012-10-17",
		Statement: statements,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// WriteOutput atomically writes policy content to the target file with POSIX 0600 permissions,
// or streams to the provided writer if targetPath is empty/stdout.
func WriteOutput(targetPath string, content []byte, fallbackWriter io.Writer) error {
	cleanedPath, err := ValidateOutputPath(targetPath)
	if err != nil {
		return err
	}

	if cleanedPath == "" {
		if fallbackWriter == nil {
			fallbackWriter = os.Stdout
		}
		_, err := fallbackWriter.Write(content)
		if err == nil && !strings.HasSuffix(string(content), "\n") {
			_, err = fallbackWriter.Write([]byte("\n"))
		}
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(cleanedPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Write file atomically with secure 0600 owner-only permissions.
	// #nosec G304 -- path is sanitized via filepath.Clean and validated prior to file creation
	file, err := os.OpenFile(cleanedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file safely: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("writing hcl payload: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("closing output file: %w", err)
	}

	return nil
}