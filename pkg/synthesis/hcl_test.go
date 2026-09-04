package synthesis

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/logzero/logzero/pkg/models"
)

func TestGenerateHCLPolicy(t *testing.T) {
	statements := []models.IAMStatement{
		{
			Effect:    "Allow",
			Actions:   []string{"s3:GetObject", "s3:PutObject"},
			Resources: []string{"arn:aws:s3:::app-bucket/*"},
		},
		{
			Effect:    "Allow",
			Actions:   []string{"dynamodb:GetItem", "dynamodb:PutItem"},
			Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/AppTable"},
		},
	}

	hclBytes, err := GenerateHCLPolicy("app_workload", statements)
	if err != nil {
		t.Fatalf("GenerateHCLPolicy failed: %v", err)
	}

	hclStr := string(hclBytes)
	if !strings.Contains(hclStr, `data "aws_iam_policy_document" "app_workload"`) {
		t.Errorf("Missing policy document header in HCL: %s", hclStr)
	}
	if !strings.Contains(hclStr, `"s3:GetObject"`) || !strings.Contains(hclStr, `"s3:PutObject"`) {
		t.Errorf("Missing S3 actions in HCL: %s", hclStr)
	}
	if !strings.Contains(hclStr, `"arn:aws:s3:::app-bucket/*"`) {
		t.Errorf("Missing S3 resource in HCL: %s", hclStr)
	}
}

func TestGenerateJSONPolicy(t *testing.T) {
	statements := []models.IAMStatement{
		{
			Effect:    "Allow",
			Actions:   []string{"kms:Decrypt"},
			Resources: []string{"arn:aws:kms:us-east-1:123456789012:key/abc-123"},
		},
	}

	jsonBytes, err := GenerateJSONPolicy(statements)
	if err != nil {
		t.Fatalf("GenerateJSONPolicy failed: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, `"Version": "2012-10-17"`) {
		t.Errorf("Missing IAM Version in JSON: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"kms:Decrypt"`) {
		t.Errorf("Missing KMS action in JSON: %s", jsonStr)
	}
}

func TestPathTraversalRejection(t *testing.T) {
	traversalPaths := []string{
		"../../../etc/passwd",
		"../policy.tf",
		"foo/../../bar.tf",
		"sub/../../../etc/shadow",
	}

	for _, p := range traversalPaths {
		_, err := ValidateOutputPath(p)
		if err == nil {
			t.Errorf("Expected path traversal error for %s, got nil", p)
		}
	}

	validPaths := []string{
		"",
		"-",
		"policy.tf",
		"./policy.tf",
		"output/policy.tf",
		"/tmp/tightened_policy.tf",
	}

	for _, p := range validPaths {
		cleaned, err := ValidateOutputPath(p)
		if err != nil {
			t.Errorf("Expected valid path for %s, got error: %v", p, err)
		}
		if p != "" && p != "-" && strings.Contains(cleaned, "..") {
			t.Errorf("Cleaned path still contains ..: %s", cleaned)
		}
	}
}

func TestAtomicWriteAndFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "test_policy.tf")

	content := []byte(`data "aws_iam_policy_document" "test" {}`)
	if err := WriteOutput(targetFile, content, nil); err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	info, err := os.Stat(targetFile)
	if err != nil {
		t.Fatalf("Failed to stat target file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Expected file permissions 0600, got %o", perm)
	}

	// Test fallback writer
	var buf bytes.Buffer
	if err := WriteOutput("-", content, &buf); err != nil {
		t.Fatalf("WriteOutput to stdout buffer failed: %v", err)
	}
	if !strings.Contains(buf.String(), `data "aws_iam_policy_document" "test"`) {
		t.Errorf("Fallback buffer did not receive content: %s", buf.String())
	}
}
