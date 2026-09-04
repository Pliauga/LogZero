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
	ErrPathTraversal   = errors.New("directory traversal tokens ('..') detected in output path")
	ErrEmptyStatements = errors.New("no valid IAM statements to synthesize")
)

func ValidateOutputPath(rawPath string) (string, error) {
	if rawPath == "" || rawPath == "-" {
		return "", nil
	}

	cleaned := filepath.Clean(rawPath)
	parts := strings.Split(cleaned, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return "", fmt.Errorf("%w: %s", ErrPathTraversal, rawPath)
		}
	}

	return cleaned, nil
}

func GenerateHCLPolicy(dataBlockName string, statements []models.IAMStatement) ([]byte, error) {
	if len(statements) == 0 {
		return nil, ErrEmptyStatements
	}

	if dataBlockName == "" {
		dataBlockName = "tightened_policy"
	}

	f := hclwrite.NewEmptyFile()
	rootBody := f.Body()

	dataBlock := rootBody.AppendNewBlock("data", []string{"aws_iam_policy_document", dataBlockName})
	dataBody := dataBlock.Body()

	for _, stmt := range statements {
		stmtBlock := dataBody.AppendNewBlock("statement", nil)
		stmtBody := stmtBlock.Body()

		stmtBody.SetAttributeValue("effect", cty.StringVal(stmt.Effect))

		var actionVals []cty.Value
		for _, action := range stmt.Actions {
			actionVals = append(actionVals, cty.StringVal(action))
		}
		if len(actionVals) > 0 {
			stmtBody.SetAttributeValue("actions", cty.ListVal(actionVals))
		}

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

	dir := filepath.Dir(cleanedPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	file, err := os.OpenFile(cleanedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("writing policy payload: %w", err)
	}

	return nil
}