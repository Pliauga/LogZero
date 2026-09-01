package models

import "regexp"

type CloudTrailResource struct {
	ARN       string `json:"ARN"`
	Type      string `json:"resourceType"`
	ARNLower  string `json:"arn,omitempty"`
	TypeLower string `json:"type,omitempty"`
}

func (r CloudTrailResource) GetARN() string {
	if r.ARN != "" {
		return r.ARN
	}
	return r.ARNLower
}

type CloudTrailRawEvent struct {
	EventSource string               `json:"eventSource"`
	EventName   string               `json:"eventName"`
	ErrorCode   string               `json:"errorCode,omitempty"`
	Resources   []CloudTrailResource `json:"resources,omitempty"`
}

type NormalizedAction struct {
	Service     string
	Action      string
	ResourceARN string
}

type IAMStatement struct {
	Effect    string   `json:"Effect"`
	Actions   []string `json:"Action"`
	Resources []string `json:"Resource"`
}

type IAMPolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []IAMStatement `json:"Statement"`
}

// ARNRegex handles commercial, GovCloud, China, and ISO partitions with optional account IDs for S3/global resources
var ARNRegex = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b):[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_]*:([0-9]{12}|\*)?:.+`)

// SafeStringRegex preserves dots (.) to allow valid S3 object extensions (.json, .csv) and domain endpoints
var SafeStringRegex = regexp.MustCompile(`[^a-zA-Z0-9:*_\-./]`)

func SanitizeString(input string) string {
	return SafeStringRegex.ReplaceAllString(input, "")
}

func IsValidARN(arn string) bool {
	return ARNRegex.MatchString(arn)
}
