package parser

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/logzero/logzero/pkg/models"
)

var arnRegex = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b):[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_]*:([0-9]{12}|\*)?:.+`)

// Includes dots (.) so S3 extensions and domain endpoints are preserved
var sanitizeRegex = regexp.MustCompile(`[^a-zA-Z0-9:*_\-./]`)

var ServicePrefixMap = map[string]string{
	"monitoring.amazonaws.com":           "cloudwatch",
	"logs.amazonaws.com":                 "logs",
	"events.amazonaws.com":               "events",
	"s3.amazonaws.com":                   "s3",
	"dynamodb.amazonaws.com":             "dynamodb",
	"sqs.amazonaws.com":                  "sqs",
	"sns.amazonaws.com":                  "sns",
	"secretsmanager.amazonaws.com":       "secretsmanager",
	"kms.amazonaws.com":                  "kms",
	"sts.amazonaws.com":                  "sts",
	"iam.amazonaws.com":                  "iam",
	"lambda.amazonaws.com":               "lambda",
	"elasticloadbalancing.amazonaws.com": "elasticloadbalancing",
	"ec2.amazonaws.com":                  "ec2",
	"rds.amazonaws.com":                  "rds",
	"ecs.amazonaws.com":                  "ecs",
	"eks.amazonaws.com":                  "eks",
	"ssm.amazonaws.com":                  "ssm",
	"athena.amazonaws.com":               "athena",
	"cloudformation.amazonaws.com":       "cloudformation",
	"cognito-idp.amazonaws.com":          "cognito-idp",
	"apigateway.amazonaws.com":           "apigateway",
	"elasticfilesystem.amazonaws.com":    "elasticfilesystem",
}

func IsValidARN(arn string) bool {
	return arnRegex.MatchString(arn)
}

func SanitizeString(s string) string {
	return sanitizeRegex.ReplaceAllString(s, "")
}

func NormalizeService(eventSource string) string {
	cleaned := strings.TrimSpace(strings.ToLower(eventSource))
	if prefix, found := ServicePrefixMap[cleaned]; found {
		return prefix
	}

	parts := strings.Split(cleaned, ".")
	if len(parts) > 0 && parts[0] != "" {
		return SanitizeString(parts[0])
	}

	return SanitizeString(cleaned)
}

type ActionAggregator struct {
	mu          sync.RWMutex
	seenKeys    map[string]struct{}
	resourceMap map[string]map[string]struct{}
}

func NewActionAggregator() *ActionAggregator {
	return &ActionAggregator{
		seenKeys:    make(map[string]struct{}),
		resourceMap: make(map[string]map[string]struct{}),
	}
}

func (a *ActionAggregator) IngestRawEvent(event models.CloudTrailRawEvent) {
	if event.ErrorCode != "" {
		return
	}

	service := NormalizeService(event.EventSource)
	actionName := SanitizeString(event.EventName)
	if service == "" || actionName == "" {
		return
	}

	fullAction := service + ":" + actionName

	var targetARNs []string
	for _, res := range event.Resources {
		rawARN := res.GetARN()
		sanitizedARN := SanitizeString(strings.TrimSpace(rawARN))
		if sanitizedARN != "" && IsValidARN(sanitizedARN) {
			targetARNs = append(targetARNs, sanitizedARN)
		}
	}

	if len(targetARNs) == 0 {
		targetARNs = []string{"*"}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, resARN := range targetARNs {
		key := service + ":" + actionName + ":" + resARN
		if _, exists := a.seenKeys[key]; exists {
			continue
		}
		a.seenKeys[key] = struct{}{}

		if _, exists := a.resourceMap[resARN]; !exists {
			a.resourceMap[resARN] = make(map[string]struct{})
		}
		a.resourceMap[resARN][fullAction] = struct{}{}
	}
}

func (a *ActionAggregator) GetNormalizedActions() []models.NormalizedAction {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var result []models.NormalizedAction
	for resARN, actions := range a.resourceMap {
		for act := range actions {
			parts := strings.SplitN(act, ":", 2)
			service := parts[0]
			result = append(result, models.NormalizedAction{
				Service:     service,
				Action:      act,
				ResourceARN: resARN,
			})
		}
	}
	return result
}

func (a *ActionAggregator) Statements() []models.IAMStatement {
	a.mu.RLock()
	defer a.mu.RUnlock()

	type actionSetKey string
	actionSetToResources := make(map[actionSetKey][]string)

	for resARN, actions := range a.resourceMap {
		var actionList []string
		for act := range actions {
			actionList = append(actionList, act)
		}
		sort.Strings(actionList)
		key := actionSetKey(strings.Join(actionList, ","))
		actionSetToResources[key] = append(actionSetToResources[key], resARN)
	}

	var statements []models.IAMStatement
	for key, resources := range actionSetToResources {
		actionList := strings.Split(string(key), ",")
		sort.Strings(resources)

		statements = append(statements, models.IAMStatement{
			Effect:    "Allow",
			Actions:   actionList,
			Resources: resources,
		})
	}

	sort.Slice(statements, func(i, j int) bool {
		if len(statements[i].Resources) > 0 && len(statements[j].Resources) > 0 {
			if statements[i].Resources[0] == "*" && statements[j].Resources[0] != "*" {
				return true
			}
			if statements[i].Resources[0] != "*" && statements[j].Resources[0] == "*" {
				return false
			}
			return statements[i].Resources[0] < statements[j].Resources[0]
		}
		return false
	})

	return statements
}

func (a *ActionAggregator) TotalUniqueActions() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.seenKeys)
}
