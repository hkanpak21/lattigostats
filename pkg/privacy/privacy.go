// Package privacy provides DDIA privacy inspection and policy enforcement
// for decrypted statistical results.
package privacy

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
)

// Policy defines privacy rules for result release
type Policy struct {
	// ID is the policy identifier
	ID string `json:"id"`

	// Name is a human-readable name
	Name string `json:"name"`

	// MinCount is the minimum count for any bin (k-anonymity)
	MinCount int `json:"min_count"`

	// MaxPrecision is the maximum decimal places for numeric results
	MaxPrecision int `json:"max_precision"`

	// SuppressSmallGroups suppresses results with count < MinCount
	SuppressSmallGroups bool `json:"suppress_small_groups"`

	// RoundingEnabled enables rounding of numeric results
	RoundingEnabled bool `json:"rounding_enabled"`

	// AuditEnabled enables query auditing
	AuditEnabled bool `json:"audit_enabled"`
}

// DefaultPolicy returns a sensible default privacy policy
func DefaultPolicy() *Policy {
	return &Policy{
		ID:                  "default",
		Name:                "Default Privacy Policy",
		MinCount:            5,
		MaxPrecision:        4,
		SuppressSmallGroups: true,
		RoundingEnabled:     true,
		AuditEnabled:        true,
	}
}

// LoadPolicy loads a policy from a JSON file
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file: %w", err)
	}
	defer f.Close()
	return ParsePolicy(f)
}

// ParsePolicy parses a policy from JSON
func ParsePolicy(r io.Reader) (*Policy, error) {
	var policy Policy
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}
	return &policy, nil
}

// Inspector performs privacy inspection on results
type Inspector struct {
	policy *Policy
}

// NewInspector creates a new privacy inspector
func NewInspector(policy *Policy) *Inspector {
	if policy == nil {
		policy = DefaultPolicy()
	}
	return &Inspector{policy: policy}
}

// InspectionResult contains the result of privacy inspection
type InspectionResult struct {
	// Approved indicates if the result can be released
	Approved bool `json:"approved"`

	// Violations lists any policy violations found
	Violations []Violation `json:"violations,omitempty"`

	// TransformedValue is the policy-compliant value (if approved)
	TransformedValue interface{} `json:"transformed_value,omitempty"`

	// AuditRecord contains audit information
	AuditRecord *AuditRecord `json:"audit_record,omitempty"`
}

// Violation represents a policy violation
type Violation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// AuditRecord contains audit information for a query
type AuditRecord struct {
	JobID      string                 `json:"job_id"`
	Operation  string                 `json:"operation"`
	Timestamp  string                 `json:"timestamp"`
	InputCols  []string               `json:"input_columns"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	ResultType string                 `json:"result_type"`
	Approved   bool                   `json:"approved"`
}

// InspectNumeric inspects a numeric result (mean, variance, etc.)
func (i *Inspector) InspectNumeric(value float64, count int, jobID string, operation string) *InspectionResult {
	result := &InspectionResult{
		Approved: true,
	}

	// Check minimum count
	if i.policy.SuppressSmallGroups && count < i.policy.MinCount {
		result.Approved = false
		result.Violations = append(result.Violations, Violation{
			Rule:    "min_count",
			Message: fmt.Sprintf("count %d is below minimum %d", count, i.policy.MinCount),
		})
	}

	// Apply rounding if approved
	if result.Approved && i.policy.RoundingEnabled {
		multiplier := math.Pow(10, float64(i.policy.MaxPrecision))
		value = math.Round(value*multiplier) / multiplier
	}

	if result.Approved {
		result.TransformedValue = value
	}

	// Create audit record
	if i.policy.AuditEnabled {
		result.AuditRecord = &AuditRecord{
			JobID:      jobID,
			Operation:  operation,
			ResultType: "numeric",
			Approved:   result.Approved,
		}
	}

	return result
}

// InspectCount inspects a count result (Bc)
func (i *Inspector) InspectCount(count int, jobID string, conditions map[string]int) *InspectionResult {
	result := &InspectionResult{
		Approved: true,
	}

	// Check minimum count
	if i.policy.SuppressSmallGroups && count < i.policy.MinCount {
		result.Approved = false
		result.Violations = append(result.Violations, Violation{
			Rule:    "min_count",
			Message: fmt.Sprintf("count %d is below minimum %d", count, i.policy.MinCount),
		})
	}

	if result.Approved {
		result.TransformedValue = count
	}

	// Create audit record
	if i.policy.AuditEnabled {
		condMap := make(map[string]interface{})
		for k, v := range conditions {
			condMap[k] = v
		}
		result.AuditRecord = &AuditRecord{
			JobID:      jobID,
			Operation:  "bc",
			Conditions: condMap,
			ResultType: "count",
			Approved:   result.Approved,
		}
	}

	return result
}

// ContingencyTable represents a multi-way contingency table
type ContingencyTable struct {
	Dimensions []string         `json:"dimensions"`
	Categories map[string][]int `json:"categories"`
	Counts     map[string]int   `json:"counts"` // key is comma-separated category values
}

// InspectContingencyTable inspects a contingency table (LBc result)
func (i *Inspector) InspectContingencyTable(table *ContingencyTable, jobID string) *InspectionResult {
	result := &InspectionResult{
		Approved: true,
	}

	// Check each cell for minimum count
	suppressedCells := make(map[string]bool)
	for key, count := range table.Counts {
		if count < i.policy.MinCount {
			if i.policy.SuppressSmallGroups {
				suppressedCells[key] = true
			} else {
				result.Violations = append(result.Violations, Violation{
					Rule:    "min_count",
					Message: fmt.Sprintf("cell %s has count %d below minimum %d", key, count, i.policy.MinCount),
				})
			}
		}
	}

	// Create transformed table with suppressions
	if result.Approved || len(result.Violations) == 0 {
		transformedCounts := make(map[string]int)
		for key, count := range table.Counts {
			if !suppressedCells[key] {
				transformedCounts[key] = count
			} else {
				transformedCounts[key] = -1 // indicates suppressed
			}
		}
		result.TransformedValue = &ContingencyTable{
			Dimensions: table.Dimensions,
			Categories: table.Categories,
			Counts:     transformedCounts,
		}
	}

	// Create audit record
	if i.policy.AuditEnabled {
		result.AuditRecord = &AuditRecord{
			JobID:      jobID,
			Operation:  "lbc",
			ResultType: "contingency_table",
			Approved:   result.Approved,
		}
	}

	return result
}

// InspectPercentile inspects a percentile result
func (i *Inspector) InspectPercentile(bucket int, count int, k float64, jobID string) *InspectionResult {
	result := &InspectionResult{
		Approved: true,
	}

	// Check minimum count
	if i.policy.SuppressSmallGroups && count < i.policy.MinCount {
		result.Approved = false
		result.Violations = append(result.Violations, Violation{
			Rule:    "min_count",
			Message: fmt.Sprintf("count %d is below minimum %d", count, i.policy.MinCount),
		})
	}

	if result.Approved {
		result.TransformedValue = bucket
	}

	// Create audit record
	if i.policy.AuditEnabled {
		result.AuditRecord = &AuditRecord{
			JobID:      jobID,
			Operation:  "percentile",
			Conditions: map[string]interface{}{"k": k},
			ResultType: "bucket_index",
			Approved:   result.Approved,
		}
	}

	return result
}

// LBcPostProcessor handles post-processing for LBc results
type LBcPostProcessor struct {
	policy *Policy
}

// NewLBcPostProcessor creates a new LBc post-processor
func NewLBcPostProcessor(policy *Policy) *LBcPostProcessor {
	if policy == nil {
		policy = DefaultPolicy()
	}
	return &LBcPostProcessor{policy: policy}
}

// PostProcessResult represents the output of LBc post-processing
type PostProcessResult struct {
	Table        *ContingencyTable `json:"table"`
	Suppressions int               `json:"suppressions"`
	Inspection   *InspectionResult `json:"inspection"`
}

// ProcessDecryptedChunks aggregates decrypted LBc chunks into a contingency table
// This is used when R > Slots * 2^Δ to ensure raw chunks are never exposed
func (p *LBcPostProcessor) ProcessDecryptedChunks(
	chunks [][]float64,
	dimensions []string,
	categoryCounts []int,
	jobID string,
) (*PostProcessResult, error) {
	// Aggregate chunks
	totalCells := 1
	for _, c := range categoryCounts {
		totalCells *= c
	}

	aggregated := make([]float64, totalCells)
	for _, chunk := range chunks {
		for i, v := range chunk {
			if i < totalCells {
				aggregated[i] += v
			}
		}
	}

	// Build contingency table
	table := &ContingencyTable{
		Dimensions: dimensions,
		Categories: make(map[string][]int),
		Counts:     make(map[string]int),
	}

	for i, dim := range dimensions {
		cats := make([]int, categoryCounts[i])
		for j := 0; j < categoryCounts[i]; j++ {
			cats[j] = j + 1
		}
		table.Categories[dim] = cats
	}

	// Populate counts
	for i, v := range aggregated {
		key := indexToKey(i, categoryCounts)
		table.Counts[key] = int(math.Round(v))
	}

	// Inspect
	inspector := NewInspector(p.policy)
	inspection := inspector.InspectContingencyTable(table, jobID)

	// Count suppressions
	suppressions := 0
	if inspection.TransformedValue != nil {
		transformedTable := inspection.TransformedValue.(*ContingencyTable)
		for _, v := range transformedTable.Counts {
			if v == -1 {
				suppressions++
			}
		}
	}

	return &PostProcessResult{
		Table:        table,
		Suppressions: suppressions,
		Inspection:   inspection,
	}, nil
}

// indexToKey converts a flat index to a comma-separated category key
func indexToKey(index int, categoryCounts []int) string {
	if len(categoryCounts) == 0 {
		return ""
	}

	values := make([]int, len(categoryCounts))
	remaining := index
	for i := len(categoryCounts) - 1; i >= 0; i-- {
		values[i] = (remaining % categoryCounts[i]) + 1
		remaining /= categoryCounts[i]
	}

	key := ""
	for i, v := range values {
		if i > 0 {
			key += ","
		}
		key += fmt.Sprintf("%d", v)
	}
	return key
}

// AuditLog stores audit records
type AuditLog struct {
	Records []*AuditRecord `json:"records"`
}

// NewAuditLog creates a new audit log
func NewAuditLog() *AuditLog {
	return &AuditLog{Records: make([]*AuditRecord, 0)}
}

// Add adds a record to the audit log
func (l *AuditLog) Add(record *AuditRecord) {
	if record != nil {
		l.Records = append(l.Records, record)
	}
}

// Save saves the audit log to a file
func (l *AuditLog) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create audit log file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(l)
}

// Load loads an audit log from a file
func LoadAuditLog(path string) (*AuditLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer f.Close()

	var log AuditLog
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&log); err != nil {
		return nil, fmt.Errorf("failed to parse audit log: %w", err)
	}
	return &log, nil
}
