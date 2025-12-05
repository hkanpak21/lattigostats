// Package jobs provides JobSpec parsing, validation, and execution planning
// for statistical operations on encrypted tables.
package jobs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Operation represents the type of statistical operation
type Operation string

const (
	OpMean       Operation = "mean"
	OpVariance   Operation = "var"
	OpStdev      Operation = "stdev"
	OpCorr       Operation = "corr"
	OpBc         Operation = "bc"
	OpBa         Operation = "ba"
	OpBv         Operation = "bv"
	OpLBc        Operation = "lbc"
	OpPercentile Operation = "percentile"
	OpLookup     Operation = "lookup"
)

// Condition represents a categorical filter condition
type Condition struct {
	Column string `json:"column"`
	Value  int    `json:"value"`
}

// JobSpec defines a statistical computation request
type JobSpec struct {
	// ID is a unique identifier for the job
	ID string `json:"id"`

	// Operation to perform
	Operation Operation `json:"operation"`

	// Table is the name of the encrypted table
	Table string `json:"table"`

	// InputColumns are the columns used in computation
	InputColumns []string `json:"input_columns,omitempty"`

	// TargetColumn is the numeric column for Ba/Bv operations
	TargetColumn string `json:"target_column,omitempty"`

	// Conditions are categorical filters for BIN-OP
	Conditions []Condition `json:"conditions,omitempty"`

	// K is the percentile value (0-100)
	K float64 `json:"k,omitempty"`

	// LookupValue is the value to look up in table lookup
	LookupValue int `json:"lookup_value,omitempty"`

	// PrivacyPolicy tags for DDIA processing
	PrivacyPolicy string `json:"privacy_policy,omitempty"`

	// OutputFormat specifies result format
	OutputFormat string `json:"output_format,omitempty"`
}

// Validate checks that the JobSpec is well-formed
func (j *JobSpec) Validate() error {
	if j.ID == "" {
		return fmt.Errorf("job ID is required")
	}
	if j.Table == "" {
		return fmt.Errorf("table name is required")
	}

	switch j.Operation {
	case OpMean, OpVariance, OpStdev:
		if len(j.InputColumns) != 1 {
			return fmt.Errorf("operation %s requires exactly one input column", j.Operation)
		}
	case OpCorr:
		if len(j.InputColumns) != 2 {
			return fmt.Errorf("operation %s requires exactly two input columns", j.Operation)
		}
	case OpBc:
		if len(j.Conditions) == 0 {
			return fmt.Errorf("operation bc requires at least one condition")
		}
	case OpBa, OpBv:
		if len(j.Conditions) == 0 {
			return fmt.Errorf("operation %s requires at least one condition", j.Operation)
		}
		if j.TargetColumn == "" {
			return fmt.Errorf("operation %s requires a target column", j.Operation)
		}
	case OpLBc:
		if len(j.InputColumns) < 2 {
			return fmt.Errorf("operation lbc requires at least two input columns")
		}
	case OpPercentile:
		if len(j.InputColumns) != 1 {
			return fmt.Errorf("operation percentile requires exactly one ordinal column")
		}
		if j.K < 0 || j.K > 100 {
			return fmt.Errorf("k must be between 0 and 100")
		}
	case OpLookup:
		if len(j.InputColumns) != 1 {
			return fmt.Errorf("operation lookup requires exactly one categorical column")
		}
		if j.TargetColumn == "" {
			return fmt.Errorf("operation lookup requires a target column")
		}
	default:
		return fmt.Errorf("unknown operation: %s", j.Operation)
	}

	return nil
}

// LoadJobSpec loads a job specification from a JSON file
func LoadJobSpec(path string) (*JobSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open job spec file: %w", err)
	}
	defer f.Close()
	return ParseJobSpec(f)
}

// ParseJobSpec parses a job specification from JSON
func ParseJobSpec(r io.Reader) (*JobSpec, error) {
	var job JobSpec
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&job); err != nil {
		return nil, fmt.Errorf("failed to parse job spec: %w", err)
	}
	if err := job.Validate(); err != nil {
		return nil, fmt.Errorf("invalid job spec: %w", err)
	}
	return &job, nil
}

// SaveJobSpec saves a job specification to a JSON file
func SaveJobSpec(path string, job *JobSpec) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create job spec file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(job); err != nil {
		return fmt.Errorf("failed to write job spec: %w", err)
	}
	return nil
}

// JobResult holds the encrypted result of a job
type JobResult struct {
	JobID      string                 `json:"job_id"`
	Operation  string                 `json:"operation"`
	ResultPath string                 `json:"result_path"` // Path to encrypted result ciphertext
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// JobPlan represents a planned execution of a job
type JobPlan struct {
	Job   *JobSpec
	Steps []PlanStep
}

// PlanStep represents one step in job execution
type PlanStep struct {
	Name        string
	Description string
	Inputs      []string
	Outputs     []string
}

// PlanJob creates an execution plan for a job
func PlanJob(job *JobSpec) (*JobPlan, error) {
	if err := job.Validate(); err != nil {
		return nil, err
	}

	plan := &JobPlan{Job: job}

	switch job.Operation {
	case OpMean:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load data blocks and validity vectors"},
			{Name: "masked_sum", Description: "Compute sum(x * v)"},
			{Name: "count", Description: "Compute sum(v)"},
			{Name: "inverse", Description: "Compute 1/count via INVNTHSQRT"},
			{Name: "divide", Description: "Compute mean = sum * invCount"},
		}
	case OpVariance:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load data blocks and validity vectors"},
			{Name: "mean", Description: "Compute mean"},
			{Name: "sum_squares", Description: "Compute sum(x^2 * v)"},
			{Name: "inverse", Description: "Compute 1/count"},
			{Name: "variance", Description: "Compute E[X^2] - E[X]^2"},
		}
	case OpStdev:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load data blocks and validity vectors"},
			{Name: "variance", Description: "Compute variance"},
			{Name: "sqrt", Description: "Compute sqrt(variance) via INVNTHSQRT"},
		}
	case OpCorr:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load data blocks for both columns"},
			{Name: "means", Description: "Compute means of X and Y"},
			{Name: "covariance", Description: "Compute covariance"},
			{Name: "variances", Description: "Compute variances of X and Y"},
			{Name: "normalize", Description: "Compute cov/(stdevX * stdevY)"},
		}
	case OpBc:
		plan.Steps = []PlanStep{
			{Name: "load_bmvs", Description: "Load BMV blocks for conditions"},
			{Name: "build_mask", Description: "Multiply BMVs to create combined mask"},
			{Name: "sum", Description: "Sum mask values to get count"},
		}
	case OpBa:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load target column and BMVs"},
			{Name: "build_mask", Description: "Build combined mask from conditions"},
			{Name: "mean", Description: "Compute mean with mask as validity"},
		}
	case OpBv:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load target column and BMVs"},
			{Name: "build_mask", Description: "Build combined mask from conditions"},
			{Name: "variance", Description: "Compute variance with mask as validity"},
		}
	case OpLBc:
		plan.Steps = []PlanStep{
			{Name: "load_pbmv", Description: "Load PBMV for primary variable"},
			{Name: "load_bbmv", Description: "Load BBMVs for other variables"},
			{Name: "multiply", Description: "Compute batched products"},
			{Name: "pack", Description: "Pack results for DDIA post-processing"},
		}
	case OpPercentile:
		plan.Steps = []PlanStep{
			{Name: "load_bmvs", Description: "Load BMVs for ordinal column"},
			{Name: "frequencies", Description: "Compute frequency for each value"},
			{Name: "cumulative", Description: "Build cumulative histogram"},
			{Name: "compare", Description: "Compare cumulative/R with k/100"},
			{Name: "find", Description: "Find first bucket above threshold"},
		}
	case OpLookup:
		plan.Steps = []PlanStep{
			{Name: "load_data", Description: "Load categorical and target columns"},
			{Name: "equality", Description: "Compute DISCRETEEQUALZERO(cat - value)"},
			{Name: "select", Description: "Multiply equality indicator by target"},
		}
	}

	return plan, nil
}

// Executor executes jobs on encrypted data
type Executor struct {
	// Future: add evaluator, storage, etc.
}

// NewExecutor creates a new job executor
func NewExecutor() *Executor {
	return &Executor{}
}

// BatchJob represents a batch of jobs to execute
type BatchJob struct {
	Jobs []*JobSpec `json:"jobs"`
}

// LoadBatchJob loads a batch job specification from a JSON file
func LoadBatchJob(path string) (*BatchJob, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open batch job file: %w", err)
	}
	defer f.Close()

	var batch BatchJob
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&batch); err != nil {
		return nil, fmt.Errorf("failed to parse batch job: %w", err)
	}

	// Validate all jobs
	for i, job := range batch.Jobs {
		if err := job.Validate(); err != nil {
			return nil, fmt.Errorf("job %d invalid: %w", i, err)
		}
	}

	return &batch, nil
}
