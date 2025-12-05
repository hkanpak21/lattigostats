package jobs

import (
	"bytes"
	"testing"
)

func TestJobSpecValidation(t *testing.T) {
	tests := []struct {
		name    string
		spec    JobSpec
		wantErr bool
	}{
		{
			name: "valid mean",
			spec: JobSpec{
				ID:           "job1",
				Operation:    OpMean,
				Table:        "table1",
				InputColumns: []string{"income"},
			},
			wantErr: false,
		},
		{
			name: "valid variance",
			spec: JobSpec{
				ID:           "job2",
				Operation:    OpVariance,
				Table:        "table1",
				InputColumns: []string{"age"},
			},
			wantErr: false,
		},
		{
			name: "valid correlation",
			spec: JobSpec{
				ID:           "job3",
				Operation:    OpCorr,
				Table:        "table1",
				InputColumns: []string{"income", "age"},
			},
			wantErr: false,
		},
		{
			name: "valid bc",
			spec: JobSpec{
				ID:        "job4",
				Operation: OpBc,
				Table:     "table1",
				Conditions: []Condition{
					{Column: "gender", Value: 1},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ba",
			spec: JobSpec{
				ID:           "job5",
				Operation:    OpBa,
				Table:        "table1",
				TargetColumn: "income",
				Conditions: []Condition{
					{Column: "gender", Value: 1},
				},
			},
			wantErr: false,
		},
		{
			name: "empty id",
			spec: JobSpec{
				ID:           "",
				Operation:    OpMean,
				Table:        "table1",
				InputColumns: []string{"income"},
			},
			wantErr: true,
		},
		{
			name: "empty table",
			spec: JobSpec{
				ID:           "job6",
				Operation:    OpMean,
				Table:        "",
				InputColumns: []string{"income"},
			},
			wantErr: true,
		},
		{
			name: "mean without input columns",
			spec: JobSpec{
				ID:           "job7",
				Operation:    OpMean,
				Table:        "table1",
				InputColumns: []string{},
			},
			wantErr: true,
		},
		{
			name: "correlation with one column",
			spec: JobSpec{
				ID:           "job8",
				Operation:    OpCorr,
				Table:        "table1",
				InputColumns: []string{"income"},
			},
			wantErr: true,
		},
		{
			name: "bc without conditions",
			spec: JobSpec{
				ID:         "job9",
				Operation:  OpBc,
				Table:      "table1",
				Conditions: []Condition{},
			},
			wantErr: true,
		},
		{
			name: "ba without target column",
			spec: JobSpec{
				ID:        "job10",
				Operation: OpBa,
				Table:     "table1",
				Conditions: []Condition{
					{Column: "gender", Value: 1},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("JobSpec.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseJobSpec(t *testing.T) {
	jsonData := `{
		"id": "test_job",
		"operation": "mean",
		"table": "table1",
		"input_columns": ["income"]
	}`

	buf := bytes.NewBufferString(jsonData)
	spec, err := ParseJobSpec(buf)
	if err != nil {
		t.Fatalf("Failed to parse job spec: %v", err)
	}

	if spec.ID != "test_job" {
		t.Errorf("Expected ID 'test_job', got '%s'", spec.ID)
	}
	if spec.Operation != OpMean {
		t.Errorf("Expected operation OpMean, got %s", spec.Operation)
	}
	if spec.Table != "table1" {
		t.Errorf("Expected table 'table1', got '%s'", spec.Table)
	}
}

func TestOperationTypes(t *testing.T) {
	operations := []Operation{
		OpMean,
		OpVariance,
		OpStdev,
		OpCorr,
		OpBc,
		OpBa,
		OpBv,
		OpPercentile,
	}

	for _, op := range operations {
		if op == "" {
			t.Error("Operation type should not be empty")
		}
	}
}

func TestCondition(t *testing.T) {
	cond := Condition{
		Column: "gender",
		Value:  1,
	}

	if cond.Column != "gender" {
		t.Errorf("Expected column 'gender', got '%s'", cond.Column)
	}
	if cond.Value != 1 {
		t.Errorf("Expected value 1, got %d", cond.Value)
	}
}

func TestJobSpecPercentile(t *testing.T) {
	spec := &JobSpec{
		ID:           "percentile_job",
		Operation:    OpPercentile,
		Table:        "table1",
		InputColumns: []string{"income"},
		K:            50.0,
	}

	if err := spec.Validate(); err != nil {
		t.Errorf("Valid percentile job failed validation: %v", err)
	}

	if spec.K != 50.0 {
		t.Errorf("Expected K=50.0, got %f", spec.K)
	}
}

func TestPlanJob(t *testing.T) {
	spec := &JobSpec{
		ID:           "test_mean",
		Operation:    OpMean,
		Table:        "table1",
		InputColumns: []string{"income"},
	}

	plan, err := PlanJob(spec)
	if err != nil {
		t.Fatalf("Failed to plan job: %v", err)
	}

	if plan.Job.ID != spec.ID {
		t.Errorf("Expected job ID %s, got %s", spec.ID, plan.Job.ID)
	}

	if len(plan.Steps) == 0 {
		t.Error("Expected non-empty plan steps")
	}
}
