// DA Run - Data Analyst Job Runner
// This tool executes statistical jobs on encrypted tables.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/hkanpak21/lattigostats/pkg/jobs"
	"github.com/hkanpak21/lattigostats/pkg/ops/categorical"
	"github.com/hkanpak21/lattigostats/pkg/ops/numeric"
	"github.com/hkanpak21/lattigostats/pkg/params"
	"github.com/hkanpak21/lattigostats/pkg/schema"
	"github.com/hkanpak21/lattigostats/pkg/storage"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func main() {
	jobPath := flag.String("job", "", "Path to job spec JSON")
	tablePath := flag.String("table", "", "Path to encrypted table directory")
	keysPath := flag.String("keys", "", "Path to evaluation keys directory")
	outputPath := flag.String("output", "./result", "Output directory for result")
	profile := flag.String("profile", "A", "Parameter profile")
	flag.Parse()

	if *jobPath == "" || *tablePath == "" || *keysPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: da_run -job <job.json> -table <table_dir> -keys <keys_dir>")
		os.Exit(1)
	}

	startTime := time.Now()

	// Load parameters
	var prof *params.Profile
	var err error
	switch *profile {
	case "A":
		prof, err = params.NewProfileA()
	case "B":
		prof, err = params.NewProfileB()
	default:
		fmt.Fprintf(os.Stderr, "Unknown profile: %s\n", *profile)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create parameters: %v\n", err)
		os.Exit(1)
	}
	p := prof.Params

	// Load job spec
	job, err := jobs.LoadJobSpec(*jobPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load job: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Job: %s (%s)\n", job.ID, job.Operation)

	// Load table
	store, err := storage.OpenTableStore(*tablePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open table: %v\n", err)
		os.Exit(1)
	}

	metaPath := filepath.Join(*tablePath, "metadata.json")
	meta, err := schema.LoadMetadataFromFile(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load metadata: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Table: %s (%d rows, %d blocks)\n", meta.Schema.Name, meta.RowCount, meta.BlockCount)

	// Load evaluation keys
	fmt.Println("Loading evaluation keys...")
	rlkPath := filepath.Join(*keysPath, "relin.key")
	rlkData, err := os.ReadFile(rlkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read relin key: %v\n", err)
		os.Exit(1)
	}
	rlk := new(rlwe.RelinearizationKey)
	if err := rlk.UnmarshalBinary(rlkData); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse relin key: %v\n", err)
		os.Exit(1)
	}

	galksPath := filepath.Join(*keysPath, "galois.key")
	galksData, err := os.ReadFile(galksPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read Galois keys: %v\n", err)
		os.Exit(1)
	}
	galks := new(rlwe.GaloisKey)
	if err := galks.UnmarshalBinary(galksData); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse Galois keys: %v\n", err)
		os.Exit(1)
	}

	// Create evaluation key set
	evk := rlwe.NewMemEvaluationKeySet(rlk, galks)

	// Create evaluator
	eval, err := he.NewEvaluator(p, evk, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create evaluator: %v\n", err)
		os.Exit(1)
	}

	// Execute job
	fmt.Println("Executing job...")
	var result *rlwe.Ciphertext

	switch job.Operation {
	case jobs.OpMean, jobs.OpVariance, jobs.OpStdev:
		result, err = runNumericOp(eval, store, meta, job)
	case jobs.OpCorr:
		result, err = runCorrelation(eval, store, meta, job)
	case jobs.OpBc, jobs.OpBa, jobs.OpBv:
		result, err = runBinOp(eval, store, meta, job)
	default:
		fmt.Fprintf(os.Stderr, "Operation %s not yet implemented\n", job.Operation)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Job execution failed: %v\n", err)
		os.Exit(1)
	}

	// Save result
	if err := os.MkdirAll(*outputPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	resultPath := filepath.Join(*outputPath, "result.ct")
	if err := storage.SaveCiphertext(resultPath, result); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save result: %v\n", err)
		os.Exit(1)
	}

	// Save job result metadata
	jobResult := &jobs.JobResult{
		JobID:      job.ID,
		Operation:  string(job.Operation),
		ResultPath: resultPath,
		Metadata: map[string]interface{}{
			"execution_time": time.Since(startTime).String(),
			"level":          result.Level(),
		},
	}

	resultMetaPath := filepath.Join(*outputPath, "result.json")
	f, _ := os.Create(resultMetaPath)
	json.NewEncoder(f).Encode(jobResult)
	f.Close()

	// Print stats
	stats := eval.Stats()
	fmt.Printf("\nExecution complete in %s\n", time.Since(startTime))
	fmt.Printf("Operations: %d mul, %d add, %d rotate, %d rescale, %d bootstrap\n",
		stats.MulCount, stats.AddCount, stats.RotateCount, stats.RescaleCount, stats.BootstrapCount)
	fmt.Printf("Result saved to: %s\n", resultPath)
}

func runNumericOp(eval *he.Evaluator, store *storage.TableStore, meta *schema.TableMetadata, job *jobs.JobSpec) (*rlwe.Ciphertext, error) {
	colName := job.InputColumns[0]

	// Load data blocks
	fmt.Printf("  Loading %d blocks for column %s...\n", meta.BlockCount, colName)
	xBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)
	vBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)

	for b := 0; b < meta.BlockCount; b++ {
		var err error
		xBlocks[b], err = store.LoadBlock(colName, b)
		if err != nil {
			return nil, fmt.Errorf("failed to load block %d: %w", b, err)
		}
		vBlocks[b], err = store.LoadValidity(colName, b)
		if err != nil {
			return nil, fmt.Errorf("failed to load validity %d: %w", b, err)
		}
	}

	numOp := numeric.NewNumericOp(eval)

	switch job.Operation {
	case jobs.OpMean:
		fmt.Println("  Computing mean...")
		return numOp.Mean(xBlocks, vBlocks)
	case jobs.OpVariance:
		fmt.Println("  Computing variance...")
		return numOp.Variance(xBlocks, vBlocks)
	case jobs.OpStdev:
		fmt.Println("  Computing standard deviation...")
		return numOp.Stdev(xBlocks, vBlocks)
	default:
		return nil, fmt.Errorf("unknown numeric operation: %s", job.Operation)
	}
}

func runCorrelation(eval *he.Evaluator, store *storage.TableStore, meta *schema.TableMetadata, job *jobs.JobSpec) (*rlwe.Ciphertext, error) {
	xCol := job.InputColumns[0]
	yCol := job.InputColumns[1]

	fmt.Printf("  Loading blocks for columns %s and %s...\n", xCol, yCol)
	xBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)
	yBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)
	vBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)

	for b := 0; b < meta.BlockCount; b++ {
		var err error
		xBlocks[b], err = store.LoadBlock(xCol, b)
		if err != nil {
			return nil, err
		}
		yBlocks[b], err = store.LoadBlock(yCol, b)
		if err != nil {
			return nil, err
		}
		// Use X's validity (assume both columns have same validity)
		vBlocks[b], err = store.LoadValidity(xCol, b)
		if err != nil {
			return nil, err
		}
	}

	numOp := numeric.NewNumericOp(eval)
	fmt.Println("  Computing correlation...")
	return numOp.Correlation(xBlocks, yBlocks, vBlocks)
}

func runBinOp(eval *he.Evaluator, store *storage.TableStore, meta *schema.TableMetadata, job *jobs.JobSpec) (*rlwe.Ciphertext, error) {
	// Load validity for target column (or first condition column)
	var validityCol string
	if job.TargetColumn != "" {
		validityCol = job.TargetColumn
	} else if len(job.Conditions) > 0 {
		validityCol = job.Conditions[0].Column
	} else {
		return nil, fmt.Errorf("no column specified for bin operation")
	}

	vBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)
	for b := 0; b < meta.BlockCount; b++ {
		var err error
		vBlocks[b], err = store.LoadValidity(validityCol, b)
		if err != nil {
			return nil, fmt.Errorf("failed to load validity: %w", err)
		}
	}

	// Create BMV store adapter
	bmvStore := &bmvStoreAdapter{
		store:      store,
		blockCount: meta.BlockCount,
	}

	// Convert conditions
	conditions := make([]categorical.Condition, len(job.Conditions))
	for i, c := range job.Conditions {
		conditions[i] = categorical.Condition{
			ColumnName: c.Column,
			Value:      c.Value,
		}
	}

	catOp := categorical.NewCategoricalOp(eval)

	switch job.Operation {
	case jobs.OpBc:
		fmt.Println("  Computing bin-count...")
		return catOp.Bc(vBlocks, conditions, bmvStore)

	case jobs.OpBa:
		fmt.Printf("  Computing bin-average for %s...\n", job.TargetColumn)
		targetBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)
		for b := 0; b < meta.BlockCount; b++ {
			var err error
			targetBlocks[b], err = store.LoadBlock(job.TargetColumn, b)
			if err != nil {
				return nil, err
			}
		}
		return catOp.Ba(targetBlocks, vBlocks, conditions, bmvStore)

	case jobs.OpBv:
		fmt.Printf("  Computing bin-variance for %s...\n", job.TargetColumn)
		targetBlocks := make([]*rlwe.Ciphertext, meta.BlockCount)
		for b := 0; b < meta.BlockCount; b++ {
			var err error
			targetBlocks[b], err = store.LoadBlock(job.TargetColumn, b)
			if err != nil {
				return nil, err
			}
		}
		return catOp.Bv(targetBlocks, vBlocks, conditions, bmvStore)

	default:
		return nil, fmt.Errorf("unknown bin operation: %s", job.Operation)
	}
}

// bmvStoreAdapter adapts storage.TableStore to categorical.BMVStore
type bmvStoreAdapter struct {
	store      *storage.TableStore
	blockCount int
}

func (a *bmvStoreAdapter) GetBMV(columnName string, value int, blockIndex int) (*rlwe.Ciphertext, error) {
	return a.store.LoadBMV(columnName, value, blockIndex)
}

func (a *bmvStoreAdapter) BlockCount() int {
	return a.blockCount
}
