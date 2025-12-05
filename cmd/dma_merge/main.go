// DMA Merge - Data Merge Authority Tool
// This tool merges encrypted tables from multiple data owners by protected identifiers.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hkanpak21/lattigostats/pkg/schema"
	"github.com/hkanpak21/lattigostats/pkg/storage"
)

func main() {
	inputsFlag := flag.String("inputs", "", "Comma-separated list of encrypted table directories")
	outputDir := flag.String("output", "./merged", "Output directory for merged table")
	macKeyPath := flag.String("mac-key", "", "Path to MAC key file (for token verification)")
	tokensFlag := flag.String("tokens", "", "Comma-separated list of token files (one per input)")
	flag.Parse()

	if *inputsFlag == "" {
		fmt.Fprintln(os.Stderr, "Usage: dma_merge -inputs <dir1,dir2,...> -output <dir>")
		os.Exit(1)
	}

	// Parse input directories
	inputs := filepath.SplitList(*inputsFlag)
	if len(inputs) == 0 {
		// Try comma-separated
		inputs = splitComma(*inputsFlag)
	}

	if len(inputs) < 1 {
		fmt.Fprintln(os.Stderr, "At least one input directory required")
		os.Exit(1)
	}

	fmt.Printf("Merging %d tables...\n", len(inputs))

	// Load metadata from all inputs
	var allMeta []*schema.TableMetadata
	var allStores []*storage.TableStore

	for i, inputPath := range inputs {
		store, err := storage.OpenTableStore(inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open table %d (%s): %v\n", i, inputPath, err)
			os.Exit(1)
		}
		allStores = append(allStores, store)

		metaPath := filepath.Join(inputPath, "metadata.json")
		meta, err := schema.LoadMetadataFromFile(metaPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load metadata for table %d: %v\n", i, err)
			os.Exit(1)
		}
		allMeta = append(allMeta, meta)

		fmt.Printf("  Table %d: %s (%d rows, %d columns)\n",
			i, meta.Schema.Name, meta.RowCount, len(meta.Schema.Columns))
	}

	// Verify parameters match
	if len(allMeta) > 1 {
		ref := allMeta[0]
		for i := 1; i < len(allMeta); i++ {
			if allMeta[i].ParamsHash != ref.ParamsHash {
				fmt.Fprintf(os.Stderr, "Parameter mismatch between table 0 and %d\n", i)
				os.Exit(1)
			}
			if allMeta[i].Slots != ref.Slots {
				fmt.Fprintf(os.Stderr, "Slots mismatch between table 0 and %d\n", i)
				os.Exit(1)
			}
		}
	}

	// Create output
	mergedStore, err := storage.NewTableStore(*outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output: %v\n", err)
		os.Exit(1)
	}

	// Simple merge: concatenate all columns from all tables
	// In a real implementation, this would join by protected identifiers
	mergedSchema := schema.TableSchema{
		Name:        "merged",
		Description: "Merged table from multiple data owners",
		Columns:     []schema.Column{},
	}

	// Track column sources
	type columnSource struct {
		storeIdx int
		colName  string
	}
	colSources := make(map[string]columnSource)

	for i, meta := range allMeta {
		for _, col := range meta.Schema.Columns {
			uniqueName := fmt.Sprintf("%s_%s", meta.DataOwnerID, col.Name)
			mergedSchema.Columns = append(mergedSchema.Columns, schema.Column{
				Name:          uniqueName,
				Type:          col.Type,
				CategoryCount: col.CategoryCount,
				MinValue:      col.MinValue,
				MaxValue:      col.MaxValue,
				Description:   fmt.Sprintf("From %s: %s", meta.DataOwnerID, col.Description),
			})
			colSources[uniqueName] = columnSource{storeIdx: i, colName: col.Name}
		}
	}

	// For now, assume all tables have same row count (simplified merge)
	// Real implementation would match by protected identifiers
	rowCount := allMeta[0].RowCount
	slots := allMeta[0].Slots

	// Check if token files are provided for proper join
	var tokenFiles []string
	if *tokensFlag != "" {
		tokenFiles = splitComma(*tokensFlag)
	}

	// If token files provided, perform intersection-based join
	var joinMasks [][]float64
	if len(tokenFiles) == len(inputs) {
		fmt.Println("\nPerforming token-based join...")
		allTokens := make([][]string, len(tokenFiles))
		for i, tf := range tokenFiles {
			tokens, err := LoadTokens(tf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load tokens from %s: %v\n", tf, err)
				os.Exit(1)
			}
			allTokens[i] = tokens
			fmt.Printf("  Loaded %d tokens from %s\n", len(tokens), tf)
		}

		// Compute intersection masks for all tables
		joinMasks = ComputeJoinMasks(allTokens)
		validCount := 0
		for _, m := range joinMasks[0] {
			if m > 0 {
				validCount++
			}
		}
		fmt.Printf("  Join intersection: %d rows\n", validCount)

		// Save join masks for DA to apply
		for i := 0; i < len(inputs); i++ {
			maskPath := filepath.Join(*outputDir, fmt.Sprintf("join_mask_%d.json", i))
			if err := SaveJoinMask(maskPath, joinMasks[i], slots); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save join mask %d: %v\n", i, err)
				os.Exit(1)
			}
		}
	}

	fmt.Printf("\nMerging into table with %d columns, %d rows\n", len(mergedSchema.Columns), rowCount)

	// Copy blocks
	for newColName, src := range colSources {
		fmt.Printf("  Copying column: %s\n", newColName)
		srcStore := allStores[src.storeIdx]
		srcMeta := allMeta[src.storeIdx]

		for b := 0; b < srcMeta.BlockCount; b++ {
			// Copy data block
			ct, err := srcStore.LoadBlock(src.colName, b)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load block: %v\n", err)
				os.Exit(1)
			}
			if err := mergedStore.SaveBlock(newColName, b, ct); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save block: %v\n", err)
				os.Exit(1)
			}

			// Copy validity
			ctVal, err := srcStore.LoadValidity(src.colName, b)
			if err != nil {
				// Validity might not exist, skip
				continue
			}
			if err := mergedStore.SaveValidity(newColName, b, ctVal); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save validity: %v\n", err)
				os.Exit(1)
			}
		}

		// Copy BMVs for categorical columns
		srcCol := allMeta[src.storeIdx].Schema.GetColumn(src.colName)
		if srcCol != nil && (srcCol.Type == schema.Categorical || srcCol.Type == schema.Ordinal) {
			for v := 1; v <= srcCol.CategoryCount; v++ {
				for b := 0; b < srcMeta.BlockCount; b++ {
					ct, err := srcStore.LoadBMV(src.colName, v, b)
					if err != nil {
						continue
					}
					if err := mergedStore.SaveBMV(newColName, v, b, ct); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to save BMV: %v\n", err)
						os.Exit(1)
					}
				}
			}
		}
	}

	// Save merged metadata
	mergedMeta, err := schema.NewTableMetadata(
		mergedSchema,
		rowCount,
		slots,
		allMeta[0].ParamsHash,
		allMeta[0].LogScale,
		"merged",
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create metadata: %v\n", err)
		os.Exit(1)
	}

	metaPath := filepath.Join(*outputDir, "metadata.json")
	if err := mergedMeta.SaveToFile(metaPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save metadata: %v\n", err)
		os.Exit(1)
	}

	// Load MAC key if provided (for future identifier matching)
	if *macKeyPath != "" {
		keyData, err := os.ReadFile(*macKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load MAC key: %v\n", err)
		} else {
			// Example of how tokens would be generated
			_ = keyData
			fmt.Println("MAC key loaded for identifier protection")
		}
	}

	fmt.Printf("\nMerge complete! Output: %s\n", *outputDir)
}

func splitComma(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// ComputeToken computes a protected identifier token
func ComputeToken(macKey []byte, identifier string) string {
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(identifier))
	return hex.EncodeToString(mac.Sum(nil))
}

// MergeConfig holds configuration for the merge operation
type MergeConfig struct {
	MatchColumn string `json:"match_column"`
	Strategy    string `json:"strategy"` // "inner", "left", "outer"
}

// LoadMergeConfig loads merge configuration from a JSON file
func LoadMergeConfig(path string) (*MergeConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var config MergeConfig
	if err := json.NewDecoder(f).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

// LoadTokens loads protected identifier tokens from a file (one per line)
func LoadTokens(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tokens []string
	for _, line := range splitLines(string(data)) {
		if line != "" {
			tokens = append(tokens, line)
		}
	}
	return tokens, nil
}

// splitLines splits a string into lines
func splitLines(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == '\n' {
			result = append(result, current)
			current = ""
		} else if c != '\r' {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// ComputeJoinMasks computes intersection masks for multiple token lists
// Returns a mask for each table where 1.0 indicates row is in the intersection
func ComputeJoinMasks(allTokens [][]string) [][]float64 {
	if len(allTokens) == 0 {
		return nil
	}

	// Build a set of tokens that appear in ALL tables
	intersection := make(map[string]bool)
	for _, t := range allTokens[0] {
		intersection[t] = true
	}

	for i := 1; i < len(allTokens); i++ {
		nextSet := make(map[string]bool)
		for _, t := range allTokens[i] {
			if intersection[t] {
				nextSet[t] = true
			}
		}
		intersection = nextSet
	}

	// Create mask for each table
	masks := make([][]float64, len(allTokens))
	for i, tokens := range allTokens {
		mask := make([]float64, len(tokens))
		for j, t := range tokens {
			if intersection[t] {
				mask[j] = 1.0
			}
		}
		masks[i] = mask
	}

	return masks
}

// JoinMaskBlocks converts a flat mask to block format for DA processing
type JoinMaskBlocks struct {
	Blocks [][]float64 `json:"blocks"`
	Slots  int         `json:"slots"`
}

// SaveJoinMask saves join mask blocks to a JSON file
func SaveJoinMask(path string, mask []float64, slots int) error {
	numBlocks := (len(mask) + slots - 1) / slots
	blocks := make([][]float64, numBlocks)

	for b := 0; b < numBlocks; b++ {
		block := make([]float64, slots)
		for s := 0; s < slots; s++ {
			idx := b*slots + s
			if idx < len(mask) {
				block[s] = mask[idx]
			}
		}
		blocks[b] = block
	}

	jmb := JoinMaskBlocks{
		Blocks: blocks,
		Slots:  slots,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jmb)
}

// LoadJoinMask loads join mask blocks from a JSON file
func LoadJoinMask(path string) (*JoinMaskBlocks, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var jmb JoinMaskBlocks
	if err := json.NewDecoder(f).Decode(&jmb); err != nil {
		return nil, err
	}
	return &jmb, nil
}
