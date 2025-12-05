// DO Encrypt - Data Owner Encryption Tool
// This tool encrypts tabular data into the Lattigo-STAT format.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/hkanpak21/lattigostats/pkg/params"
	"github.com/hkanpak21/lattigostats/pkg/schema"
	"github.com/hkanpak21/lattigostats/pkg/storage"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	dataPath := flag.String("data", "", "Path to CSV data file")
	schemaPath := flag.String("schema", "", "Path to schema JSON file")
	pkPath := flag.String("pk", "", "Path to public key")
	outputDir := flag.String("output", "./encrypted", "Output directory")
	profile := flag.String("profile", "A", "Parameter profile (A or B)")
	ownerID := flag.String("owner", "owner1", "Data owner ID")
	flag.Parse()

	if *dataPath == "" || *schemaPath == "" || *pkPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: do_encrypt -data <csv> -schema <json> -pk <public_key>")
		os.Exit(1)
	}

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

	// Load schema
	schemaFile, err := os.Open(*schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open schema: %v\n", err)
		os.Exit(1)
	}
	var tableSchema schema.TableSchema
	json.NewDecoder(schemaFile).Decode(&tableSchema)
	schemaFile.Close()

	if err := tableSchema.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid schema: %v\n", err)
		os.Exit(1)
	}

	// Load public key
	pkData, err := os.ReadFile(*pkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read public key: %v\n", err)
		os.Exit(1)
	}
	pk := new(rlwe.PublicKey)
	if err := pk.UnmarshalBinary(pkData); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse public key: %v\n", err)
		os.Exit(1)
	}

	// Load CSV data
	dataFile, err := os.Open(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open data: %v\n", err)
		os.Exit(1)
	}
	reader := csv.NewReader(dataFile)
	records, err := reader.ReadAll()
	dataFile.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read CSV: %v\n", err)
		os.Exit(1)
	}

	if len(records) < 2 {
		fmt.Fprintln(os.Stderr, "CSV must have header and at least one row")
		os.Exit(1)
	}

	header := records[0]
	data := records[1:]
	rowCount := len(data)

	// Map column names to indices
	colIndex := make(map[string]int)
	for i, name := range header {
		colIndex[name] = i
	}

	// Validate schema columns exist
	for _, col := range tableSchema.Columns {
		if _, ok := colIndex[col.Name]; !ok {
			fmt.Fprintf(os.Stderr, "Column %s not found in data\n", col.Name)
			os.Exit(1)
		}
	}

	// Create output directory
	store, err := storage.NewTableStore(*outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create table store: %v\n", err)
		os.Exit(1)
	}

	// Setup encryption
	encryptor := rlwe.NewEncryptor(p, pk)
	encoder := ckks.NewEncoder(p)
	slots := p.MaxSlots()
	scale := rlwe.NewScale(p.DefaultScale())
	level := p.MaxLevel()

	// Calculate blocks
	blockCount := (rowCount + slots - 1) / slots

	fmt.Printf("Encrypting %d rows in %d blocks (slots=%d)\n", rowCount, blockCount, slots)

	// Encrypt each column
	for _, col := range tableSchema.Columns {
		fmt.Printf("  Encrypting column: %s (%s)\n", col.Name, col.Type)
		idx := colIndex[col.Name]

		for b := 0; b < blockCount; b++ {
			startRow := b * slots
			endRow := startRow + slots
			if endRow > rowCount {
				endRow = rowCount
			}

			// Extract values for this block
			values := make([]complex128, slots)
			validity := make([]complex128, slots)

			for i := startRow; i < endRow; i++ {
				slotIdx := i - startRow
				cellValue := data[i][idx]

				if cellValue == "" || cellValue == "NA" || cellValue == "null" {
					validity[slotIdx] = 0
					values[slotIdx] = 0
				} else {
					validity[slotIdx] = 1
					v, err := strconv.ParseFloat(cellValue, 64)
					if err != nil {
						// For categorical, try int
						iv, err2 := strconv.Atoi(cellValue)
						if err2 != nil {
							fmt.Fprintf(os.Stderr, "Invalid value at row %d, col %s: %s\n", i, col.Name, cellValue)
							os.Exit(1)
						}
						v = float64(iv)
					}
					values[slotIdx] = complex(v, 0)
				}
			}

			// Encrypt values
			pt := ckks.NewPlaintext(p, level)
			pt.Scale = scale
			encoder.Encode(values, pt)
			ct, err := encryptor.EncryptNew(pt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
				os.Exit(1)
			}

			if err := store.SaveBlock(col.Name, b, ct); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save block: %v\n", err)
				os.Exit(1)
			}

			// Encrypt validity
			ptVal := ckks.NewPlaintext(p, level)
			ptVal.Scale = scale
			encoder.Encode(validity, ptVal)
			ctVal, err := encryptor.EncryptNew(ptVal)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Validity encryption failed: %v\n", err)
				os.Exit(1)
			}

			if err := store.SaveValidity(col.Name, b, ctVal); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save validity: %v\n", err)
				os.Exit(1)
			}
		}

		// Generate BMVs for categorical/ordinal columns
		if col.Type == schema.Categorical || col.Type == schema.Ordinal {
			fmt.Printf("    Generating BMVs for %d categories\n", col.CategoryCount)
			idx := colIndex[col.Name]

			for catVal := 1; catVal <= col.CategoryCount; catVal++ {
				for b := 0; b < blockCount; b++ {
					startRow := b * slots
					endRow := startRow + slots
					if endRow > rowCount {
						endRow = rowCount
					}

					bmv := make([]complex128, slots)
					for i := startRow; i < endRow; i++ {
						slotIdx := i - startRow
						cellValue := data[i][idx]
						if cellValue != "" && cellValue != "NA" && cellValue != "null" {
							iv, _ := strconv.Atoi(cellValue)
							if iv == catVal {
								bmv[slotIdx] = 1
							}
						}
					}

					pt := ckks.NewPlaintext(p, level)
					pt.Scale = scale
					encoder.Encode(bmv, pt)
					ct, err := encryptor.EncryptNew(pt)
					if err != nil {
						fmt.Fprintf(os.Stderr, "BMV encryption failed: %v\n", err)
						os.Exit(1)
					}

					if err := store.SaveBMV(col.Name, catVal, b, ct); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to save BMV: %v\n", err)
						os.Exit(1)
					}
				}
			}
		}
	}

	// Save metadata
	meta, err := schema.NewTableMetadata(
		tableSchema,
		rowCount,
		slots,
		*profile,
		int(p.LogDefaultScale()),
		*ownerID,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create metadata: %v\n", err)
		os.Exit(1)
	}

	metaPath := store.BasePath + "/metadata.json"
	if err := meta.SaveToFile(metaPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save metadata: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nEncryption complete! Output: %s\n", *outputDir)
}
