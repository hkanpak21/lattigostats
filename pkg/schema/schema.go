// Package schema defines the table schema, column types, and metadata structures
// for encrypted tables in Lattigo-STAT.
package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ColumnType represents the type of data in a column
type ColumnType string

const (
	// Numerical represents real-valued columns (encoded as CKKS floats)
	Numerical ColumnType = "numerical"
	// Categorical represents integer-coded categorical columns [1..S_f]
	Categorical ColumnType = "categorical"
	// Ordinal represents ordered categorical columns [1..S_f]
	Ordinal ColumnType = "ordinal"
)

// Column defines a single column in the encrypted table
type Column struct {
	Name          string     `json:"name"`
	Type          ColumnType `json:"type"`
	CategoryCount int        `json:"category_count,omitempty"` // S_f for categorical/ordinal
	MinValue      float64    `json:"min_value,omitempty"`      // For numerical normalization
	MaxValue      float64    `json:"max_value,omitempty"`      // For numerical normalization
	Description   string     `json:"description,omitempty"`
}

// Validate checks that the column definition is consistent
func (c *Column) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("column name cannot be empty")
	}
	switch c.Type {
	case Numerical:
		// Numerical columns don't require category count
	case Categorical, Ordinal:
		if c.CategoryCount <= 0 {
			return fmt.Errorf("categorical/ordinal column %q must have positive category_count", c.Name)
		}
	default:
		return fmt.Errorf("unknown column type %q for column %q", c.Type, c.Name)
	}
	return nil
}

// TableSchema defines the structure of an encrypted table
type TableSchema struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Columns     []Column `json:"columns"`
}

// Validate checks that all columns are valid
func (s *TableSchema) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("table name cannot be empty")
	}
	if len(s.Columns) == 0 {
		return fmt.Errorf("table must have at least one column")
	}
	names := make(map[string]bool)
	for _, col := range s.Columns {
		if err := col.Validate(); err != nil {
			return fmt.Errorf("invalid column: %w", err)
		}
		if names[col.Name] {
			return fmt.Errorf("duplicate column name: %q", col.Name)
		}
		names[col.Name] = true
	}
	return nil
}

// GetColumn returns the column with the given name, or nil if not found
func (s *TableSchema) GetColumn(name string) *Column {
	for i := range s.Columns {
		if s.Columns[i].Name == name {
			return &s.Columns[i]
		}
	}
	return nil
}

// GetColumnIndex returns the index of the column with the given name, or -1 if not found
func (s *TableSchema) GetColumnIndex(name string) int {
	for i := range s.Columns {
		if s.Columns[i].Name == name {
			return i
		}
	}
	return -1
}

// TableMetadata contains runtime information about an encrypted table
type TableMetadata struct {
	Schema      TableSchema `json:"schema"`
	RowCount    int         `json:"row_count"`     // R
	Slots       int         `json:"slots"`         // N/2
	BlockCount  int         `json:"block_count"`   // NB = ceil(R / Slots)
	ParamsHash  string      `json:"params_hash"`   // Hash of CKKS params used
	LogScale    int         `json:"log_scale"`     // Scale used for encoding
	CreatedAt   string      `json:"created_at"`    // ISO 8601 timestamp
	DataOwnerID string      `json:"data_owner_id"` // Identifier of data owner
	Version     string      `json:"version"`       // Format version
}

// NewTableMetadata creates metadata for a new table
func NewTableMetadata(schema TableSchema, rowCount, slots int, paramsHash string, logScale int, dataOwnerID string) (*TableMetadata, error) {
	if err := schema.Validate(); err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}
	if rowCount <= 0 {
		return nil, fmt.Errorf("row count must be positive")
	}
	if slots <= 0 {
		return nil, fmt.Errorf("slots must be positive")
	}
	blockCount := (rowCount + slots - 1) / slots // ceil(R / Slots)
	return &TableMetadata{
		Schema:      schema,
		RowCount:    rowCount,
		Slots:       slots,
		BlockCount:  blockCount,
		ParamsHash:  paramsHash,
		LogScale:    logScale,
		DataOwnerID: dataOwnerID,
		Version:     "1.0",
	}, nil
}

// Validate checks that the metadata is consistent
func (m *TableMetadata) Validate() error {
	if err := m.Schema.Validate(); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	if m.RowCount <= 0 {
		return fmt.Errorf("row count must be positive")
	}
	if m.Slots <= 0 {
		return fmt.Errorf("slots must be positive")
	}
	expectedBlocks := (m.RowCount + m.Slots - 1) / m.Slots
	if m.BlockCount != expectedBlocks {
		return fmt.Errorf("block count mismatch: expected %d, got %d", expectedBlocks, m.BlockCount)
	}
	return nil
}

// SaveToFile saves metadata to a JSON file
func (m *TableMetadata) SaveToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create metadata file: %w", err)
	}
	defer f.Close()
	return m.WriteTo(f)
}

// WriteTo writes metadata as JSON to the given writer
func (m *TableMetadata) WriteTo(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(m)
}

// LoadMetadataFromFile loads metadata from a JSON file
func LoadMetadataFromFile(path string) (*TableMetadata, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata file: %w", err)
	}
	defer f.Close()
	return LoadMetadata(f)
}

// LoadMetadata loads metadata from a JSON reader
func LoadMetadata(r io.Reader) (*TableMetadata, error) {
	var m TableMetadata
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid metadata: %w", err)
	}
	return &m, nil
}

// BlockRange returns the row indices covered by a given block
// Returns (startRow, endRow) where endRow is exclusive
func (m *TableMetadata) BlockRange(blockIndex int) (int, int) {
	start := blockIndex * m.Slots
	end := start + m.Slots
	if end > m.RowCount {
		end = m.RowCount
	}
	return start, end
}

// RowsInBlock returns the number of valid rows in a given block
func (m *TableMetadata) RowsInBlock(blockIndex int) int {
	start, end := m.BlockRange(blockIndex)
	return end - start
}
