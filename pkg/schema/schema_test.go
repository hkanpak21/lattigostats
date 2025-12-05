package schema

import (
	"bytes"
	"testing"
)

func TestColumnValidation(t *testing.T) {
	tests := []struct {
		name    string
		column  Column
		wantErr bool
	}{
		{
			name: "valid numerical",
			column: Column{
				Name: "income",
				Type: Numerical,
			},
			wantErr: false,
		},
		{
			name: "valid categorical",
			column: Column{
				Name:          "gender",
				Type:          Categorical,
				CategoryCount: 3,
			},
			wantErr: false,
		},
		{
			name: "valid ordinal",
			column: Column{
				Name:          "education",
				Type:          Ordinal,
				CategoryCount: 4,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			column: Column{
				Name: "",
				Type: Numerical,
			},
			wantErr: true,
		},
		{
			name: "categorical without category count",
			column: Column{
				Name: "category",
				Type: Categorical,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.column.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Column.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTableSchemaValidation(t *testing.T) {
	schema := &TableSchema{
		Name: "test_table",
		Columns: []Column{
			{Name: "id", Type: Numerical},
			{Name: "name", Type: Categorical, CategoryCount: 3},
			{Name: "level", Type: Ordinal, CategoryCount: 3},
		},
	}

	if err := schema.Validate(); err != nil {
		t.Errorf("Valid schema validation failed: %v", err)
	}

	// Test empty table name
	invalidSchema := &TableSchema{
		Name:    "",
		Columns: []Column{{Name: "id", Type: Numerical}},
	}
	if err := invalidSchema.Validate(); err == nil {
		t.Error("Expected error for empty table name")
	}

	// Test empty columns
	invalidSchema2 := &TableSchema{
		Name:    "test",
		Columns: []Column{},
	}
	if err := invalidSchema2.Validate(); err == nil {
		t.Error("Expected error for empty columns")
	}
}

func TestGetColumn(t *testing.T) {
	schema := &TableSchema{
		Name: "test_table",
		Columns: []Column{
			{Name: "id", Type: Numerical},
			{Name: "name", Type: Categorical, CategoryCount: 2},
		},
	}

	col := schema.GetColumn("id")
	if col == nil {
		t.Error("Expected to find column 'id'")
	} else if col.Type != Numerical {
		t.Errorf("Expected Numerical type, got %v", col.Type)
	}

	nonexistent := schema.GetColumn("nonexistent")
	if nonexistent != nil {
		t.Error("Expected not to find nonexistent column")
	}
}

func TestGetColumnIndex(t *testing.T) {
	schema := &TableSchema{
		Name: "test_table",
		Columns: []Column{
			{Name: "id", Type: Numerical},
			{Name: "name", Type: Categorical, CategoryCount: 2},
			{Name: "value", Type: Numerical},
		},
	}

	idx := schema.GetColumnIndex("name")
	if idx != 1 {
		t.Errorf("Expected column index 1, got %d", idx)
	}

	idx = schema.GetColumnIndex("nonexistent")
	if idx != -1 {
		t.Errorf("Expected -1 for nonexistent column, got %d", idx)
	}
}

func TestNewTableMetadata(t *testing.T) {
	schema := TableSchema{
		Name: "test_table",
		Columns: []Column{
			{Name: "id", Type: Numerical},
			{Name: "category", Type: Categorical, CategoryCount: 2},
		},
	}

	meta, err := NewTableMetadata(schema, 1000, 8192, "abc123", 40, "owner1")
	if err != nil {
		t.Fatalf("Failed to create metadata: %v", err)
	}

	if meta.Schema.Name != "test_table" {
		t.Errorf("Expected schema name 'test_table', got %s", meta.Schema.Name)
	}
	if meta.RowCount != 1000 {
		t.Errorf("Expected row count 1000, got %d", meta.RowCount)
	}
	if meta.ParamsHash != "abc123" {
		t.Errorf("Expected params hash 'abc123', got %s", meta.ParamsHash)
	}
	if meta.BlockCount != 1 {
		t.Errorf("Expected block count 1, got %d", meta.BlockCount)
	}
}

func TestTableMetadataSerialization(t *testing.T) {
	schema := TableSchema{
		Name: "test_table",
		Columns: []Column{
			{Name: "id", Type: Numerical},
			{Name: "category", Type: Categorical, CategoryCount: 2},
		},
	}

	meta, err := NewTableMetadata(schema, 1000, 8192, "abc123", 40, "owner1")
	if err != nil {
		t.Fatalf("Failed to create metadata: %v", err)
	}

	// Test serialization
	var buf bytes.Buffer
	if err := meta.WriteTo(&buf); err != nil {
		t.Fatalf("Failed to write metadata: %v", err)
	}

	// Test deserialization
	loaded, err := LoadMetadata(&buf)
	if err != nil {
		t.Fatalf("Failed to load metadata: %v", err)
	}

	if loaded.Schema.Name != meta.Schema.Name {
		t.Errorf("Expected schema name %s, got %s", meta.Schema.Name, loaded.Schema.Name)
	}
	if loaded.RowCount != meta.RowCount {
		t.Errorf("Expected row count %d, got %d", meta.RowCount, loaded.RowCount)
	}
	if loaded.ParamsHash != meta.ParamsHash {
		t.Errorf("Expected params hash %s, got %s", meta.ParamsHash, loaded.ParamsHash)
	}
}

func TestTableMetadataBlockRange(t *testing.T) {
	schema := TableSchema{
		Name:    "test",
		Columns: []Column{{Name: "id", Type: Numerical}},
	}

	// 100 rows, 30 slots per block -> 4 blocks (30, 30, 30, 10)
	meta, err := NewTableMetadata(schema, 100, 30, "hash", 40, "owner")
	if err != nil {
		t.Fatalf("Failed to create metadata: %v", err)
	}

	if meta.BlockCount != 4 {
		t.Errorf("Expected 4 blocks, got %d", meta.BlockCount)
	}

	// First block: 0-30
	start, end := meta.BlockRange(0)
	if start != 0 || end != 30 {
		t.Errorf("Block 0: expected (0, 30), got (%d, %d)", start, end)
	}

	// Last block: 90-100
	start, end = meta.BlockRange(3)
	if start != 90 || end != 100 {
		t.Errorf("Block 3: expected (90, 100), got (%d, %d)", start, end)
	}

	// Check rows in block
	if meta.RowsInBlock(0) != 30 {
		t.Errorf("Expected 30 rows in block 0, got %d", meta.RowsInBlock(0))
	}
	if meta.RowsInBlock(3) != 10 {
		t.Errorf("Expected 10 rows in block 3, got %d", meta.RowsInBlock(3))
	}
}
