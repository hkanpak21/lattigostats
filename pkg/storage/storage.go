// Package storage provides ciphertext serialization, chunked storage,
// and streaming read/write for encrypted tables.
package storage

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// TableStore manages the storage of an encrypted table
type TableStore struct {
	BasePath string
}

// NewTableStore creates a new table store at the given path
func NewTableStore(basePath string) (*TableStore, error) {
	// Create directory structure
	dirs := []string{
		basePath,
		filepath.Join(basePath, "blocks"),
		filepath.Join(basePath, "validity"),
		filepath.Join(basePath, "bmvs"),
		filepath.Join(basePath, "pbmv"),
		filepath.Join(basePath, "bbmv"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return &TableStore{BasePath: basePath}, nil
}

// OpenTableStore opens an existing table store
func OpenTableStore(basePath string) (*TableStore, error) {
	info, err := os.Stat(basePath)
	if err != nil {
		return nil, fmt.Errorf("table store not found: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("table store path is not a directory")
	}
	return &TableStore{BasePath: basePath}, nil
}

// blockPath returns the path for a column block
func (ts *TableStore) blockPath(columnName string, blockIndex int) string {
	return filepath.Join(ts.BasePath, "blocks", fmt.Sprintf("%s_%d.bin", columnName, blockIndex))
}

// validityPath returns the path for a validity block
func (ts *TableStore) validityPath(columnName string, blockIndex int) string {
	return filepath.Join(ts.BasePath, "validity", fmt.Sprintf("%s_%d.bin", columnName, blockIndex))
}

// bmvPath returns the path for a BMV block
func (ts *TableStore) bmvPath(columnName string, categoryValue int, blockIndex int) string {
	return filepath.Join(ts.BasePath, "bmvs", fmt.Sprintf("%s_v%d_%d.bin", columnName, categoryValue, blockIndex))
}

// pbmvPath returns the path for a PBMV block
func (ts *TableStore) pbmvPath(columnName string, blockIndex int) string {
	return filepath.Join(ts.BasePath, "pbmv", fmt.Sprintf("%s_%d.bin", columnName, blockIndex))
}

// bbmvPath returns the path for a BBMV block
func (ts *TableStore) bbmvPath(columnName string, blockIndex int) string {
	return filepath.Join(ts.BasePath, "bbmv", fmt.Sprintf("%s_%d.bin", columnName, blockIndex))
}

// metadataPath returns the path for table metadata
func (ts *TableStore) metadataPath() string {
	return filepath.Join(ts.BasePath, "metadata.json")
}

// SaveCiphertext saves a ciphertext to a file
func SaveCiphertext(path string, ct *rlwe.Ciphertext) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create ciphertext file: %w", err)
	}
	defer f.Close()
	return WriteCiphertext(f, ct)
}

// WriteCiphertext writes a ciphertext to a writer
func WriteCiphertext(w io.Writer, ct *rlwe.Ciphertext) error {
	data, err := ct.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal ciphertext: %w", err)
	}
	// Write length prefix
	length := uint64(len(data))
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}
	// Write data
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write ciphertext data: %w", err)
	}
	return nil
}

// LoadCiphertext loads a ciphertext from a file
func LoadCiphertext(path string) (*rlwe.Ciphertext, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ciphertext file: %w", err)
	}
	defer f.Close()
	return ReadCiphertext(f)
}

// ReadCiphertext reads a ciphertext from a reader
func ReadCiphertext(r io.Reader) (*rlwe.Ciphertext, error) {
	// Read length prefix
	var length uint64
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}
	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("failed to read ciphertext data: %w", err)
	}
	// Unmarshal
	ct := new(rlwe.Ciphertext)
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ciphertext: %w", err)
	}
	return ct, nil
}

// SaveBlock saves a column block
func (ts *TableStore) SaveBlock(columnName string, blockIndex int, ct *rlwe.Ciphertext) error {
	return SaveCiphertext(ts.blockPath(columnName, blockIndex), ct)
}

// LoadBlock loads a column block
func (ts *TableStore) LoadBlock(columnName string, blockIndex int) (*rlwe.Ciphertext, error) {
	return LoadCiphertext(ts.blockPath(columnName, blockIndex))
}

// SaveValidity saves a validity block
func (ts *TableStore) SaveValidity(columnName string, blockIndex int, ct *rlwe.Ciphertext) error {
	return SaveCiphertext(ts.validityPath(columnName, blockIndex), ct)
}

// LoadValidity loads a validity block
func (ts *TableStore) LoadValidity(columnName string, blockIndex int) (*rlwe.Ciphertext, error) {
	return LoadCiphertext(ts.validityPath(columnName, blockIndex))
}

// SaveBMV saves a BMV block
func (ts *TableStore) SaveBMV(columnName string, categoryValue int, blockIndex int, ct *rlwe.Ciphertext) error {
	return SaveCiphertext(ts.bmvPath(columnName, categoryValue, blockIndex), ct)
}

// LoadBMV loads a BMV block
func (ts *TableStore) LoadBMV(columnName string, categoryValue int, blockIndex int) (*rlwe.Ciphertext, error) {
	return LoadCiphertext(ts.bmvPath(columnName, categoryValue, blockIndex))
}

// SavePBMV saves a PBMV block
func (ts *TableStore) SavePBMV(columnName string, blockIndex int, ct *rlwe.Ciphertext) error {
	return SaveCiphertext(ts.pbmvPath(columnName, blockIndex), ct)
}

// LoadPBMV loads a PBMV block
func (ts *TableStore) LoadPBMV(columnName string, blockIndex int) (*rlwe.Ciphertext, error) {
	return LoadCiphertext(ts.pbmvPath(columnName, blockIndex))
}

// SaveBBMV saves a BBMV block
func (ts *TableStore) SaveBBMV(columnName string, blockIndex int, ct *rlwe.Ciphertext) error {
	return SaveCiphertext(ts.bbmvPath(columnName, blockIndex), ct)
}

// LoadBBMV loads a BBMV block
func (ts *TableStore) LoadBBMV(columnName string, blockIndex int) (*rlwe.Ciphertext, error) {
	return LoadCiphertext(ts.bbmvPath(columnName, blockIndex))
}

// BlockIterator provides streaming access to blocks
type BlockIterator struct {
	store      *TableStore
	columnName string
	blockCount int
	current    int
}

// NewBlockIterator creates an iterator for column blocks
func (ts *TableStore) NewBlockIterator(columnName string, blockCount int) *BlockIterator {
	return &BlockIterator{
		store:      ts,
		columnName: columnName,
		blockCount: blockCount,
		current:    0,
	}
}

// HasNext returns true if there are more blocks
func (bi *BlockIterator) HasNext() bool {
	return bi.current < bi.blockCount
}

// Next loads and returns the next block
func (bi *BlockIterator) Next() (*rlwe.Ciphertext, error) {
	if !bi.HasNext() {
		return nil, fmt.Errorf("no more blocks")
	}
	ct, err := bi.store.LoadBlock(bi.columnName, bi.current)
	if err != nil {
		return nil, err
	}
	bi.current++
	return ct, nil
}

// Reset resets the iterator to the beginning
func (bi *BlockIterator) Reset() {
	bi.current = 0
}

// BMVIterator provides streaming access to BMV blocks for a category value
type BMVIterator struct {
	store         *TableStore
	columnName    string
	categoryValue int
	blockCount    int
	current       int
}

// NewBMVIterator creates an iterator for BMV blocks
func (ts *TableStore) NewBMVIterator(columnName string, categoryValue int, blockCount int) *BMVIterator {
	return &BMVIterator{
		store:         ts,
		columnName:    columnName,
		categoryValue: categoryValue,
		blockCount:    blockCount,
		current:       0,
	}
}

// HasNext returns true if there are more blocks
func (bi *BMVIterator) HasNext() bool {
	return bi.current < bi.blockCount
}

// Next loads and returns the next BMV block
func (bi *BMVIterator) Next() (*rlwe.Ciphertext, error) {
	if !bi.HasNext() {
		return nil, fmt.Errorf("no more blocks")
	}
	ct, err := bi.store.LoadBMV(bi.columnName, bi.categoryValue, bi.current)
	if err != nil {
		return nil, err
	}
	bi.current++
	return ct, nil
}

// Reset resets the iterator to the beginning
func (bi *BMVIterator) Reset() {
	bi.current = 0
}
