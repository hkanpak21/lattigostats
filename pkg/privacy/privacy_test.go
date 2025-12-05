package privacy

import (
	"bytes"
	"testing"
)

func TestDefaultPolicy(t *testing.T) {
	policy := DefaultPolicy()

	if policy == nil {
		t.Fatal("DefaultPolicy returned nil")
	}

	if policy.ID != "default" {
		t.Errorf("Expected ID 'default', got '%s'", policy.ID)
	}

	if policy.MinCount != 5 {
		t.Errorf("Expected MinCount=5, got %d", policy.MinCount)
	}

	if policy.MaxPrecision != 4 {
		t.Errorf("Expected MaxPrecision=4, got %d", policy.MaxPrecision)
	}

	if !policy.SuppressSmallGroups {
		t.Error("Expected SuppressSmallGroups=true")
	}

	if !policy.RoundingEnabled {
		t.Error("Expected RoundingEnabled=true")
	}

	if !policy.AuditEnabled {
		t.Error("Expected AuditEnabled=true")
	}
}

func TestNewInspector(t *testing.T) {
	// Test with nil policy (should use default)
	inspector := NewInspector(nil)
	if inspector == nil {
		t.Fatal("NewInspector returned nil")
	}

	// Test with custom policy
	customPolicy := &Policy{
		ID:       "custom",
		MinCount: 10,
	}
	inspector2 := NewInspector(customPolicy)
	if inspector2 == nil {
		t.Fatal("NewInspector with custom policy returned nil")
	}
}

func TestPolicy(t *testing.T) {
	policy := &Policy{
		ID:                  "test",
		Name:                "Test Policy",
		MinCount:            10,
		MaxPrecision:        2,
		SuppressSmallGroups: true,
		RoundingEnabled:     false,
		AuditEnabled:        true,
	}

	if policy.ID != "test" {
		t.Errorf("Expected ID 'test', got '%s'", policy.ID)
	}
	if policy.Name != "Test Policy" {
		t.Errorf("Expected Name 'Test Policy', got '%s'", policy.Name)
	}
	if policy.MinCount != 10 {
		t.Errorf("Expected MinCount=10, got %d", policy.MinCount)
	}
}

func TestParsePolicyFromJSON(t *testing.T) {
	jsonData := `{
		"id": "json_policy",
		"name": "JSON Policy",
		"min_count": 15,
		"max_precision": 3,
		"suppress_small_groups": true,
		"rounding_enabled": true,
		"audit_enabled": false
	}`

	buf := bytes.NewBufferString(jsonData)
	policy, err := ParsePolicy(buf)
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}

	if policy.ID != "json_policy" {
		t.Errorf("Expected ID 'json_policy', got '%s'", policy.ID)
	}
	if policy.MinCount != 15 {
		t.Errorf("Expected MinCount=15, got %d", policy.MinCount)
	}
	if !policy.SuppressSmallGroups {
		t.Error("Expected SuppressSmallGroups=true")
	}
}

func TestInspectionResult(t *testing.T) {
	result := &InspectionResult{
		Approved:         true,
		Violations:       []Violation{},
		TransformedValue: 42.5,
	}

	if !result.Approved {
		t.Error("Expected result to be approved")
	}
	if len(result.Violations) != 0 {
		t.Error("Expected no violations")
	}
	if result.TransformedValue != 42.5 {
		t.Errorf("Expected TransformedValue=42.5, got %v", result.TransformedValue)
	}
}

func TestViolation(t *testing.T) {
	violation := Violation{
		Rule:    "min_count",
		Message: "Count is below minimum threshold",
	}

	if violation.Rule != "min_count" {
		t.Errorf("Expected Rule 'min_count', got '%s'", violation.Rule)
	}
	if violation.Message == "" {
		t.Error("Expected non-empty message")
	}
}
