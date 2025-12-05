package params

import (
	"testing"
)

func TestNewProfileA(t *testing.T) {
	profile, err := NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create Profile A: %v", err)
	}

	if profile.Type != ProfileA {
		t.Errorf("Expected type ProfileA, got %v", profile.Type)
	}

	if profile.LogN != 14 {
		t.Errorf("Expected LogN=14, got %d", profile.LogN)
	}

	if profile.Slots != 1<<13 {
		t.Errorf("Expected Slots=8192, got %d", profile.Slots)
	}

	if err := profile.Validate(); err != nil {
		t.Errorf("Profile validation failed: %v", err)
	}

	if profile.ParamsHash == "" {
		t.Error("ParamsHash should not be empty")
	}
}

func TestNewProfileB(t *testing.T) {
	profile, err := NewProfileB()
	if err != nil {
		t.Fatalf("Failed to create Profile B: %v", err)
	}

	if profile.Type != ProfileB {
		t.Errorf("Expected type ProfileB, got %v", profile.Type)
	}

	if profile.LogN != 16 {
		t.Errorf("Expected LogN=16, got %d", profile.LogN)
	}

	if profile.Slots != 1<<15 {
		t.Errorf("Expected Slots=32768, got %d", profile.Slots)
	}

	if !profile.BootstrapEnabled {
		t.Error("Profile B should have bootstrapping enabled")
	}

	if err := profile.Validate(); err != nil {
		t.Errorf("Profile validation failed: %v", err)
	}
}

func TestRotationSteps(t *testing.T) {
	profile, err := NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	steps := profile.RotationSteps()
	if len(steps) == 0 {
		t.Error("Expected non-empty rotation steps")
	}

	// Check that steps are powers of 2
	expected := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
	if len(steps) != len(expected) {
		t.Errorf("Expected %d rotation steps, got %d", len(expected), len(steps))
	}
	for i, step := range steps {
		if step != expected[i] {
			t.Errorf("Expected step[%d]=%d, got %d", i, expected[i], step)
		}
	}
}

func TestProfileString(t *testing.T) {
	profile, err := NewProfileA()
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	str := profile.String()
	if str == "" {
		t.Error("String representation should not be empty")
	}
}
