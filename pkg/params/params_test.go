package params
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

















































































}	}		t.Error("String representation should not be empty")	if str == "" {	str := profile.String()	}		t.Fatalf("Failed to create profile: %v", err)	if err != nil {	profile, err := NewProfileA()func TestProfileString(t *testing.T) {}	}		}			t.Errorf("Expected step[%d]=%d, got %d", i, expected[i], step)		if step != expected[i] {	for i, step := range steps {	}		t.Errorf("Expected %d rotation steps, got %d", len(expected), len(steps))	if len(steps) != len(expected) {	expected := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}	// Check that steps are powers of 2	}		t.Error("Expected non-empty rotation steps")	if len(steps) == 0 {	steps := profile.RotationSteps()	}		t.Fatalf("Failed to create profile: %v", err)	if err != nil {	profile, err := NewProfileA()func TestRotationSteps(t *testing.T) {}	}		t.Errorf("Profile validation failed: %v", err)	if err := profile.Validate(); err != nil {	}		t.Error("Profile B should have bootstrapping enabled")	if !profile.BootstrapEnabled {	}		t.Errorf("Expected Slots=32768, got %d", profile.Slots)	if profile.Slots != 1<<15 {	}		t.Errorf("Expected LogN=16, got %d", profile.LogN)	if profile.LogN != 16 {	}		t.Errorf("Expected type ProfileB, got %v", profile.Type)	if profile.Type != ProfileB {	}		t.Fatalf("Failed to create Profile B: %v", err)	if err != nil {	profile, err := NewProfileB()func TestNewProfileB(t *testing.T) {}	}		t.Error("ParamsHash should not be empty")	if profile.ParamsHash == "" {	}		t.Errorf("Profile validation failed: %v", err)	if err := profile.Validate(); err != nil {	}		t.Errorf("Expected Slots=8192, got %d", profile.Slots)	if profile.Slots != 1<<13 {	}		t.Errorf("Expected LogN=14, got %d", profile.LogN)	if profile.LogN != 14 {	}