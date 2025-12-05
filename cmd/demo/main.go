// Package main provides a demo suite for Lattigo-STAT
// It demonstrates encryption, statistical computations, and noise analysis
package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"

	"github.com/hkanpak21/lattigostats/pkg/he"
	"github.com/hkanpak21/lattigostats/pkg/params"
)

// StatResult holds both plaintext and encrypted computation results
type StatResult struct {
	Name           string
	PlaintextValue float64
	EncryptedValue float64
	AbsoluteError  float64
	RelativeError  float64
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           Lattigo-STAT Demo Suite - Statistical HE              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	rand.Seed(time.Now().UnixNano())

	if err := runDemo(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func runDemo() error {
	// Step 1: Setup CKKS Parameters
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Step 1: Setting up CKKS Parameters                             │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")

	profile, err := params.NewProfileA()
	if err != nil {
		return fmt.Errorf("failed to create profile: %w", err)
	}

	fmt.Printf("  • Profile Type:      %s (No Bootstrapping)\n", profile.Type)
	fmt.Printf("  • Ring Degree (N):   2^%d = %d\n", profile.LogN, 1<<profile.LogN)
	fmt.Printf("  • Slots:             %d\n", profile.Slots)
	fmt.Printf("  • Log Scale:         %d bits\n", profile.LogScale)
	fmt.Printf("  • Max Level:         %d\n", profile.Params.MaxLevel())
	fmt.Printf("  • Params Hash:       %s...\n", profile.ParamsHash[:16])
	fmt.Println()

	// Step 2: Generate Keys
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Step 2: Generating Cryptographic Keys                          │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")

	start := time.Now()
	kgen := rlwe.NewKeyGenerator(profile.Params)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)

	rotSteps := profile.RotationSteps()
	galoisElts := make([]uint64, len(rotSteps))
	for i, step := range rotSteps {
		galoisElts[i] = profile.Params.GaloisElement(step)
	}
	galoisKeys := kgen.GenGaloisKeysNew(galoisElts, sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk, galoisKeys...)

	keyGenTime := time.Since(start)
	fmt.Printf("  • Secret Key:        Generated\n")
	fmt.Printf("  • Public Key:        Generated\n")
	fmt.Printf("  • Relinearization:   Generated\n")
	fmt.Printf("  • Galois Keys:       %d rotation keys\n", len(rotSteps))
	fmt.Printf("  • Time:              %v\n", keyGenTime)
	fmt.Println()

	// Step 3: Generate Test Vectors
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Step 3: Generating Test Vectors                                │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")

	vectorSizes := []int{10, 100, 1000}

	for _, n := range vectorSizes {
		fmt.Printf("\n  ▶ Vector Size: %d elements\n", n)
		fmt.Println("  ─────────────────────────────────────────────────────────────")

		vectorA := generateRandomVector(n, -10.0, 10.0)
		vectorB := generateRandomVector(n, -10.0, 10.0)
		mask := generateMaskVector(n, 0.9)

		plainStats := computePlaintextStats(vectorA, vectorB, mask)

		fmt.Printf("    Vector A:    min=%.4f, max=%.4f\n",
			minSlice(vectorA[:n]), maxSlice(vectorA[:n]))
		fmt.Printf("    Vector B:    min=%.4f, max=%.4f\n",
			minSlice(vectorB[:n]), maxSlice(vectorB[:n]))
		fmt.Printf("    Valid mask:  %d / %d entries (%.1f%%)\n",
			countOnes(mask[:n]), n, float64(countOnes(mask[:n]))/float64(n)*100)
		fmt.Println()

		// Step 4: Encrypt Vectors
		fmt.Println("    ┌───────────────────────────────────────────────────────────┐")
		fmt.Println("    │ Encrypting Vectors                                        │")
		fmt.Println("    └───────────────────────────────────────────────────────────┘")

		encoder := ckks.NewEncoder(profile.Params)
		encryptor := rlwe.NewEncryptor(profile.Params, pk)
		decryptor := rlwe.NewDecryptor(profile.Params, sk)

		paddedA := padToSlots(vectorA, profile.Slots)
		paddedB := padToSlots(vectorB, profile.Slots)
		paddedMask := padToSlots(mask, profile.Slots)

		start = time.Now()

		ptA := ckks.NewPlaintext(profile.Params, profile.Params.MaxLevel())
		if err := encoder.Encode(paddedA, ptA); err != nil {
			return fmt.Errorf("encode A failed: %w", err)
		}
		ctA, err := encryptor.EncryptNew(ptA)
		if err != nil {
			return fmt.Errorf("encrypt A failed: %w", err)
		}

		ptB := ckks.NewPlaintext(profile.Params, profile.Params.MaxLevel())
		if err := encoder.Encode(paddedB, ptB); err != nil {
			return fmt.Errorf("encode B failed: %w", err)
		}
		ctB, err := encryptor.EncryptNew(ptB)
		if err != nil {
			return fmt.Errorf("encrypt B failed: %w", err)
		}

		ptMask := ckks.NewPlaintext(profile.Params, profile.Params.MaxLevel())
		if err := encoder.Encode(paddedMask, ptMask); err != nil {
			return fmt.Errorf("encode mask failed: %w", err)
		}
		ctMask, err := encryptor.EncryptNew(ptMask)
		if err != nil {
			return fmt.Errorf("encrypt mask failed: %w", err)
		}

		encryptTime := time.Since(start)
		fmt.Printf("      Encryption time: %v\n", encryptTime)
		fmt.Printf("      Ciphertext level: %d\n", ctA.Level())
		fmt.Println()

		// Step 5: Compute Statistics on Encrypted Data
		fmt.Println("    ┌───────────────────────────────────────────────────────────┐")
		fmt.Println("    │ Computing Statistics on Encrypted Data                    │")
		fmt.Println("    └───────────────────────────────────────────────────────────┘")

		evaluator, err := he.NewEvaluator(profile.Params, evk, nil)
		if err != nil {
			return fmt.Errorf("create evaluator failed: %w", err)
		}

		results := make([]StatResult, 0)

		// Sum (masked)
		start = time.Now()
		ctSum, err := computeEncryptedSum(evaluator, ctA, ctMask)
		if err != nil {
			fmt.Printf("      ⚠ Sum computation failed: %v\n", err)
		} else {
			sumTime := time.Since(start)
			encSum := decryptScalar(decryptor, encoder, ctSum, profile.Slots)
			results = append(results, StatResult{
				Name:           "Masked Sum",
				PlaintextValue: plainStats["sum"],
				EncryptedValue: encSum,
				AbsoluteError:  math.Abs(encSum - plainStats["sum"]),
				RelativeError:  relError(encSum, plainStats["sum"]),
			})
			fmt.Printf("      ✓ Masked Sum computed in %v (level: %d)\n", sumTime, ctSum.Level())
		}

		// Sum of Squares
		start = time.Now()
		ctSumSq, err := computeEncryptedSumSquares(evaluator, ctA, ctMask)
		if err != nil {
			fmt.Printf("      ⚠ Sum of Squares failed: %v\n", err)
		} else {
			sumSqTime := time.Since(start)
			encSumSq := decryptScalar(decryptor, encoder, ctSumSq, profile.Slots)
			results = append(results, StatResult{
				Name:           "Sum of Squares",
				PlaintextValue: plainStats["sumSq"],
				EncryptedValue: encSumSq,
				AbsoluteError:  math.Abs(encSumSq - plainStats["sumSq"]),
				RelativeError:  relError(encSumSq, plainStats["sumSq"]),
			})
			fmt.Printf("      ✓ Sum of Squares computed in %v (level: %d)\n", sumSqTime, ctSumSq.Level())
		}

		// Dot Product
		start = time.Now()
		ctDot, err := computeEncryptedDotProduct(evaluator, ctA, ctB, ctMask)
		if err != nil {
			fmt.Printf("      ⚠ Dot Product failed: %v\n", err)
		} else {
			dotTime := time.Since(start)
			encDot := decryptScalar(decryptor, encoder, ctDot, profile.Slots)
			results = append(results, StatResult{
				Name:           "Dot Product",
				PlaintextValue: plainStats["dot"],
				EncryptedValue: encDot,
				AbsoluteError:  math.Abs(encDot - plainStats["dot"]),
				RelativeError:  relError(encDot, plainStats["dot"]),
			})
			fmt.Printf("      ✓ Dot Product computed in %v (level: %d)\n", dotTime, ctDot.Level())
		}

		// Count
		start = time.Now()
		ctCount, err := computeEncryptedCount(evaluator, ctMask)
		if err != nil {
			fmt.Printf("      ⚠ Count failed: %v\n", err)
		} else {
			countTime := time.Since(start)
			encCount := decryptScalar(decryptor, encoder, ctCount, profile.Slots)
			results = append(results, StatResult{
				Name:           "Count",
				PlaintextValue: plainStats["count"],
				EncryptedValue: encCount,
				AbsoluteError:  math.Abs(encCount - plainStats["count"]),
				RelativeError:  relError(encCount, plainStats["count"]),
			})
			fmt.Printf("      ✓ Count computed in %v (level: %d)\n", countTime, ctCount.Level())
		}

		fmt.Println()

		// Step 6: Results and Noise Analysis
		fmt.Println("    ┌───────────────────────────────────────────────────────────┐")
		fmt.Println("    │ Results & Noise Analysis                                  │")
		fmt.Println("    └───────────────────────────────────────────────────────────┘")

		fmt.Println()
		fmt.Println("    ╔═══════════════════╦═══════════════════╦═══════════════════╦═══════════════╦═══════════════╗")
		fmt.Println("    ║ Statistic         ║ Plaintext         ║ Encrypted         ║ Abs Error     ║ Rel Error     ║")
		fmt.Println("    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════╬═══════════════╣")

		for _, r := range results {
			fmt.Printf("    ║ %-17s ║ %17.6f ║ %17.6f ║ %13.2e ║ %12.2e%% ║\n",
				r.Name, r.PlaintextValue, r.EncryptedValue, r.AbsoluteError, r.RelativeError*100)
		}

		fmt.Println("    ╚═══════════════════╩═══════════════════╩═══════════════════╩═══════════════╩═══════════════╝")
		fmt.Println()

		if len(results) > 0 {
			maxAbsErr := 0.0
			maxRelErr := 0.0
			avgRelErr := 0.0
			for _, r := range results {
				if r.AbsoluteError > maxAbsErr {
					maxAbsErr = r.AbsoluteError
				}
				if r.RelativeError > maxRelErr {
					maxRelErr = r.RelativeError
				}
				avgRelErr += r.RelativeError
			}
			avgRelErr /= float64(len(results))

			fmt.Println("    ┌───────────────────────────────────────────────────────────┐")
			fmt.Println("    │ Noise Summary                                             │")
			fmt.Println("    └───────────────────────────────────────────────────────────┘")
			fmt.Printf("      • Max Absolute Error:   %.6e\n", maxAbsErr)
			fmt.Printf("      • Max Relative Error:   %.6e%% (%.2f bits of precision)\n",
				maxRelErr*100, -math.Log2(maxRelErr+1e-15))
			fmt.Printf("      • Avg Relative Error:   %.6e%%\n", avgRelErr*100)
			fmt.Println()
		}

		// Step 7: Element-wise Noise Analysis
		fmt.Println("    ┌───────────────────────────────────────────────────────────┐")
		fmt.Println("    │ Element-wise Encryption/Decryption Noise                  │")
		fmt.Println("    └───────────────────────────────────────────────────────────┘")

		ptDecrypted := decryptor.DecryptNew(ctA)
		decrypted := make([]complex128, profile.Slots)
		if err := encoder.Decode(ptDecrypted, decrypted); err != nil {
			return fmt.Errorf("decode failed: %w", err)
		}

		fmt.Println("      First 10 elements comparison:")
		fmt.Println("      ┌─────────┬─────────────────────┬─────────────────────┬─────────────────┐")
		fmt.Println("      │  Index  │     Original        │     Decrypted       │   Abs Error     │")
		fmt.Println("      ├─────────┼─────────────────────┼─────────────────────┼─────────────────┤")

		showCount := 10
		if n < showCount {
			showCount = n
		}
		for i := 0; i < showCount; i++ {
			orig := vectorA[i]
			dec := real(decrypted[i])
			errVal := math.Abs(dec - orig)
			fmt.Printf("      │  %5d  │ %19.10f │ %19.10f │ %15.2e │\n", i, orig, dec, errVal)
		}
		fmt.Println("      └─────────┴─────────────────────┴─────────────────────┴─────────────────┘")

		allErrors := make([]float64, n)
		for i := 0; i < n; i++ {
			allErrors[i] = math.Abs(real(decrypted[i]) - vectorA[i])
		}

		fmt.Println()
		fmt.Printf("      Element-wise error statistics (n=%d):\n", n)
		fmt.Printf("        • Mean error:     %.6e\n", meanSlice(allErrors))
		fmt.Printf("        • Max error:      %.6e\n", maxSlice(allErrors))
		fmt.Printf("        • Min error:      %.6e\n", minSlice(allErrors))
		fmt.Printf("        • Std dev:        %.6e\n", stdSlice(allErrors))
		fmt.Println()
	}

	// Final Summary
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     Demo Complete!                               ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Println("║ Key Observations:                                                ║")
	fmt.Println("║ • CKKS encryption introduces small numerical noise               ║")
	fmt.Println("║ • Noise accumulates with each HE operation                       ║")
	fmt.Println("║ • Relative errors are typically < 0.001% for simple operations   ║")
	fmt.Println("║ • More complex operations (division) require more depth          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")

	return nil
}

func generateRandomVector(n int, min, max float64) []float64 {
	v := make([]float64, n)
	for i := 0; i < n; i++ {
		v[i] = min + rand.Float64()*(max-min)
	}
	return v
}

func generateMaskVector(n int, validProb float64) []float64 {
	v := make([]float64, n)
	for i := 0; i < n; i++ {
		if rand.Float64() < validProb {
			v[i] = 1.0
		} else {
			v[i] = 0.0
		}
	}
	return v
}

func padToSlots(v []float64, slots int) []float64 {
	padded := make([]float64, slots)
	copy(padded, v)
	return padded
}

func computePlaintextStats(a, b, mask []float64) map[string]float64 {
	stats := make(map[string]float64)
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if len(mask) < n {
		n = len(mask)
	}

	sum := 0.0
	sumSq := 0.0
	dot := 0.0
	count := 0.0

	for i := 0; i < n; i++ {
		m := mask[i]
		sum += a[i] * m
		sumSq += a[i] * a[i] * m
		dot += a[i] * b[i] * m
		count += m
	}

	stats["sum"] = sum
	stats["sumSq"] = sumSq
	stats["dot"] = dot
	stats["count"] = count

	if count > 0 {
		stats["mean"] = sum / count
		stats["variance"] = sumSq/count - (sum/count)*(sum/count)
	}

	return stats
}

func computeEncryptedSum(eval *he.Evaluator, ct, mask *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	masked, err := eval.Mul(ct, mask)
	if err != nil {
		return nil, err
	}
	masked, err = eval.Rescale(masked)
	if err != nil {
		return nil, err
	}
	return eval.SumSlots(masked)
}

func computeEncryptedSumSquares(eval *he.Evaluator, ct, mask *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	sq, err := eval.Mul(ct, ct)
	if err != nil {
		return nil, err
	}
	sq, err = eval.Rescale(sq)
	if err != nil {
		return nil, err
	}
	masked, err := eval.Mul(sq, mask)
	if err != nil {
		return nil, err
	}
	masked, err = eval.Rescale(masked)
	if err != nil {
		return nil, err
	}
	return eval.SumSlots(masked)
}

func computeEncryptedDotProduct(eval *he.Evaluator, ctA, ctB, mask *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	prod, err := eval.Mul(ctA, ctB)
	if err != nil {
		return nil, err
	}
	prod, err = eval.Rescale(prod)
	if err != nil {
		return nil, err
	}
	masked, err := eval.Mul(prod, mask)
	if err != nil {
		return nil, err
	}
	masked, err = eval.Rescale(masked)
	if err != nil {
		return nil, err
	}
	return eval.SumSlots(masked)
}

func computeEncryptedCount(eval *he.Evaluator, mask *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	return eval.SumSlots(mask)
}

func decryptScalar(decryptor *rlwe.Decryptor, encoder *ckks.Encoder, ct *rlwe.Ciphertext, slots int) float64 {
	pt := decryptor.DecryptNew(ct)
	result := make([]complex128, slots)
	encoder.Decode(pt, result)
	return real(result[0])
}

func minSlice(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	min := v[0]
	for _, x := range v[1:] {
		if x < min {
			min = x
		}
	}
	return min
}

func maxSlice(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	max := v[0]
	for _, x := range v[1:] {
		if x > max {
			max = x
		}
	}
	return max
}

func meanSlice(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func stdSlice(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	mean := meanSlice(v)
	sumSq := 0.0
	for _, x := range v {
		d := x - mean
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(v)))
}

func countOnes(v []float64) int {
	count := 0
	for _, x := range v {
		if x == 1.0 {
			count++
		}
	}
	return count
}

func relError(computed, expected float64) float64 {
	if math.Abs(expected) < 1e-10 {
		return math.Abs(computed)
	}
	return math.Abs(computed-expected) / math.Abs(expected)
}
