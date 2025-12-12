// DDIA - Data Decryption and Inspection Authority
// This tool handles key generation, decryption, and privacy inspection.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hkanpak21/lattigostats/pkg/params"
	"github.com/hkanpak21/lattigostats/pkg/privacy"
	"github.com/hkanpak21/lattigostats/pkg/storage"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	// Subcommands
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	inspectCmd := flag.NewFlagSet("inspect", flag.ExitOnError)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		runKeygen(keygenCmd, os.Args[2:])
	case "decrypt":
		runDecrypt(decryptCmd, os.Args[2:])
	case "inspect":
		runInspect(inspectCmd, os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: ddia <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen   Generate CKKS keys")
	fmt.Println("  decrypt  Decrypt ciphertext")
	fmt.Println("  inspect  Run privacy inspection")
}

func runKeygen(cmd *flag.FlagSet, args []string) {
	profile := cmd.String("profile", "A", "Parameter profile (A or B)")
	outputDir := cmd.String("output", "./keys", "Output directory for keys")
	cmd.Parse(args)

	// Get parameters
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

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Generate keys
	fmt.Println("Generating secret key...")
	kgen := rlwe.NewKeyGenerator(p)
	sk := kgen.GenSecretKeyNew()

	fmt.Println("Generating public key...")
	pk := kgen.GenPublicKeyNew(sk)

	fmt.Println("Generating relinearization key...")
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Save keys
	fmt.Println("Saving keys...")

	// Secret key (keep secure!)
	skPath := filepath.Join(*outputDir, "secret.key")
	if err := saveKey(skPath, sk); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save secret key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Secret key saved to: %s (KEEP SECURE!)\n", skPath)

	// Public key
	pkPath := filepath.Join(*outputDir, "public.key")
	if err := saveKey(pkPath, pk); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save public key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Public key saved to: %s\n", pkPath)

	// Relinearization key
	rlkPath := filepath.Join(*outputDir, "relin.key")
	if err := saveKey(rlkPath, rlk); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save relinearization key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Relinearization key saved to: %s\n", rlkPath)

	// Generate Galois keys (and bootstrapping keys for Profile B)
	if prof.BootstrapEnabled {
		fmt.Println("Generating Bootstrapping keys (this may take a while)...")
		fmt.Println("WARNING: This operation is memory-intensive and may take several minutes.")

		// Create bootstrapping parameters
		logN := p.LogN()
		btpParamsLiteral := bootstrapping.ParametersLiteral{
			LogN: &logN,
			LogP: []int{61, 61, 61, 61},
			Xs:   p.Xs(),
		}

		btpParams, err := bootstrapping.NewParametersFromLiteral(p, btpParamsLiteral)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create bootstrapping params: %v\n", err)
			os.Exit(1)
		}

		// Generate bootstrapping evaluation keys
		btpEvk, _, err := btpParams.GenEvaluationKeys(sk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate bootstrapping keys: %v\n", err)
			os.Exit(1)
		}

		// Save bootstrapping keys as a single bundle
		bkPath := filepath.Join(*outputDir, "bootstrapping.key")
		bkData, err := btpEvk.MarshalBinary()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal bootstrapping keys: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(bkPath, bkData, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save bootstrapping keys: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Bootstrapping keys saved to: %s\n", bkPath)

	} else {
		// Profile A: Generate standard Galois keys for rotations
		fmt.Println("Generating Galois keys for rotations...")
		slots := p.MaxSlots()
		galks := kgen.GenGaloisKeysNew(rlwe.GaloisElementsForInnerSum(p, 1, slots), sk)

		// Save Galois keys individually
		galksDir := filepath.Join(*outputDir, "galois")
		if err := os.MkdirAll(galksDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create galois directory: %v\n", err)
			os.Exit(1)
		}
		for i, gk := range galks {
			gkPath := filepath.Join(galksDir, fmt.Sprintf("galois_%d.key", i))
			if err := saveKey(gkPath, gk); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save Galois key %d: %v\n", i, err)
				os.Exit(1)
			}
		}
		fmt.Printf("Galois keys saved to: %s\n", galksDir)
	}

	// Save parameters metadata
	meta := map[string]interface{}{
		"profile":   *profile,
		"log_n":     p.LogN(),
		"log_scale": p.LogDefaultScale(),
		"slots":     p.MaxSlots(),
	}
	metaPath := filepath.Join(*outputDir, "params.json")
	f, err := os.Create(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create params file: %v\n", err)
		os.Exit(1)
	}
	json.NewEncoder(f).Encode(meta)
	f.Close()
	fmt.Printf("Parameters saved to: %s\n", metaPath)

	fmt.Println("\nKey generation complete!")
}

func saveKey(path string, key interface{ MarshalBinary() ([]byte, error) }) error {
	data, err := key.MarshalBinary()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func runDecrypt(cmd *flag.FlagSet, args []string) {
	skPath := cmd.String("sk", "", "Path to secret key")
	ctPath := cmd.String("ct", "", "Path to ciphertext")
	outputPath := cmd.String("output", "", "Output path for plaintext")
	paramsProfile := cmd.String("profile", "A", "Parameter profile")
	cmd.Parse(args)

	if *skPath == "" || *ctPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: ddia decrypt -sk <secret_key> -ct <ciphertext>")
		os.Exit(1)
	}

	// Load parameters
	var prof *params.Profile
	var err error
	switch *paramsProfile {
	case "A":
		prof, err = params.NewProfileA()
	case "B":
		prof, err = params.NewProfileB()
	default:
		fmt.Fprintf(os.Stderr, "Unknown profile: %s\n", *paramsProfile)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create parameters: %v\n", err)
		os.Exit(1)
	}
	p := prof.Params

	// Load secret key
	skData, err := os.ReadFile(*skPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read secret key: %v\n", err)
		os.Exit(1)
	}
	sk := new(rlwe.SecretKey)
	if err := sk.UnmarshalBinary(skData); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse secret key: %v\n", err)
		os.Exit(1)
	}

	// Load ciphertext using storage package (handles length prefix)
	ct, err := storage.LoadCiphertext(*ctPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ciphertext: %v\n", err)
		os.Exit(1)
	}

	// Decrypt
	decryptor := rlwe.NewDecryptor(p, sk)
	encoder := ckks.NewEncoder(p)

	pt := decryptor.DecryptNew(ct)
	values := make([]complex128, p.MaxSlots())
	encoder.Decode(pt, values)

	// Output
	realValues := make([]float64, len(values))
	for i, v := range values {
		realValues[i] = real(v)
	}

	if *outputPath != "" {
		f, err := os.Create(*outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		json.NewEncoder(f).Encode(realValues)
		f.Close()
		fmt.Printf("Decrypted values saved to: %s\n", *outputPath)
	} else {
		// Print first few values
		fmt.Println("Decrypted values (first 10):")
		for i := 0; i < 10 && i < len(realValues); i++ {
			fmt.Printf("  [%d]: %f\n", i, realValues[i])
		}
	}
}

func runInspect(cmd *flag.FlagSet, args []string) {
	inputPath := cmd.String("input", "", "Path to decrypted values JSON")
	policyPath := cmd.String("policy", "", "Path to privacy policy JSON")
	jobID := cmd.String("job", "", "Job ID for audit")
	operation := cmd.String("op", "", "Operation type")
	count := cmd.Int("count", 0, "Sample count")
	cmd.Parse(args)

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: ddia inspect -input <values.json> [-policy <policy.json>]")
		os.Exit(1)
	}

	// Load policy
	var policy *privacy.Policy
	if *policyPath != "" {
		var err error
		policy, err = privacy.LoadPolicy(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
			os.Exit(1)
		}
	} else {
		policy = privacy.DefaultPolicy()
	}

	// Load values
	f, err := os.Open(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open input: %v\n", err)
		os.Exit(1)
	}
	var values []float64
	json.NewDecoder(f).Decode(&values)
	f.Close()

	// Run inspection
	inspector := privacy.NewInspector(policy)

	// For simple numeric result, inspect first value
	if len(values) > 0 {
		result := inspector.InspectNumeric(values[0], *count, *jobID, *operation)

		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	}
}
