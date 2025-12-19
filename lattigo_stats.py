import subprocess
import json
import os
import pandas as pd
import matplotlib.pyplot as plt

class LattigoStats:
    """
    A Python wrapper for the LattigoStats Go CLI tools.
    Provides a seamless interface for KeyGen, Encryption, Computation, and Decryption.
    """
    
    def __init__(self, bin_dir="./bin"):
        self.bin_dir = bin_dir
        self.ddia_bin = os.path.join(bin_dir, "ddia")
        self.do_encrypt_bin = os.path.join(bin_dir, "do_encrypt")
        self.da_run_bin = os.path.join(bin_dir, "da_run")

    def _run_cmd(self, cmd):
        print(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            raise Exception(f"Command failed with exit code {result.returncode}")
        print(result.stdout)
        return result.stdout

    def keygen(self, profile="B", output_dir="./keys"):
        cmd = [self.ddia_bin, "keygen", "-profile", profile, "-output", output_dir]
        return self._run_cmd(cmd)

    def encrypt(self, data_path, schema_path, pk_path, output_dir="./encrypted", profile="B"):
        cmd = [
            self.do_encrypt_bin, 
            "-data", data_path, 
            "-schema", schema_path, 
            "-pk", pk_path, 
            "-output", output_dir, 
            "-profile", profile
        ]
        return self._run_cmd(cmd)

    def run_job(self, job_path, table_dir, keys_dir, output_dir="result.ct"):
        cmd = [
            self.da_run_bin,
            "-job", job_path,
            "-table", table_dir,
            "-keys", keys_dir,
            "-output", output_dir
        ]
        return self._run_cmd(cmd)

    def decrypt(self, sk_path, ct_path, output_path, profile="B"):
        cmd = [
            self.ddia_bin, "decrypt",
            "-sk", sk_path,
            "-ct", ct_path,
            "-output", output_path,
            "-profile", profile
        ]
        return self._run_cmd(cmd)

    def inspect(self, input_path):
        cmd = [self.ddia_bin, "inspect", "-input", input_path]
        return self._run_cmd(cmd)

    def load_decrypted_result(self, result_path):
        """Loads decrypted JSON result and returns a cleaned list of values."""
        with open(result_path, 'r') as f:
            data = json.load(f)
        
        # Filter out extreme noise values (typical for HE division by zero)
        # We assume values > 1e50 are noise/errors in this context
        cleaned = [v if v < 1e50 else float('nan') for v in data]
        return cleaned

    def plot_results(self, values, title="HE Operation Result"):
        """Simple visualization helper."""
        plt.figure(figsize=(10, 4))
        plt.plot(values, marker='o', linestyle='None', alpha=0.5)
        plt.title(title)
        plt.xlabel("Slot Index")
        plt.ylabel("Value")
        plt.grid(True, alpha=0.3)
        plt.show()

    def generate_schema(self, name, columns, output_path="schema.json"):
        schema = {
            "name": name,
            "columns": columns
        }
        with open(output_path, 'w') as f:
            json.dump(schema, f, indent=4)
        print(f"Schema saved to {output_path}")

    def generate_job(self, job_id, operation, table, target_column, conditions, output_path):
        job = {
            "id": job_id,
            "operation": operation,
            "table": table,
            "target_column": target_column,
            "conditions": conditions
        }
        with open(output_path, 'w') as f:
            json.dump(job, f, indent=4)
        print(f"Job saved to {output_path}")
