# zkFHE TOML Generator

A modular Rust workspace for generating cryptographic parameters and TOML files for zkFHE (zero-knowledge Fully Homomorphic Encryption) circuits, specifically designed for Noir zero-knowledge proofs.

- Clean separation between shared utilities and circuit-specific implementations in order to add new circuits with the trait-based interface.
- Pre-configured security levels (dev, test, prod) with comprehensive parameter validation and error handling.
- Generates Prover TOML files compatible with Noir circuits.

## Installation

### Prerequisites

- Rust 1.86+ (stable)
- Cargo

### Building

```bash
# Clone the repository
git clone <repository-url>
cd zkfhe-toml-generator

# Build all crates
cargo build

# Build specific crate
cargo build -p zkfhe-generator
```

## Usage

### CLI Commands

#### List available circuits and presets
```bash
cargo run -p zkfhe-generator -- list
```

#### Generate parameters for a specific circuit
```bash
# Basic generation with dev preset (BFV only)
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev

# Generate with custom BFV parameters
cargo run -p zkfhe-generator -- generate --circuit greco --bfv-n 16384 --z 2000 --lambda 128

# Generate with custom output directory
cargo run -p zkfhe-generator -- generate --circuit greco --preset prod --output ./my-output

# Note: Currently no circuits accept both BFV and PVW parameters
# PVW parameters can be provided but will show a warning for BFV-only circuits like greco
cargo run -p zkfhe-generator -- generate --circuit greco --pvw-n 1000 --verbose
```

### Generated Output

The generator creates a `Prover.toml` file containing the following. Please, note that these might vary a bit based on the circuit.

- **Cryptographic Parameters**: BFV configuration (degree, moduli, etc.)
- **Bounds**: Valid ranges for polynomial coefficients based on computed parameters
- **Vectors**: Input validation vectors for zero-knowledge proofs
- **Metadata**: Generation timestamp, configuration details, and parameter compatibility information

### Parameter Types and Circuit Compatibility

#### BFV Parameters
- Used for homomorphic encryption operations
- Required by all circuits
- Automatically computed based on security requirements

#### PVW Parameters  
- Used for zero-knowledge proof systems
- **Currently not supported by any existing circuits**
- Infrastructure is in place for future circuits that require PVW parameters
- Include redundancy factors (ℓ), LWE dimensions (k), and error bounds (σ₁, σ₂)

#### Current Circuit Support
- **greco**: BFV only (will show warning if PVW parameters are provided)

## Architecture

### Core Traits

#### `Circuit`
The main trait that all circuit implementations must implement:

```rust
pub trait Circuit {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn generate_params(&self, config: &CircuitConfig) -> Result<CircuitParams, Box<dyn Error>>;
    fn generate_toml(&self, params: &CircuitParams, output_dir: &Path) -> Result<(), Box<dyn Error>>;
    fn validate_config(&self, config: &CircuitConfig) -> Result<(), Box<dyn Error>>;
}
```

#### `TomlGenerator`
Trait for TOML file generation:

```rust
pub trait TomlGenerator {
    fn to_toml_string(&self) -> Result<String, Box<dyn Error>>;
    fn generate_toml(&self, output_dir: &Path) -> Result<PathBuf, Box<dyn Error>>;
}
```

### Adding a New Circuit

1. Create a new crate in `crates/circuits/your-circuit/`
2. Implement the `Circuit` trait in `src/lib.rs`
3. Add circuit-specific modules (bounds, vectors, toml)
4. Register the circuit in the generator CLI
5. (optional) Add tests to ensure correctness

### Run all tests
```bash
cargo test
```

### Test CLI
```bash
cargo test -p zkfhe-generator
```

## 📄 License

This repo created under the [LGPL-3.0+ license](LICENSE).