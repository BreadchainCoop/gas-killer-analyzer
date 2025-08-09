# Minimal Transaction State Extractor

This is a minimal implementation that addresses issue #46 by adding a lightweight transaction state extraction API to the existing gas-analyzer-rs codebase. Instead of creating a separate library with duplicated code, this approach reuses existing functionality through public exports.

## Changes Made

This implementation adds just **3 files** to the existing codebase:

1. **`src/tx_extractor.rs`** - A thin wrapper module that provides a clean API
2. **`examples/tx_extractor_example.rs`** - Example usage
3. **This README** - Documentation

Plus minimal changes to:
- **`src/lib.rs`** - Made 2 functions public and added module export
- **`Cargo.toml`** - Added example configuration

## Key Advantages

- **Minimal code addition**: ~150 lines total
- **No code duplication**: Reuses existing tracing and parsing logic
- **Zero new dependencies**: Uses existing project dependencies
- **Maintains compatibility**: No breaking changes to existing code
- **Easy to maintain**: Changes stay in sync with main codebase

## Usage

```rust
use gas_analyzer_rs::tx_extractor::from_rpc_url;
use alloy::primitives::FixedBytes;

#[tokio::main]
async fn main() -> Result<()> {
    // Create extractor
    let extractor = from_rpc_url("https://eth.llamarpc.com")?;
    
    // Extract state updates
    let tx_hash: FixedBytes<32> = "0x...".parse()?;
    let updates = extractor.extract_state_updates(tx_hash).await?;
    
    // Or with metadata
    let report = extractor.extract_with_metadata(tx_hash).await?;
    
    println!("Found {} state updates", updates.len());
    Ok(())
}
```

## API

The module exposes:

- `TxStateExtractor<P>` - Generic extractor that works with any provider
- `from_rpc_url(url)` - Convenience function to create extractor from RPC URL
- `extract_state_updates(tx_hash)` - Get just the state updates
- `extract_with_metadata(tx_hash)` - Get state updates with transaction metadata
- `StateUpdateReport` - Contains transaction metadata and state updates

## Running the Example

```bash
# With environment variable
RPC_URL=https://your-rpc cargo run --example tx_extractor_example 0xTRANSACTION_HASH

# Or with command line argument
cargo run --example tx_extractor_example 0xTRANSACTION_HASH
```

## Comparison with Standalone Library Approach

| Aspect | This Minimal Approach | Standalone Library (PR #47) |
|--------|----------------------|----------------------------|
| Files Added | 3 | 12+ |
| Lines of Code | ~150 | ~1900 |
| Dependencies | 0 new | Separate Cargo.toml |
| Maintenance | Automatic | Requires sync |
| Build Time | No change | Additional crate |
| Code Duplication | None | Significant |

## How It Works

This implementation:
1. Makes existing `compute_state_updates` and `get_tx_trace` functions public
2. Provides a thin wrapper (`TxStateExtractor`) for convenience
3. Exports types from `sol_types` module
4. Adds an example showing usage

The entire extraction logic remains in the main codebase, ensuring consistency and avoiding duplication.

## Resolves

This minimal implementation addresses all requirements from issue #46:
- ✅ Accepts transaction hash as input
- ✅ Extracts all state-changing operations
- ✅ Returns Solidity-compatible structures
- ✅ Operates independently (no gas estimation overhead)
- ✅ Lightweight and maintainable