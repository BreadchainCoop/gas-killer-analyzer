# Minimal Transaction State Extractor

This is a minimal implementation that addresses issue #46 by adding a lightweight transaction state extraction API to the existing gas-analyzer-rs codebase. Instead of creating a separate library with duplicated code, this approach reuses existing functionality through public exports.

## Using in External Projects

### Adding as a Dependency

To use the transaction state extractor in your own Rust project, add gas-analyzer-rs as a dependency in your `Cargo.toml`:

```toml
[dependencies]
gas-analyzer-rs = { git = "https://github.com/BreadchainCoop/gas-analyzer-rs.git", branch = "main" }
# Or use a specific commit/tag for stability:
# gas-analyzer-rs = { git = "https://github.com/BreadchainCoop/gas-analyzer-rs.git", rev = "COMMIT_HASH" }

# You'll also need these peer dependencies
alloy = { version = "1.0", features = ["providers", "rpc", "rpc-types"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
```

### Basic Usage in Your Project

```rust
use gas_analyzer_rs::tx_extractor::{from_rpc_url, TxStateExtractor, StateUpdateReport};
use gas_analyzer_rs::sol_types::StateUpdate;
use alloy::primitives::FixedBytes;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Method 1: Create from RPC URL
    let extractor = from_rpc_url("https://eth.llamarpc.com")?;
    
    // Method 2: Use with your own provider
    use alloy::providers::{Provider, ProviderBuilder};
    use gas_analyzer_rs::tx_extractor::TxStateExtractor;
    
    let provider = ProviderBuilder::new()
        .connect_http("https://eth.llamarpc.com".parse()?);
    let extractor = TxStateExtractor::new(provider);
    
    // Extract state updates
    let tx_hash: FixedBytes<32> = "0x1234...".parse()?;
    let updates = extractor.extract_state_updates(tx_hash).await?;
    
    // Process updates
    for update in updates {
        match update {
            StateUpdate::Store(store) => {
                println!("Storage update: slot={:?}, value={:?}", store.slot, store.value);
            }
            StateUpdate::Call(call) => {
                println!("Call: to={:?}, value={}", call.target, call.value);
            }
            // ... handle other update types
        }
    }
    
    Ok(())
}
```

### Advanced Integration Example

```rust
use gas_analyzer_rs::tx_extractor::{from_rpc_url, StateUpdateReport};
use gas_analyzer_rs::sol_types::{StateUpdate, IStateUpdateTypes};
use alloy::primitives::FixedBytes;

/// Your custom transaction analyzer
pub struct TransactionAnalyzer {
    extractor: gas_analyzer_rs::tx_extractor::TxStateExtractor<impl Provider + DebugApi>,
}

impl TransactionAnalyzer {
    pub fn new(rpc_url: &str) -> Result<Self> {
        Ok(Self {
            extractor: from_rpc_url(rpc_url)?,
        })
    }
    
    pub async fn analyze_transaction(&self, tx_hash: FixedBytes<32>) -> Result<AnalysisResult> {
        let report = self.extractor.extract_with_metadata(tx_hash).await?;
        
        let storage_changes = report.state_updates.iter()
            .filter_map(|u| match u {
                StateUpdate::Store(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        
        let calls = report.state_updates.iter()
            .filter_map(|u| match u {
                StateUpdate::Call(c) => Some(c.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        
        Ok(AnalysisResult {
            tx_hash: report.tx_hash,
            storage_changes_count: storage_changes.len(),
            external_calls_count: calls.len(),
            gas_used: report.gas_used,
            // ... your custom analysis
        })
    }
}
```

### Working with State Updates

The state updates are returned as Solidity-compatible structures:

```rust
use gas_analyzer_rs::sol_types::StateUpdate;

fn process_state_update(update: &StateUpdate) {
    match update {
        StateUpdate::Store(store) => {
            // Storage slot modification
            let slot = store.slot;    // FixedBytes<32>
            let value = store.value;  // FixedBytes<32>
        }
        StateUpdate::Call(call) => {
            // External call
            let target = call.target;     // Address
            let value = call.value;       // U256
            let calldata = &call.callargs; // Bytes
        }
        StateUpdate::Log0(log) => {
            // Event without topics
            let data = &log.data;  // Bytes
        }
        StateUpdate::Log1(log) => {
            // Event with 1 topic
            let topic1 = log.topic1;  // FixedBytes<32>
            let data = &log.data;     // Bytes
        }
        // Log2, Log3, Log4 follow the same pattern
        _ => {}
    }
}
```

### Requirements for External Projects

Your RPC provider must support:
- `eth_getTransactionReceipt`
- `eth_getTransactionByHash`
- `debug_traceTransaction` with memory enabled

Compatible RPC providers:
- Alchemy (with debug API addon)
- QuickNode (with trace addon)
- Local nodes (Geth, Erigon, Anvil)
- Any provider with debug/trace API support

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