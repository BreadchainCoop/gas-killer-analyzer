# Transaction State Extractor

A lightweight, standalone Rust library for extracting state updates from Ethereum transactions. This library provides a simple interface to trace transaction execution and extract all state-changing operations in Solidity-compatible structures.

## Overview

This library is extracted from the [gas-analyzer-rs](https://github.com/BreadchainCoop/gas-analyzer-rs) project, following the design specification in [tx-hash-to-state-updates-extraction.md](../tx-hash-to-state-updates-extraction.md). It provides:

- Transaction tracing via Ethereum's debug API
- State update extraction (SSTORE, CALL, LOG operations)
- Solidity-compatible data structures
- ABI encoding for smart contract integration
- Minimal dependencies and simple API

## Features

- ✅ Extract storage updates (SSTORE)
- ✅ Extract external calls (CALL, STATICCALL)
- ✅ Extract event logs (LOG0-LOG4)
- ✅ Handle nested calls and execution depth
- ✅ Parse EVM memory and stack
- ✅ Encode to Solidity-compatible format
- ✅ Full transaction metadata

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tx-state-extractor = { path = "tx-state-extractor" }
```

## Quick Start

```rust
use tx_state_extractor::{TxStateExtractor, types::StateUpdate};
use alloy_primitives::FixedBytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with RPC endpoint
    let extractor = TxStateExtractor::new("https://eth.llamarpc.com")?;
    
    // Parse transaction hash
    let tx_hash: FixedBytes<32> = "0x1234...".parse()?;
    
    // Extract state updates
    let updates = extractor.extract_state_updates(tx_hash).await?;
    
    // Process updates
    for update in updates {
        match update {
            StateUpdate::Store(store) => {
                println!("Storage: slot={:?}, value={:?}", store.slot, store.value);
            }
            StateUpdate::Call(call) => {
                println!("Call: to={:?}, value={:?}", call.target, call.value);
            }
            _ => {}
        }
    }
    
    Ok(())
}
```

## Usage Examples

### Extract with Metadata

```rust
// Get full transaction report with metadata
let report = extractor.extract_with_metadata(tx_hash).await?;

println!("From: {:?}", report.from);
println!("To: {:?}", report.to);
println!("Gas Used: {}", report.gas_used);
println!("State Updates: {}", report.state_updates.len());
```

### Encode for Solidity

```rust
use tx_state_extractor::encoder::SolidityEncoder;

// Encode state updates for smart contract consumption
let encoded = SolidityEncoder::encode_state_updates(updates)?;

// Get ABI-encoded bytes
let abi_bytes = SolidityEncoder::to_abi_encoded(&encoded);
```

### Command Line Usage

```bash
# Run the example with a transaction hash
cargo run --example basic_usage -- 0x1234...

# With custom RPC URL
cargo run --example basic_usage -- 0x1234... https://your-rpc-url
```

## Architecture

The library follows a modular design as specified in the [design document](../tx-hash-to-state-updates-extraction.md):

```
tx-state-extractor/
├── src/
│   ├── lib.rs          # Main extractor API
│   ├── provider.rs     # RPC provider abstraction
│   ├── parser.rs       # State update extraction logic
│   ├── types.rs        # Solidity-compatible types
│   ├── memory.rs       # EVM memory utilities
│   └── encoder.rs      # Solidity encoding
└── examples/
    └── basic_usage.rs  # Example usage
```

## State Update Types

The library extracts the following state update types:

- **SSTORE**: Storage slot modifications
- **CALL**: External contract calls
- **LOG0-LOG4**: Event emissions with topics

Problematic opcodes (CREATE, DELEGATECALL, SELFDESTRUCT) are tracked but skipped.

## Requirements

- Rust 1.70+
- RPC provider with `debug_trace_transaction` support
- Network access to Ethereum node

## RPC Provider Requirements

The RPC provider must support:
- `eth_getTransactionReceipt`
- `eth_getTransactionByHash`
- `debug_traceTransaction` with memory enabled

Compatible providers:
- Alchemy (with debug API addon)
- QuickNode
- Local nodes (Geth, Erigon)
- Anvil (for testing)

## Testing

```bash
# Run tests
cargo test

# Run with example transaction
RPC_URL=https://your-rpc cargo run --example basic_usage -- 0x...
```

## Performance Considerations

- Tracing large transactions can be memory-intensive
- Consider implementing caching for frequently accessed transactions
- Use batch requests when processing multiple transactions

## Integration with Solidity

```solidity
// Example Solidity contract to process state updates
contract StateUpdateProcessor {
    enum StateUpdateType { STORE, CALL, LOG0, LOG1, LOG2, LOG3, LOG4 }
    
    function processUpdates(
        uint8[] memory types,
        bytes[] memory data
    ) external {
        for (uint i = 0; i < types.length; i++) {
            if (types[i] == uint8(StateUpdateType.STORE)) {
                (bytes32 slot, bytes32 value) = abi.decode(data[i], (bytes32, bytes32));
                // Process storage update
            }
            // Handle other types...
        }
    }
}
```

## Contributing

This library is part of the gas-analyzer-rs project. See the main repository for contribution guidelines.

## License

MIT

## References

- [Design Document](../tx-hash-to-state-updates-extraction.md)
- [Gas Analyzer RS](https://github.com/BreadchainCoop/gas-analyzer-rs)
- [Issue #46](https://github.com/BreadchainCoop/gas-analyzer-rs/issues/46)