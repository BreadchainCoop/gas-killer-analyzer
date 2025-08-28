# Transaction State Extractor

Extract state updates from Ethereum transactions using the minimal API added to gas-analyzer-rs.

## Using as External Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
gas-analyzer-rs = { git = "https://github.com/BreadchainCoop/gas-analyzer-rs.git", branch = "main" }
alloy = { version = "1.0", features = ["providers", "rpc", "rpc-types"] }
alloy-provider = { version = "1.0", features = ["debug-api"] }
tokio = { version = "1.0", features = ["full"] }
```

## Basic Usage

```rust
use gas_analyzer_rs::tx_extractor::from_rpc_url;
use alloy::primitives::FixedBytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let extractor = from_rpc_url("https://eth.llamarpc.com")?;
    
    let tx_hash: FixedBytes<32> = "0x1234...".parse()?;
    let updates = extractor.extract_state_updates(tx_hash).await?;
    
    println!("Found {} state updates", updates.len());
    Ok(())
}
```

## Working with State Updates

```rust
use gas_analyzer_rs::sol_types::StateUpdate;

match update {
    StateUpdate::Store(store) => {
        // Storage modification: slot, value
    }
    StateUpdate::Call(call) => {
        // External call: target, value, calldata
    }
    StateUpdate::Log0(log) => {
        // Event without topics: data
    }
    // Log1, Log2, Log3, Log4 for events with topics
    _ => {}
}
```

## API Reference

- `from_rpc_url(url)` - Create extractor from RPC URL
- `extract_state_updates(tx_hash)` - Get state updates only
- `extract_with_metadata(tx_hash)` - Get state updates with transaction metadata

## Requirements

RPC provider must support:
- `eth_getTransactionReceipt`
- `eth_getTransactionByHash`
- `debug_traceTransaction`

Compatible providers: Alchemy, QuickNode, local nodes (Geth/Erigon/Anvil).

## Running the Example

```bash
RPC_URL=https://your-rpc cargo run --example tx_extractor_example 0xTRANSACTION_HASH
```