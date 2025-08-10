use gas_analyzer_rs::tx_extractor::{from_rpc_url, StateUpdateReport};
use gas_analyzer_rs::sol_types::StateUpdate;
use alloy::primitives::FixedBytes;
use anyhow::Result;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Get RPC URL and tx hash from environment or use defaults
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| {
        "https://compatible-floral-sponge.ethereum-holesky.quiknode.pro/5208c2ae65694338de5f5a883442970cf04fefe0".to_string()
    });
    
    let tx_hash_str = env::args().nth(1).unwrap_or_else(|| {
        "0xbcb9e0b361ca9567d2d5ef094edcf7a8553e1ba76d3e298d0419762012dc9148".to_string()
    });
    
    println!("Testing gas-analyzer-rs tx_extractor integration");
    println!("RPC URL: {}", rpc_url);
    println!("Transaction: {}", tx_hash_str);
    println!();
    
    // Parse transaction hash
    let tx_hash: FixedBytes<32> = tx_hash_str.parse()?;
    
    // Create extractor from RPC URL
    let extractor = from_rpc_url(&rpc_url)?;
    
    // Try to extract state updates with metadata
    match extractor.extract_with_metadata(tx_hash).await {
        Ok(report) => {
            print_report(&report);
            println!("\n✅ Successfully extracted state updates!");
        }
        Err(e) => {
            eprintln!("❌ Error extracting state updates: {}", e);
            
            // Try basic extraction
            println!("\nTrying basic extraction...");
            match extractor.extract_state_updates(tx_hash).await {
                Ok(updates) => {
                    println!("✅ Basic extraction succeeded!");
                    println!("Found {} state updates", updates.len());
                    for (i, update) in updates.iter().enumerate() {
                        println!("\nUpdate #{}: {}", i + 1, format_update(update));
                    }
                }
                Err(e) => eprintln!("❌ Basic extraction also failed: {}", e),
            }
        }
    }
    
    Ok(())
}

fn print_report(report: &StateUpdateReport) {
    println!("=== Transaction Report ===");
    println!("Block Number: {}", report.block_number);
    println!("From: {:?}", report.from);
    println!("To: {:?}", report.to);
    println!("Value: {} wei", report.value);
    println!("Gas Used: {}", report.gas_used);
    println!("Status: {}", if report.status { "Success ✅" } else { "Failed ❌" });
    
    println!("\n=== State Updates ({} total) ===", report.state_updates.len());
    for (i, update) in report.state_updates.iter().enumerate() {
        println!("\n[Update #{}] {}", i + 1, format_update(update));
    }
}

fn format_update(update: &StateUpdate) -> String {
    match update {
        StateUpdate::Store(store) => {
            format!("SSTORE: slot={:?}, value={:?}", store.slot, store.value)
        }
        StateUpdate::Call(call) => {
            format!("CALL: to={:?}, value={} wei, data_len={} bytes", 
                call.target, call.value, call.callargs.len())
        }
        StateUpdate::Log0(log) => {
            format!("LOG0: data_len={} bytes", log.data.len())
        }
        StateUpdate::Log1(log) => {
            format!("LOG1: topic={:?}, data_len={} bytes", log.topic1, log.data.len())
        }
        StateUpdate::Log2(log) => {
            format!("LOG2: topics=[{:?}, {:?}], data_len={} bytes", 
                log.topic1, log.topic2, log.data.len())
        }
        StateUpdate::Log3(log) => {
            format!("LOG3: topics=[{:?}, {:?}, {:?}], data_len={} bytes", 
                log.topic1, log.topic2, log.topic3, log.data.len())
        }
        StateUpdate::Log4(log) => {
            format!("LOG4: topics=[{:?}, {:?}, {:?}, {:?}], data_len={} bytes", 
                log.topic1, log.topic2, log.topic3, log.topic4, log.data.len())
        }
    }
}
