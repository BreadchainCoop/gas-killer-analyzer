use alloy::primitives::FixedBytes;
use anyhow::Result;
use gas_analyzer_rs::sol_types::StateUpdate;
use gas_analyzer_rs::tx_extractor::{StateUpdateReport, from_rpc_url};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Get transaction hash from command line or use example
    let args: Vec<String> = env::args().collect();
    let tx_hash_str = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");

    // Get RPC URL from environment or use default
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

    println!("Extracting state updates for transaction: {}", tx_hash_str);
    println!("Using RPC URL: {}", rpc_url);

    // Parse transaction hash
    let tx_hash: FixedBytes<32> = tx_hash_str.parse()?;

    // Create extractor from RPC URL
    let extractor = from_rpc_url(&rpc_url).await?;

    // Extract state updates with metadata
    match extractor.extract_with_metadata(tx_hash).await {
        Ok(report) => print_report(&report),
        Err(e) => {
            eprintln!("Error extracting state updates: {}", e);

            // Try basic extraction without metadata
            println!("\nTrying basic extraction...");
            match extractor.extract_state_updates(tx_hash).await {
                Ok(updates) => {
                    println!("Found {} state updates", updates.len());
                    for (i, update) in updates.iter().enumerate() {
                        println!("Update #{}: {:?}", i + 1, update);
                    }
                }
                Err(e) => eprintln!("Basic extraction also failed: {}", e),
            }
        }
    }

    Ok(())
}

fn print_report(report: &StateUpdateReport) {
    println!("\n=== Transaction Report ===");
    println!("Block Number: {}", report.block_number);
    println!("From: {:?}", report.from);
    println!("To: {:?}", report.to);
    println!("Value: {} wei", report.value);
    println!("Gas Used: {}", report.gas_used);
    println!(
        "Status: {}",
        if report.status { "Success" } else { "Failed" }
    );

    println!(
        "\n=== State Updates ({} total) ===",
        report.state_updates.len()
    );
    for (i, update) in report.state_updates.iter().enumerate() {
        println!("\n[Update #{}]", i + 1);
        match update {
            StateUpdate::Store(store) => {
                println!("  Type: SSTORE");
                println!("  Slot: {:?}", store.slot);
                println!("  Value: {:?}", store.value);
            }
            StateUpdate::Call(call) => {
                println!("  Type: CALL");
                println!("  Target: {:?}", call.target);
                println!("  Value: {} wei", call.value);
                println!("  Calldata length: {} bytes", call.callargs.len());
            }
            StateUpdate::Log0(log) => {
                println!("  Type: LOG0");
                println!("  Data length: {} bytes", log.data.len());
            }
            StateUpdate::Log1(log) => {
                println!("  Type: LOG1");
                println!("  Topic1: {:?}", log.topic1);
                println!("  Data length: {} bytes", log.data.len());
            }
            StateUpdate::Log2(log) => {
                println!("  Type: LOG2");
                println!("  Topic1: {:?}", log.topic1);
                println!("  Topic2: {:?}", log.topic2);
                println!("  Data length: {} bytes", log.data.len());
            }
            StateUpdate::Log3(log) => {
                println!("  Type: LOG3");
                println!("  Topic1: {:?}", log.topic1);
                println!("  Topic2: {:?}", log.topic2);
                println!("  Topic3: {:?}", log.topic3);
                println!("  Data length: {} bytes", log.data.len());
            }
            StateUpdate::Log4(log) => {
                println!("  Type: LOG4");
                println!("  Topic1: {:?}", log.topic1);
                println!("  Topic2: {:?}", log.topic2);
                println!("  Topic3: {:?}", log.topic3);
                println!("  Topic4: {:?}", log.topic4);
                println!("  Data length: {} bytes", log.data.len());
            }
        }
    }
}
