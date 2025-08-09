use anyhow::Result;
use tx_state_extractor::{TxStateExtractor, types::StateUpdate, encoder::SolidityEncoder};
use alloy_primitives::{FixedBytes, hex};
use std::env;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();
    
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <transaction_hash> [rpc_url]", args[0]);
        eprintln!("Example: {} 0x1234... https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY", args[0]);
        std::process::exit(1);
    }
    
    let tx_hash_str = &args[1];
    let rpc_url = if let Some(url) = args.get(2) {
        url.to_string()
    } else if let Ok(url) = env::var("RPC_URL") {
        url
    } else {
        "https://eth.llamarpc.com".to_string()
    };
    
    println!("Extracting state updates for transaction: {}", tx_hash_str);
    println!("Using RPC URL: {}", rpc_url);
    println!();
    
    let tx_hash: FixedBytes<32> = tx_hash_str.parse()?;
    
    let extractor = TxStateExtractor::new(&rpc_url)?;
    
    println!("Fetching transaction data...");
    let report = extractor.extract_with_metadata(tx_hash).await?;
    
    println!("\n=== Transaction Metadata ===");
    println!("Block Number: {}", report.block_number);
    println!("From: {:?}", report.from);
    println!("To: {:?}", report.to);
    println!("Value: {} wei", report.value);
    println!("Gas Used: {}", report.gas_used);
    println!("Status: {}", if report.status { "Success" } else { "Failed" });
    
    println!("\n=== State Updates ({} total) ===", report.state_updates.len());
    
    for (i, update) in report.state_updates.iter().enumerate() {
        println!("\n[Update #{}]", i + 1);
        match update {
            StateUpdate::Store(store) => {
                println!("  Type: SSTORE");
                println!("  Slot: 0x{}", hex::encode(store.slot));
                println!("  Value: 0x{}", hex::encode(store.value));
            }
            StateUpdate::Call(call) => {
                println!("  Type: CALL");
                println!("  Target: {:?}", call.target);
                println!("  Value: {} wei", call.value);
                println!("  Calldata: 0x{}", hex::encode(&call.callargs));
            }
            StateUpdate::Log0(log) => {
                println!("  Type: LOG0");
                println!("  Data: 0x{}", hex::encode(&log.data));
            }
            StateUpdate::Log1(log) => {
                println!("  Type: LOG1");
                println!("  Topic1: 0x{}", hex::encode(log.topic1));
                println!("  Data: 0x{}", hex::encode(&log.data));
            }
            StateUpdate::Log2(log) => {
                println!("  Type: LOG2");
                println!("  Topic1: 0x{}", hex::encode(log.topic1));
                println!("  Topic2: 0x{}", hex::encode(log.topic2));
                println!("  Data: 0x{}", hex::encode(&log.data));
            }
            StateUpdate::Log3(log) => {
                println!("  Type: LOG3");
                println!("  Topic1: 0x{}", hex::encode(log.topic1));
                println!("  Topic2: 0x{}", hex::encode(log.topic2));
                println!("  Topic3: 0x{}", hex::encode(log.topic3));
                println!("  Data: 0x{}", hex::encode(&log.data));
            }
            StateUpdate::Log4(log) => {
                println!("  Type: LOG4");
                println!("  Topic1: 0x{}", hex::encode(log.topic1));
                println!("  Topic2: 0x{}", hex::encode(log.topic2));
                println!("  Topic3: 0x{}", hex::encode(log.topic3));
                println!("  Topic4: 0x{}", hex::encode(log.topic4));
                println!("  Data: 0x{}", hex::encode(&log.data));
            }
        }
    }
    
    if !report.skipped_opcodes.is_empty() {
        println!("\n=== Skipped Opcodes ===");
        println!("{:?}", report.skipped_opcodes);
    }
    
    println!("\n=== Solidity Encoding ===");
    let encoded = SolidityEncoder::encode_state_updates(report.state_updates)?;
    println!("Types array: {:?}", encoded.types);
    println!("Data array length: {}", encoded.data.len());
    let abi_encoded = SolidityEncoder::to_abi_encoded(&encoded);
    println!("ABI encoded (first 100 bytes): 0x{}", hex::encode(&abi_encoded[..abi_encoded.len().min(100)]));
    
    Ok(())
}

