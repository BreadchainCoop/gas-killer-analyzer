use alloy::{hex, providers::ProviderBuilder, signers::local::LocalSigner};
use alloy_eips::{BlockId, BlockNumberOrTag, RpcBlockHash};
use alloy_rpc_types::TransactionRequest;
use colored::Colorize;
use gas_analyzer_rs::{
    call_to_encoded_state_updates_with_gas_estimate, gas_estimate_block, gas_estimate_tx,
    gk::GasKillerDefault,
};
use std::env;
use std::{fs::File, io::Read};
use url::Url;

enum Commands {
    Block(String),
    Transaction(String),
    Request(String),
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let args: Vec<String> = env::args().collect();
    let command: Option<Commands> = if args.len() < 3 {
        None
    } else {
        let input_type: &str = &args[1];
        match input_type {
            "b" | "block" => {
                let value = &args[2];
                Some(Commands::Block(value.clone()))
            }
            "t" | "tx" => {
                let value = &args[2];
                Some(Commands::Transaction(value.clone()))
            }
            "r" | "request" => {
                let value = &args[2];
                Some(Commands::Request(value.clone()))
            }
            _ => None,
        }
    };

    let rpc_url: Url = std::env::var("TESTNET_RPC_URL")
        .expect("TESTNET_RPC_URL must be set")
        .parse()
        .expect("unable to parse rpc url");
    let gk = GasKillerDefault::new()
        .await
        .expect("unable to initialize GasKiller");
    match command {
        Some(Commands::Block(hash)) => {
            let identifier = match hash.as_ref() {
                "latest" => BlockId::Number(BlockNumberOrTag::Latest),
                "finalized" => BlockId::Number(BlockNumberOrTag::Finalized),
                "safe" => BlockId::Number(BlockNumberOrTag::Safe),
                "earliest" => BlockId::Number(BlockNumberOrTag::Earliest),
                "pending" => BlockId::Number(BlockNumberOrTag::Pending),
                _ => {
                    let id = hex::const_decode_to_array(hash.as_bytes())
                        .expect("failed to decode transaction hash");
                    BlockId::Hash(RpcBlockHash {
                        block_hash: id.into(),
                        require_canonical: None,
                    })
                }
            };

            let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
            let private_key = private_key.strip_prefix("0x").unwrap_or(&private_key);
            let bytes = hex::decode(private_key).expect("Invalid private key hex");
            let signer = LocalSigner::from_slice(&bytes).expect("Invalid private key");
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(rpc_url.clone());
            let estimate = gas_estimate_block(provider, identifier, gk).await;
            if let Err(e) = estimate {
                println!("Error! {}", e)
            }
        }
        Some(Commands::Transaction(hash)) => {
            let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
            let private_key = private_key.strip_prefix("0x").unwrap_or(&private_key);
            let bytes = hex::decode(private_key).expect("Invalid private key hex");
            let signer = LocalSigner::from_slice(&bytes).expect("Invalid private key");
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(rpc_url.clone());
            let bytes: [u8; 32] = hex::const_decode_to_array(hash.as_bytes())
                .expect("failed to decode transaction hash");

            let estimate = gas_estimate_tx(provider, bytes.into(), gk).await;
            if let Err(e) = estimate {
                println!("Error! {}", e)
            }
        }
        Some(Commands::Request(file)) => {
            let mut file = File::open(file).expect("couldn't find file");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("unable to read file contents");
            let request = serde_json::from_str::<TransactionRequest>(contents.as_ref())
                .expect("unable to read json data");
            if let Ok((_, estimate)) =
                call_to_encoded_state_updates_with_gas_estimate(rpc_url, request, gk).await
            {
                println!("gas killer estimate: {estimate}");
            } else {
                println!("estimation failed!");
            }
        }
        None => {
            println!("failed to recognize input, please check your arguments again:\n");
            println!(
                "{} for blocks",
                "b/block [<HASH> | latest | pending | finalized | safe | earliest]".bold()
            );
            println!("{} for accepted transactions", "t/tx <HASH>".bold());
            println!(
                "{} for transaction requests",
                "r/request <JSON_FILE>".bold()
            );
        }
    }
}
