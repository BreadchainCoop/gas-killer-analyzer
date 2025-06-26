use alloy::{hex, primitives::FixedBytes, providers::ProviderBuilder, signers::local::LocalSigner};
use alloy_rpc_types::TransactionRequest;
use clap::Parser;
use clap_derive::{Parser, Subcommand};
use gas_analyzer_rs::{
    call_to_encoded_state_updates_with_gas_estimate, fetch_encoded_state_updates_with_gas_estimate,
    fetch_encoded_state_updates_with_gas_estimate_block, gk::GasKillerDefault,
};
use std::{fs::File, io::Read};
use url::Url;

#[derive(Parser, Debug)]
#[command(version, about = "Gas Killer savings analyzer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Block {
        #[arg(short = 'n', long, help = "block number")]
        number: u64,
    },
    Transaction {
        #[arg(long = "hash", help = "transaction hash")]
        hash: String,
    },
    Request {
        #[arg(
            short = 'f',
            long = "file",
            help = "transaction request (as JSON file)"
        )]
        file: String,
    },
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let cli = Cli::parse();
    let rpc_url: Url = std::env::var("TESTNET_RPC_URL")
        .expect("TESTNET_RPC_URL must be set")
        .parse()
        .expect("unable to parse rpc url");
    let gk = GasKillerDefault::new()
        .await
        .expect("unable to initialize GasKiller");
    match &cli.command {
        Commands::Block { number } => {
            let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
            let private_key = private_key.strip_prefix("0x").unwrap_or(&private_key);
            let bytes = hex::decode(private_key).expect("Invalid private key hex");
            let signer = LocalSigner::from_slice(&bytes).expect("Invalid private key");
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(rpc_url.clone());
            let result = fetch_encoded_state_updates_with_gas_estimate_block(
                provider,
                number.to_be_bytes().as_ref(),
                gk,
            )
            .await;
            if let Ok((_, estimate)) = result {
                println!("gas killer estimate: {}", estimate);
            } else {
                println!("estimation failed");
            }
        }
        Commands::Transaction { hash } => {
            let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
            let private_key = private_key.strip_prefix("0x").unwrap_or(&private_key);
            let bytes = hex::decode(private_key).expect("Invalid private key hex");
            let signer = LocalSigner::from_slice(&bytes).expect("Invalid private key");
            let provider = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(rpc_url.clone());
            let bytes: [u8; 32] = hex::const_decode_to_array(hash.as_bytes())
                .expect("failed to decode transaction hash");
            let result = fetch_encoded_state_updates_with_gas_estimate(
                provider,
                FixedBytes::from(bytes),
                gk,
            )
            .await;
            if let Ok((_, estimate)) = result {
                println!("gas killer estimate: {}", estimate);
            } else {
                println!("estimation failed");
            }
        }
        Commands::Request { file } => {
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
    }
}
