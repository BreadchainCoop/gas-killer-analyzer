use alloy::{hex, providers::ProviderBuilder};
use alloy_eips::{BlockId, BlockNumberOrTag, RpcBlockHash};
use alloy_rpc_types::TransactionRequest;
use anyhow::Result;
use colored::Colorize;
use csv::Writer;
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

    let _ = execute_command(command).await;
}

async fn execute_command(cmd: Option<Commands>) -> Result<()> {
    let rpc_url: Url = std::env::var("RPC_URL")
        .expect("RPC_URL must be set")
        .parse()
        .expect("unable to parse rpc url");
    let gk = GasKillerDefault::new()
        .await
        .expect("unable to initialize GasKiller");
    match cmd {
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

            let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
            println!("generating gaskiller reports...");
            let reports = gas_estimate_block(provider, identifier, gk).await?;
            let mut writer = Writer::from_path("../../reports/{hash}.csv")?;
            let _ = reports.iter().map(|report| writer.serialize(report));
            writer.flush()?;
            println!("successfully wrote data to reports/{hash}.csv");
        }
        Some(Commands::Transaction(hash)) => {
            let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
            let bytes: [u8; 32] = hex::const_decode_to_array(hash.as_bytes())
                .expect("failed to decode transaction hash");
            println!("generating gaskiller report...");
            let report = gas_estimate_tx(provider, bytes.into(), gk).await?;
            let mut writer = Writer::from_path("../../reports/{hash}.csv")?;
            writer.serialize(report)?;
            writer.flush()?;
            println!("successfully wrote data to reports/{hash}.csv");
        }

        Some(Commands::Request(file)) => {
            let mut file = File::open(file).expect("couldn't find file");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("unable to read file contents");
            let request = serde_json::from_str::<TransactionRequest>(contents.as_ref())
                .expect("unable to read json data");
            if let Ok((_, estimate, _)) =
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
    Ok(())
}
