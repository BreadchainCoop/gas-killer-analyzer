use alloy::{hex, providers::ProviderBuilder};
use alloy_eips::BlockId;
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use anyhow::Result;
use colored::Colorize;
use csv::WriterBuilder;
use gas_analyzer_rs::{
    call_to_encoded_state_updates_with_gas_estimate, gas_estimate_block, gas_estimate_tx,
    gk::GasKillerDefault,
};
use std::fs::OpenOptions;
use std::path::Path;
use std::str::FromStr;
use std::{env, path};
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

    let result = execute_command(command).await;
    if let Err(e) = result {
        println!("{e:?}");
    }
}

async fn execute_command(cmd: Option<Commands>) -> Result<()> {
    let rpc_url: Url = std::env::var("RPC_URL")
        .expect("RPC_URL must be set")
        .parse()
        .expect("unable to parse rpc url");

    match cmd {
        Some(Commands::Block(input)) => {
            let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
            let identifier =
                BlockId::from_str(input.as_ref()).expect("failed to parse block identifier");
            let all_receipts = provider
                .get_block_receipts(identifier)
                .await?
                .expect("couldn't fetch block receipts");
            let block_number = all_receipts[0]
                .block_number
                .expect("couldn't retrieve block number");
            let gk = GasKillerDefault::builder(rpc_url.clone())
                .block_number(block_number)
                .build()
                .await
                .expect("unable to initialize GasKiller");

            println!("generating gaskiller reports...");
            let reports = gas_estimate_block(provider, all_receipts, gk).await?;
            println!("fetched reports");
            let output_file = std::env::var("OUTPUT_FILE").expect("OUTPUT_FILE must be set");
            let path = Path::new(output_file.as_str());

            let exists = path::Path::exists(path);
            let file = OpenOptions::new()
                .create(!exists)
                .append(true)
                .open(path)
                .unwrap();
            let mut writer = WriterBuilder::new().has_headers(!exists).from_writer(file);
            for report in reports {
                writer.serialize(&report)?;
                println!("serialized {}", report.tx_hash);
            }
            writer.flush()?;
            println!("successfully wrote data to {output_file}");
        }
        Some(Commands::Transaction(hash)) => {
            let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
            let bytes: [u8; 32] = hex::const_decode_to_array(hash.as_bytes())
                .expect("failed to decode transaction hash");
            let receipt = provider
                .get_transaction_receipt(bytes.into())
                .await?
                .expect("couldn't fetch tx receipt for tx {hash}");
            let block_number = receipt
                .block_number
                .expect("couldn't retrieve block number");
            let gk = GasKillerDefault::builder(rpc_url.clone())
                .block_number(block_number)
                .build()
                .await
                .expect("unable to initialize GasKiller");

            let report = gas_estimate_tx(provider, bytes.into(), &gk).await?;
            let output_file = std::env::var("OUTPUT_FILE").expect("OUTPUT_FILE must be set");
            let path = Path::new(output_file.as_str());

            let exists = path::Path::exists(path);
            let file = OpenOptions::new()
                .create(!exists)
                .append(true)
                .open(path)
                .unwrap();
            let mut writer = WriterBuilder::new().has_headers(!exists).from_writer(file);
            writer.serialize(report)?;
            writer.flush()?;
            println!("successfully wrote data to {output_file}");
        }

        Some(Commands::Request(file)) => {
            let gk = GasKillerDefault::builder(rpc_url.clone())
                .build()
                .await
                .expect("unable to initialize GasKiller");
            let mut file = File::open(file).expect("couldn't find file");
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .expect("unable to read file contents");
            let request = serde_json::from_str::<TransactionRequest>(contents.as_ref())
                .expect("unable to read json data");
            if let Ok((_, estimate, _)) =
                call_to_encoded_state_updates_with_gas_estimate(request, gk).await
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
