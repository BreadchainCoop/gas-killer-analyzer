use std::env;
use std::path::PathBuf;
use anyhow::Result;
use alloy_eips::eip1898::BlockId;
use clap::{Parser, Subcommand};
use gas_analyzer_rs::commands;
use url::Url;

enum Commands {
    Block {
        /// The block to estimate gas against
        block: BlockId,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let out_path = env::var("OUT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut default_path = PathBuf::new();
            default_path.push(".");
            default_path.push("out");
            default_path
        });
    let fork_url = env::var("FORK_URL").expect("FORK_URL must be set");
    // let config = Config {
    //     out_path,
    //     fork_url: Url::parse(&fork_url).expect("FORK_URL must be a valid URL"),
    // };

    let cli = Cli::parse();

    match cli.command {
        Commands::Block { block } => {
            commands::block::run(block).await
        },
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
            let identifier = BlockId::from_str(input.as_ref()).expect("failed to parse block identifier");
            let all_receipts = provider.get_block_receipts(identifier).await?.expect("couldn't fetch block receipts");
             let block_number = all_receipts[0].block_number.expect("couldn't retrieve block number");
            let gk = GasKillerDefault::new(rpc_url.clone(), Some(block_number))
                .await
                .expect("unable to initialize GasKiller");
            
            println!("generating gaskiller reports...");
            let reports = gas_estimate_block(provider, all_receipts, gk).await?;
            println!("fetched reports");
            let output_file = std::env::var("OUTPUT_FILE")
        .expect("OUTPUT_FILE must be set");
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
            let receipt = provider.get_transaction_receipt(bytes.into()).await?.expect("couldn't fetch tx receipt for tx {hash}");
            let block_number = receipt.block_number.expect("couldn't retrieve block number");
             let gk = GasKillerDefault::new(rpc_url.clone(), Some(block_number))
                .await
                .expect("unable to initialize GasKiller");
            
           
            let report = gas_estimate_tx(provider, bytes.into(), &gk).await?;
              let output_file = std::env::var("OUTPUT_FILE")
                .expect("OUTPUT_FILE must be set");
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
              let gk = GasKillerDefault::new(rpc_url.clone(), None)
                .await
                .expect("unable to initialize GasKiller");
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
