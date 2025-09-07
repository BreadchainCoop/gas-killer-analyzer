mod commands;

use alloy_eips::eip1898::BlockId;
use anyhow::Result;
use clap::Parser;
use clap_derive::{Parser, Subcommand};
use std::env;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use crate::commands::block;

pub struct Config {
    pub out_path: PathBuf,
    pub log_path: PathBuf,
    pub fork_url: Url,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Block {
        /// The block to estimate gas against
        block: BlockId,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "gas_analyzer_cli=info,gas_analyzer_rs=info".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let log_path = env::var("LOG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./gas-analyzer.log"));

    let out_path = env::var("OUT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut default_path = PathBuf::new();
            default_path.push(".");
            default_path.push("out");
            default_path
        });
    let fork_url = env::var("FORK_URL").expect("FORK_URL must be set");
    let config = Config {
        out_path,
        log_path,
        fork_url: Url::parse(&fork_url).expect("FORK_URL must be a valid URL"),
    };

    let cli = Cli::parse();

    match cli.command {
        Commands::Block { block } => block::run(block, config).await,
    }
}
