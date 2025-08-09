use alloy::providers::{Provider, ProviderBuilder};
use alloy_primitives::FixedBytes;
use alloy_provider::ext::DebugApi;
use alloy_rpc_types::trace::geth::{DefaultFrame, GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace};
use alloy_rpc_types::{TransactionReceipt, Transaction};
use anyhow::{Result, anyhow};

#[derive(Clone)]
pub struct TxProvider {
    provider: alloy::providers::RootProvider<alloy::transports::http::Http<alloy::transports::http::Client>>,
}

impl TxProvider {
    pub fn new(rpc_url: &str) -> Result<Self> {
        let url = rpc_url.parse().map_err(|e| anyhow!("Invalid RPC URL: {}", e))?;
        let provider = ProviderBuilder::new()
            .on_http(url);
        
        Ok(Self {
            provider,
        })
    }
    
    pub async fn get_transaction_receipt(&self, tx_hash: FixedBytes<32>) -> Result<TransactionReceipt> {
        self.provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or_else(|| anyhow!("Transaction receipt not found for hash: {:?}", tx_hash))
    }
    
    pub async fn get_transaction(&self, tx_hash: FixedBytes<32>) -> Result<Transaction> {
        self.provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| anyhow!("Transaction not found for hash: {:?}", tx_hash))
    }
    
    pub async fn debug_trace_transaction(&self, tx_hash: FixedBytes<32>) -> Result<DefaultFrame> {
        let options = GethDebugTracingOptions {
            config: GethDefaultTracingOptions {
                enable_memory: Some(true),
                disable_storage: Some(false),
                disable_stack: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };
        
        let trace = self.provider
            .debug_trace_transaction(tx_hash, options)
            .await?;
        
        match trace {
            GethTrace::Default(frame) => Ok(frame),
            _ => Err(anyhow!("Unexpected trace format"))
        }
    }
    
    pub async fn get_block_number(&self) -> Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_provider_creation() {
        let provider = TxProvider::new("https://eth.llamarpc.com");
        assert!(provider.is_ok());
    }
}