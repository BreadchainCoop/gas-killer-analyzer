pub mod encoder;
pub mod memory;
pub mod parser;
pub mod provider;
pub mod types;

use crate::parser::StateUpdateParser;
use crate::provider::TxProvider;
use crate::types::{StateUpdate, StateUpdateReport};
use alloy_primitives::FixedBytes;
use alloy_rpc_types::TransactionTrait;
use anyhow::{Result, anyhow};
use tracing::{info, warn};

pub struct TxStateExtractor {
    provider: TxProvider,
}

impl TxStateExtractor {
    pub fn new(rpc_url: &str) -> Result<Self> {
        let provider = TxProvider::new(rpc_url)?;
        Ok(Self { provider })
    }
    
    pub async fn extract_state_updates(&self, tx_hash: FixedBytes<32>) -> Result<Vec<StateUpdate>> {
        let receipt = self.provider.get_transaction_receipt(tx_hash).await?;
        
        if !receipt.status() {
            return Err(anyhow!("Transaction failed: {:?}", tx_hash));
        }
        
        let trace = self.provider.debug_trace_transaction(tx_hash).await?;
        
        let mut parser = StateUpdateParser::new();
        let (updates, skipped) = parser.parse_trace(trace)?;
        
        if !skipped.is_empty() {
            warn!("Skipped opcodes: {:?}", skipped);
        }
        
        info!("Extracted {} state updates from transaction {:?}", updates.len(), tx_hash);
        
        Ok(updates)
    }
    
    pub async fn extract_with_metadata(&self, tx_hash: FixedBytes<32>) -> Result<StateUpdateReport> {
        let receipt = self.provider.get_transaction_receipt(tx_hash).await?;
        let tx = self.provider.get_transaction(tx_hash).await?;
        
        if !receipt.status() {
            return Err(anyhow!("Transaction failed: {:?}", tx_hash));
        }
        
        let trace = self.provider.debug_trace_transaction(tx_hash).await?;
        
        let mut parser = StateUpdateParser::new();
        let (updates, skipped_opcodes) = parser.parse_trace(trace)?;
        
        Ok(StateUpdateReport {
            tx_hash,
            block_number: receipt.block_number.unwrap_or(0),
            from: tx.from,
            to: tx.inner.to(),
            value: tx.inner.value(),
            gas_used: receipt.gas_used,
            status: receipt.status(),
            state_updates: updates,
            skipped_opcodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_extractor_creation() {
        let extractor = TxStateExtractor::new("https://eth.llamarpc.com");
        assert!(extractor.is_ok());
    }
}