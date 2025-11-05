use crate::{compute_state_updates, get_tx_trace, sol_types::StateUpdate};
use alloy::primitives::FixedBytes;
use alloy::providers::{Provider, ProviderBuilder, ext::DebugApi};
use alloy_rpc_types::TransactionTrait;
use anyhow::{Result, anyhow};

/// Minimal transaction state extractor that reuses existing gas-analyzer-rs functionality
pub struct TxStateExtractor<P: Provider + DebugApi<alloy::network::Ethereum>> {
    provider: P,
}

impl<P: Provider + DebugApi<alloy::network::Ethereum>> TxStateExtractor<P> {
    /// Create a new extractor with the given provider
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Extract state updates from a transaction hash
    pub async fn extract_state_updates(&self, tx_hash: FixedBytes<32>) -> Result<Vec<StateUpdate>> {
        // Use existing get_tx_trace function
        let trace = get_tx_trace(&self.provider, tx_hash).await?;

        // Use existing compute_state_updates function
        let (state_updates, _skipped) = compute_state_updates(trace).await?;

        Ok(state_updates)
    }

    /// Extract state updates with transaction metadata
    pub async fn extract_with_metadata(
        &self,
        tx_hash: FixedBytes<32>,
    ) -> Result<StateUpdateReport> {
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or_else(|| anyhow!("Transaction not found"))?;

        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .ok_or_else(|| anyhow!("Transaction not found"))?;

        if !receipt.status() {
            return Err(anyhow!("Transaction failed"));
        }

        let trace = get_tx_trace(&self.provider, tx_hash).await?;
        let (state_updates, _skipped) = compute_state_updates(trace).await?;

        Ok(StateUpdateReport {
            tx_hash,
            block_number: receipt.block_number.unwrap_or(0),
            from: receipt.from,
            to: tx.inner.to(),
            value: tx.inner.value(),
            gas_used: receipt.gas_used as u128,
            status: receipt.status(),
            state_updates,
        })
    }
}

/// Convenience function to create an extractor from RPC URL
pub async fn from_rpc_url(
    rpc_url: &str,
) -> Result<TxStateExtractor<impl Provider + DebugApi<alloy::network::Ethereum>>> {
    let provider = ProviderBuilder::new().connect(rpc_url).await?;
    Ok(TxStateExtractor::new(provider))
}

/// Report containing state updates and transaction metadata
#[derive(Debug)]
pub struct StateUpdateReport {
    pub tx_hash: FixedBytes<32>,
    pub block_number: u64,
    pub from: alloy::primitives::Address,
    pub to: Option<alloy::primitives::Address>,
    pub value: alloy::primitives::U256,
    pub gas_used: u128,
    pub status: bool,
    pub state_updates: Vec<StateUpdate>,
}
