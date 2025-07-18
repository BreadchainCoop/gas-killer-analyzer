use alloy::primitives::FixedBytes;
use alloy_rpc_types::TransactionReceipt;
use serde_derive::Serialize;

pub(crate) type Opcode = String;

#[derive(Serialize)]
pub struct GasKillerReport {
    pub tx_hash: FixedBytes<32>,
    pub block_hash: FixedBytes<32>,
    pub gas_used: u64,
    pub gas_cost: u128,
    pub approx_gas_unit_price: f64,
    pub gaskiller_gas_estimate: u64,
    pub gaskiller_estimated_gas_cost: f64,
    pub gas_savings: u64,
    pub percent_savings: f64,
    pub function_selector: FixedBytes<4>,
    pub skipped_opcodes: String,
    pub error_log: Option<String>,
}

impl GasKillerReport {
    pub fn report_error(receipt: &TransactionReceipt, e: &anyhow::Error) -> Self {
        GasKillerReport {
            tx_hash: receipt.transaction_hash,
            block_hash: receipt.block_hash.unwrap_or_else(|| {
                panic!(
                    "couldn't retrieve block hash for tx {}",
                    receipt.transaction_hash
                )
            }),
            gas_used: receipt.gas_used,
            gas_cost: receipt.effective_gas_price,
            approx_gas_unit_price: receipt.effective_gas_price as f64 / receipt.gas_used as f64, 
            gaskiller_gas_estimate: 0,
            gaskiller_estimated_gas_cost: 0.0,
            gas_savings: 0,
            percent_savings: 0.0,
            function_selector: FixedBytes::default(),
            skipped_opcodes: "".to_string(),
            error_log: Some(format!("{e:?}")),
        }
    }
    pub fn from(receipt: &TransactionReceipt, details: ReportDetails) -> Self {
        GasKillerReport {
            tx_hash: receipt.transaction_hash,
            block_hash: receipt.block_hash.unwrap_or_else(|| {
                panic!(
                    "couldn't retrieve block hash for tx {}",
                    receipt.transaction_hash
                )
            }),
            gas_used: receipt.gas_used,
            gas_cost: receipt.effective_gas_price,
            approx_gas_unit_price: details.approx_gas_price_per_unit,
            gaskiller_gas_estimate: details.gaskiller_gas_estimate,
            gaskiller_estimated_gas_cost: details.gaskiller_estimated_gas_cost,
            gas_savings: details.gas_savings,
            percent_savings: details.percent_savings,
            function_selector: details.function_selector,
            skipped_opcodes: details.skipped_opcodes,
            error_log: None,
        }
    }
}

pub struct ReportDetails {
    pub approx_gas_price_per_unit : f64,
        pub gaskiller_gas_estimate: u64,
    pub gaskiller_estimated_gas_cost: f64,
    pub gas_savings: u64,
    pub percent_savings: f64,
    pub function_selector: FixedBytes<4>,
    pub skipped_opcodes: String,
}
