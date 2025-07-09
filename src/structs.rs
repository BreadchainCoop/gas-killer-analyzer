use alloy::primitives::FixedBytes;
use alloy_rpc_types::TransactionReceipt;
use serde_derive::Serialize;

pub(crate) type Opcode = String;

#[derive(Serialize)]
pub struct GasKillerReport {
    pub hash: FixedBytes<32>,
    pub gas_used: u128,
    pub gas_cost: u128,
    pub gaskiller_gas_estimate: u128,
    pub gaskiller_estimated_gas_cost: u128,
    pub percent_savings: f64,
    pub function_selector: FixedBytes<4>,
    pub skipped_opcodes: String,
    pub error_log: Option<String>,
}

impl GasKillerReport {
    pub fn report_error(receipt: &TransactionReceipt, e: &anyhow::Error) -> Self {
        GasKillerReport {
            hash: receipt.transaction_hash,
            gas_used: receipt.gas_used.into(),
            gas_cost: 0,
            gaskiller_gas_estimate: 0,
            gaskiller_estimated_gas_cost: 0,
            percent_savings: 0.0,
            function_selector: FixedBytes::default(),
            skipped_opcodes: "".to_string(),
            error_log: Some(format!("{:?}", e)),
        }
    }
    pub fn from(receipt: &TransactionReceipt, details: ReportDetails) -> Self {
        GasKillerReport {
            hash: receipt.transaction_hash,
            gas_used: receipt.gas_used.into(),
            gas_cost: details.gas_cost,
            gaskiller_gas_estimate: details.gaskiller_gas_estimate,
            gaskiller_estimated_gas_cost: details.gaskiller_estimated_gas_cost,
            percent_savings: details.percent_savings,
            function_selector: details.function_selector,
            skipped_opcodes: details.skipped_opcodes,
            error_log: None,
        }
    }
}

pub struct ReportDetails {
    pub gas_cost: u128,
    pub gaskiller_gas_estimate: u128,
    pub gaskiller_estimated_gas_cost: u128,
    pub percent_savings: f64,
    pub function_selector: FixedBytes<4>,
    pub skipped_opcodes: String,
}
