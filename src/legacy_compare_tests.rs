//! Legacy implementation comparison tests.
//!
//! This module tests that the new opcode-tracer based implementation produces
//! identical results to the legacy implementation for all test cases.
//!
//! The legacy implementation is in lib.rs with `_legacy` suffix functions.

use crate::sol_types::StateUpdate;
use anyhow::{Result, bail};

/// Compare two state update vectors for equality.
fn compare_state_updates(legacy: &[StateUpdate], new: &[StateUpdate]) -> Result<()> {
    if legacy.len() != new.len() {
        bail!(
            "Length mismatch: legacy has {} updates, new has {}",
            legacy.len(),
            new.len()
        );
    }

    for (i, (l, n)) in legacy.iter().zip(new.iter()).enumerate() {
        match (l, n) {
            (StateUpdate::Store(lg), StateUpdate::Store(nw)) => {
                if lg.slot != nw.slot {
                    bail!(
                        "Store slot mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.slot,
                        nw.slot
                    );
                }
                if lg.value != nw.value {
                    bail!(
                        "Store value mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.value,
                        nw.value
                    );
                }
            }
            (StateUpdate::Call(lg), StateUpdate::Call(nw)) => {
                if lg.target != nw.target {
                    bail!(
                        "Call target mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.target,
                        nw.target
                    );
                }
                if lg.value != nw.value {
                    bail!(
                        "Call value mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.value,
                        nw.value
                    );
                }
                if lg.callargs != nw.callargs {
                    bail!(
                        "Call args mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.callargs,
                        nw.callargs
                    );
                }
            }
            (StateUpdate::Log0(lg), StateUpdate::Log0(nw)) => {
                if lg.data != nw.data {
                    bail!(
                        "Log0 data mismatch at index {}: {:?} vs {:?}",
                        i,
                        lg.data,
                        nw.data
                    );
                }
            }
            (StateUpdate::Log1(lg), StateUpdate::Log1(nw)) => {
                if lg.data != nw.data {
                    bail!("Log1 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log1 topic1 mismatch at index {}", i);
                }
            }
            (StateUpdate::Log2(lg), StateUpdate::Log2(nw)) => {
                if lg.data != nw.data {
                    bail!("Log2 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log2 topic1 mismatch at index {}", i);
                }
                if lg.topic2 != nw.topic2 {
                    bail!("Log2 topic2 mismatch at index {}", i);
                }
            }
            (StateUpdate::Log3(lg), StateUpdate::Log3(nw)) => {
                if lg.data != nw.data {
                    bail!("Log3 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log3 topic1 mismatch at index {}", i);
                }
                if lg.topic2 != nw.topic2 {
                    bail!("Log3 topic2 mismatch at index {}", i);
                }
                if lg.topic3 != nw.topic3 {
                    bail!("Log3 topic3 mismatch at index {}", i);
                }
            }
            (StateUpdate::Log4(lg), StateUpdate::Log4(nw)) => {
                if lg.data != nw.data {
                    bail!("Log4 data mismatch at index {}", i);
                }
                if lg.topic1 != nw.topic1 {
                    bail!("Log4 topic1 mismatch at index {}", i);
                }
                if lg.topic2 != nw.topic2 {
                    bail!("Log4 topic2 mismatch at index {}", i);
                }
                if lg.topic3 != nw.topic3 {
                    bail!("Log4 topic3 mismatch at index {}", i);
                }
                if lg.topic4 != nw.topic4 {
                    bail!("Log4 topic4 mismatch at index {}", i);
                }
            }
            _ => {
                bail!(
                    "State update type mismatch at index {}: {:?} vs {:?}",
                    i,
                    std::mem::discriminant(l),
                    std::mem::discriminant(n)
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::sol_types::SimpleStorage;
    use crate::{
        compute_state_updates, compute_state_updates_legacy, get_trace_from_call, get_tx_trace,
    };
    use alloy::primitives::U256;
    use alloy::providers::ProviderBuilder;
    use url::Url;

    /// Test comparing legacy vs new implementation for SimpleStorage SET transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_simple_storage_set() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_SET_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: SimpleStorage SET - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for SimpleStorage DEPOSIT transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_simple_storage_deposit() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_DEPOSIT_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: SimpleStorage DEPOSIT - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for DELEGATECALL transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_delegatecall() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = DELEGATECALL_CONTRACT_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: DELEGATECALL - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for CALL external transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_call_external() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_CALL_EXTERNAL_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: CALL external - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for simulated call.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_simulate_call() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;

        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let simple_storage =
            SimpleStorage::SimpleStorageInstance::new(SIMPLE_STORAGE_ADDRESS, &provider);
        let tx_request = simple_storage.set(U256::from(1)).into_transaction_request();

        let trace = get_trace_from_call(rpc_url, tx_request).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: Simulate call - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for AccessControl transaction.
    #[tokio::test]
    #[ignore = "requires RPC_URL with pre-deployed test contracts"]
    async fn test_compare_access_control() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = ACCESS_CONTROL_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: AccessControl - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }
}
