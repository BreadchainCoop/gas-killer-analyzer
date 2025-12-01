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
    /// This is a complex test with multiple state updates at different depths:
    /// - 4 SSTORE operations (some inside DELEGATECALL context)
    /// - 1 CALL operation
    /// - 2 DELEGATECALL operations (which should be skipped, not captured as state updates)
    #[tokio::test]
    async fn test_compare_delegatecall() -> Result<()> {
        use crate::sol_types::IStateUpdateTypes;
        use alloy::primitives::b256;

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

        // Verify we got exactly 4 state updates (3 SSTOREs + 1 CALL, filtered by depth)
        assert_eq!(legacy_updates.len(), 4, "Expected 4 state updates");
        assert_eq!(new_updates.len(), 4, "Expected 4 state updates");

        // Verify the types are correct: Store, Call, Store, Store
        assert!(matches!(legacy_updates[0], StateUpdate::Store(_)));
        assert!(matches!(legacy_updates[1], StateUpdate::Call(_)));
        assert!(matches!(legacy_updates[2], StateUpdate::Store(_)));
        assert!(matches!(legacy_updates[3], StateUpdate::Store(_)));

        // Verify specific values for the first SSTORE
        if let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &legacy_updates[0] {
            assert_eq!(
                slot,
                &b256!("0x0000000000000000000000000000000000000000000000000000000000000003")
            );
            assert_eq!(
                value,
                &b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
            );
        }

        // Verify the CALL target
        if let StateUpdate::Call(IStateUpdateTypes::Call { target, .. }) = &legacy_updates[1] {
            assert_eq!(target, &DELEGATE_CONTRACT_A_ADDRESS);
        }

        println!(
            "SUCCESS: DELEGATECALL - both implementations produced {} identical state updates (3 Stores + 1 Call)",
            legacy_updates.len()
        );

        Ok(())
    }

    /// Test comparing legacy vs new implementation for CALL external transaction.
    #[tokio::test]
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

    /// Test comparing legacy vs new implementation for array iteration transaction.
    /// This is a more complex test case with multiple SSTORE operations.
    #[tokio::test]
    async fn test_compare_array_iteration() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_ARRAY_ITERATION_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;

        // Run legacy implementation
        let (legacy_updates, legacy_skipped) = compute_state_updates_legacy(trace.clone())?;

        // Run new implementation
        let (new_updates, new_skipped) = compute_state_updates(trace)?;

        // Compare results
        compare_state_updates(&legacy_updates, &new_updates)?;
        assert_eq!(legacy_skipped, new_skipped, "Skipped opcodes mismatch");

        println!(
            "SUCCESS: Array iteration - both implementations produced {} identical state updates",
            legacy_updates.len()
        );

        Ok(())
    }
}
