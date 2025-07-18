#[allow(dead_code)]
mod constants;
pub mod gk;
mod sol_types;
pub mod structs;

use std::{collections::HashSet, str::FromStr};
use structs::{GasKillerReport, Opcode, ReportDetails};

use alloy::{
    primitives::{Address, Bytes, FixedBytes, TxKind},
    providers::{Provider, ProviderBuilder, ext::DebugApi},
    rpc::types::{
        TransactionReceipt,
        eth::TransactionRequest,
        trace::geth::{
            DefaultFrame, GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, StructLog,
        },
    },
    sol_types::SolValue,
};
use alloy_eips::eip1898::BlockId;
use alloy_rpc_types::TransactionTrait;
use anyhow::{Result, anyhow, bail};
use gk::GasKillerDefault;
use sol_types::{IStateUpdateTypes, StateUpdate, StateUpdateType, StateUpdates};
use url::Url;

const TURETZKY_UPPER_GAS_LIMIT: u64 = 200000u64;

fn copy_memory(memory: &[u8], offset: usize, length: usize) -> Vec<u8> {
    if memory.len() >= offset + length {
        memory[offset..offset + length].to_vec()
    } else {
        let mut memory = memory.to_vec();
        memory.resize(offset + length, 0);
        memory[offset..offset + length].to_vec()
    }
}

fn parse_trace_memory(memory: Vec<String>) -> Vec<u8> {
    memory
        .join("")
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|c| c.iter().collect::<String>())
        .map(|s| u8::from_str_radix(&s, 16).expect("invalid hex"))
        .collect::<Vec<u8>>()
}

fn append_to_state_updates(
    state_updates: &mut Vec<StateUpdate>,
    struct_log: StructLog,
) -> Result<Option<Opcode>> {
    let mut stack = struct_log.stack.expect("stack is empty");
    stack.reverse();
    let memory = match struct_log.memory {
        Some(memory) => parse_trace_memory(memory),
        None => match struct_log.op.as_str() {
            "CALL" | "LOG0" | "LOG1" | "LOG2" | "LOG3" | "LOG4" if struct_log.depth == 1 => {
                bail!("There is no memory for {:?} in depth 1", struct_log.op)
            }
            _ => return Ok(None),
        },
    };
    match struct_log.op.as_str() {
        "CREATE" | "CREATE2" | "SELFDESTRUCT" => {
            return Ok(Some(struct_log.op));
        }
        "DELEGATECALL" | "CALLCODE" => {
            bail!(
                "Calling opcode {:?}, this shouldn't even happen!",
                struct_log.op
            );
        }
        "SSTORE" => state_updates.push(StateUpdate::Store(IStateUpdateTypes::Store {
            slot: stack[0].into(),
            value: stack[1].into(),
        })),
        "CALL" => {
            let args_offset: usize = stack[3].try_into().expect("invalid args offset");
            let args_length: usize = stack[4].try_into().expect("invalid args length");
            let args = copy_memory(&memory, args_offset, args_length);
            state_updates.push(StateUpdate::Call(IStateUpdateTypes::Call {
                target: Address::from_word(stack[1].into()),
                value: stack[2],
                callargs: args.into(),
            }));
        }
        "LOG0" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log0(IStateUpdateTypes::Log0 {
                data: data.into(),
            }));
        }
        "LOG1" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log1(IStateUpdateTypes::Log1 {
                data: data.into(),
                topic1: stack[2].into(),
            }));
        }
        "LOG2" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log2(IStateUpdateTypes::Log2 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
            }));
        }
        "LOG3" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log3(IStateUpdateTypes::Log3 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
                topic3: stack[4].into(),
            }));
        }
        "LOG4" => {
            let data_offset: usize = stack[0].try_into().expect("invalid data offset");
            let data_length: usize = stack[1].try_into().expect("invalid data length");
            let data = copy_memory(&memory, data_offset, data_length);
            state_updates.push(StateUpdate::Log4(IStateUpdateTypes::Log4 {
                data: data.into(),
                topic1: stack[2].into(),
                topic2: stack[3].into(),
                topic3: stack[4].into(),
                topic4: stack[5].into(),
            }));
        }
        _ => {}
    }
    Ok(None)
}

async fn compute_state_updates(trace: DefaultFrame) -> Result<(Vec<StateUpdate>, HashSet<Opcode>)> {
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    // depth for which we care about state updates happening in
    let mut target_depth = 1;
    let mut skipped_opcodes = HashSet::new();
    for struct_log in trace.struct_logs {
        // Whenever stepping up (leaving a CALL/CALLCODE/DELEGATECALL) reset the target depth
        if struct_log.depth < target_depth {
            target_depth = struct_log.depth;
        } else if struct_log.depth == target_depth {
            // If we're going to step into a new execution context, increase the target depth
            // else, try to add the state update
            if struct_log.op.as_str() == "DELEGATECALL" || struct_log.op.as_str() == "CALLCODE" {
                target_depth = struct_log.depth + 1;
            } else if let Some(opcode) = append_to_state_updates(&mut state_updates, struct_log)? {
                skipped_opcodes.insert(opcode);
            }
        }
    }
    Ok((state_updates, skipped_opcodes))
}

async fn get_tx_trace<P: Provider>(provider: &P, tx_hash: FixedBytes<32>) -> Result<DefaultFrame> {
    let tx_receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("could not get receipt for tx {}", tx_hash))?;

    if !tx_receipt.status() {
        bail!("transaction failed");
    }

    let options = GethDebugTracingOptions {
        config: GethDefaultTracingOptions {
            enable_memory: Some(true),
            ..Default::default()
        },
        ..Default::default()
    };

    let GethTrace::Default(trace) = provider.debug_trace_transaction(tx_hash, options).await?
    else {
        return Err(anyhow::anyhow!("Expected default trace"));
    };
    Ok(trace)
}

pub async fn get_trace_from_call(
    rpc_url: Url,
    tx_request: TransactionRequest,
) -> Result<DefaultFrame> {
    let provider = ProviderBuilder::new().connect_anvil_with_wallet_and_config(|config| {
        config
            .fork(rpc_url)
            .arg("--steps-tracing")
            .arg("--auto-impersonate")
    })?;
    let tx_receipt = provider
        .send_transaction(tx_request)
        .await?
        .get_receipt()
        .await?;
    if !tx_receipt.status() {
        bail!("transaction failed");
    }
    let tx_hash = tx_receipt.transaction_hash;
    get_tx_trace(&provider, tx_hash).await
}

fn encode_state_updates_to_sol(
    state_updates: &[StateUpdate],
) -> (Vec<StateUpdateType>, Vec<Bytes>) {
    let state_update_types: Vec<StateUpdateType> = state_updates
        .iter()
        .map(|state_update| match state_update {
            StateUpdate::Store(_) => StateUpdateType::STORE,
            StateUpdate::Call(_) => StateUpdateType::CALL,
            StateUpdate::Log0(_) => StateUpdateType::LOG0,
            StateUpdate::Log1(_) => StateUpdateType::LOG1,
            StateUpdate::Log2(_) => StateUpdateType::LOG2,
            StateUpdate::Log3(_) => StateUpdateType::LOG3,
            StateUpdate::Log4(_) => StateUpdateType::LOG4,
        })
        .collect::<Vec<_>>();
    // This is ugly but I can't bother doing it with traits
    let datas: Vec<Bytes> = state_updates
        .iter()
        .map(|state_update| {
            Bytes::copy_from_slice(&match state_update {
                StateUpdate::Store(x) => x.abi_encode_sequence(),
                StateUpdate::Call(x) => x.abi_encode_sequence(),
                StateUpdate::Log0(x) => x.abi_encode_sequence(),
                StateUpdate::Log1(x) => x.abi_encode_sequence(),
                StateUpdate::Log2(x) => x.abi_encode_sequence(),
                StateUpdate::Log3(x) => x.abi_encode_sequence(),
                StateUpdate::Log4(x) => x.abi_encode_sequence(),
            })
        })
        .collect::<Vec<_>>();
    (state_update_types, datas)
}

fn encode_state_updates_to_abi(state_updates: &[StateUpdate]) -> Bytes {
    let (state_update_types, datas) = encode_state_updates_to_sol(state_updates);
    let state_updates = StateUpdates {
        types: state_update_types
            .iter()
            .map(|x| *x as u8)
            .collect::<Vec<_>>(),
        data: datas,
    };
    let encoded = StateUpdates::abi_encode(&state_updates);
    Bytes::copy_from_slice(&encoded)
}

pub async fn invokes_smart_contract(
    provider: impl Provider,
    receipt: &TransactionReceipt,
) -> Result<bool> {
    let to_address = receipt.to;
    match to_address {
        None => Ok(false),
        Some(address) => {
            let code = provider.get_code_at(address).await?;
            if code == Bytes::from_str("0x")? {
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}


// computes state updates and estimates for each transaction one by one, nicer for CLI
pub async fn gas_estimate_block(
    provider: impl Provider,
    block_id: BlockId,
    gk: GasKillerDefault,
) -> Result<(Vec<GasKillerReport>, FixedBytes<32>)> {
    let all_receipts = provider
        .get_block_receipts(block_id)
        .await?
        .expect("block receipts retrieval failed");
    let block_hash = all_receipts[0]
        .block_hash
        .expect("couldn't find block hash in receipt");
    
    let receipts: Vec<_> = all_receipts.into_iter().filter(|x| x.gas_used > TURETZKY_UPPER_GAS_LIMIT).collect();
    
    println!("got {} receipts for block {}", receipts.len(), block_hash);
    let mut reports = Vec::new();
    for receipt in receipts {
        println!("processing {}", &receipt.transaction_hash);
        reports.push(get_report(&provider,receipt.transaction_hash, &receipt, &gk)
                     .await
                     .unwrap_or_else(|e| GasKillerReport::report_error(&receipt, &e)));
            println!("done");
    }
    Ok((reports, block_hash))
}

pub async fn gas_estimate_tx(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
    gk: &GasKillerDefault,
) -> Result<GasKillerReport> {
    
   let receipt = provider.get_transaction_receipt(tx_hash).await?.ok_or_else(|| anyhow!("could not get receipt for tx 0x{}", tx_hash))?;
    let smart_contract_tx = invokes_smart_contract(&provider, &receipt).await?;
    if (receipt.gas_used <= TURETZKY_UPPER_GAS_LIMIT) || !smart_contract_tx {
        bail! ("Skipped: either gas used is less than or equal to TUGL or no smart contract calls are made")
    }

    get_report(&provider, tx_hash, &receipt, gk).await
}


pub async fn get_report (provider: impl Provider, tx_hash: FixedBytes<32>, receipt: &TransactionReceipt, gk: &GasKillerDefault) -> Result<GasKillerReport>
{
    let details = gaskiller_reporter(&provider, tx_hash, gk, receipt).await;
    if let Err(e) = details {
        return Ok(GasKillerReport::report_error(receipt, &e));
    }
   
    Ok(GasKillerReport::from(receipt, details.unwrap()))
}

pub async fn gaskiller_reporter(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
    gk: &GasKillerDefault,
    receipt: &TransactionReceipt,
) -> Result<ReportDetails> {
    let transaction = provider
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("could not get receipt for tx 0x{}", tx_hash))?;
    let trace = get_tx_trace(&provider, tx_hash).await?;
    let (state_updates, opcodes) = compute_state_updates(trace).await?;
    let skipped_opcodes = opcodes.into_iter().collect::<Vec<_>>().join(", ");
    let gaskiller_gas_estimate = gk
        .estimate_state_changes_gas(
            receipt
                .to
                .ok_or_else(|| anyhow!("receipt does not have to address"))?,
            &state_updates,
        )
        .await?;
    let gas_used = receipt.gas_used;
    let approx_gas_price_per_unit: f64 = receipt.effective_gas_price as f64 / gas_used as f64;
    let gaskiller_estimated_gas_cost = approx_gas_price_per_unit * gaskiller_gas_estimate as f64;
    let gas_savings = gas_used.saturating_sub(gaskiller_gas_estimate);
    let function_selector = *transaction
        .function_selector()
        .ok_or_else(|| anyhow!("could not get function selector for tx 0x{}", tx_hash))?;
    Ok(ReportDetails {
        approx_gas_price_per_unit,
        gaskiller_gas_estimate,
        gaskiller_estimated_gas_cost,
        gas_savings,
        percent_savings: ( gas_savings*100)
            as f64
            / gas_used as f64,
        function_selector,
        skipped_opcodes,
    })
}

pub async fn call_to_encoded_state_updates_with_gas_estimate(
    url: Url,
    tx_request: TransactionRequest,
    gk: GasKillerDefault,
) -> Result<(Bytes, u64, HashSet<Opcode>)> {
    let contract_address = tx_request
        .to
        .and_then(|x| match x {
            TxKind::Call(address) => Some(address),
            TxKind::Create => None,
        })
        .ok_or_else(|| anyhow!("receipt does not have to address"))?;
    let trace = get_trace_from_call(url, tx_request).await?;
    let (state_updates, skipped_opcodes) = compute_state_updates(trace).await?;
    let gas_estimate = gk
        .estimate_state_changes_gas(contract_address, &state_updates)
        .await?;
    Ok((
        encode_state_updates_to_abi(&state_updates),
        gas_estimate,
        skipped_opcodes,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use alloy::{
        hex,
        primitives::{U256, address, b256, bytes},
    };
    use constants::*;
    use csv::Writer;
    use sol_types::SimpleStorage;

    #[tokio::test]
    async fn test_csv_writer() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;

        let hash = "0x0df13f90b94773887709ce26216928c952e2d7f6d5af44198504ac6899fc5165";
        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
        let bytes: [u8; 32] =
            hex::const_decode_to_array(hash.as_bytes()).expect("failed to decode transaction hash");
        let gk = GasKillerDefault::new(rpc_url).await?;
        let report = gas_estimate_tx(provider, bytes.into(), gk).await?;

        let _ = File::create("test.csv")?;
        let mut writer = Writer::from_path("test.csv")?;

        writer.serialize(report)?;
        writer.flush()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_estimate_state_changes_gas_set() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let tx_hash = SIMPLE_STORAGE_SET_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new(rpc_url).await?;
        let gas_estimate = gk
            .estimate_state_changes_gas(SIMPLE_STORAGE_ADDRESS, &state_updates)
            .await?;
        assert_eq!(gas_estimate, 32549);
        Ok(())
    }

    #[tokio::test]
    async fn test_estimate_state_changes_gas_access_control() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let tx_hash = ACCESS_CONTROL_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new(rpc_url).await?;
        let gas_estimate = gk
            .estimate_state_changes_gas(ACCESS_CONTROL_MAIN_ADDRESS, &state_updates)
            .await?;
        assert_eq!(gas_estimate, 37185);
        Ok(())
    }

    #[tokio::test]
    async fn test_estimate_state_changes_gas_access_control_failure() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let tx_hash = ACCESS_CONTROL_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new(rpc_url).await?;
        let gas_estimate = gk
            .estimate_state_changes_gas(FAKE_ADDRESS, &state_updates)
            .await;
        // Check that the error contains a certain substring
        let error_msg = match gas_estimate {
            Ok(_) => bail!("Expected error, got Ok"),
            Err(e) => e.to_string(),
        };

        // cast sig "RevertingContext(address,bytes)"
        assert!(error_msg.contains("custom error 0xaa86ecee"));

        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_set() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_SET_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 2);
        assert!(matches!(state_updates[0], StateUpdate::Store(_)));
        let StateUpdate::Store(store) = &state_updates[0] else {
            bail!("Expected Store");
        };

        assert_eq!(
            store.slot,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            store.value,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );

        assert!(matches!(state_updates[1], StateUpdate::Log1(_)));
        let StateUpdate::Log1(log) = &state_updates[1] else {
            bail!("Expected Log1");
        };
        assert_eq!(
            log.data,
            bytes!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            log.topic1,
            b256!("0x9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d49")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_deposit() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_DEPOSIT_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 2);
        assert!(matches!(state_updates[0], StateUpdate::Store(_)));
        let StateUpdate::Store(store) = &state_updates[0] else {
            bail!("Expected Store");
        };

        assert_eq!(
            store.slot,
            b256!("0x440be2d9467c2219d5dbcccf352e669f171177c1a3ff408399184565c5a56cca")
        );
        assert_eq!(
            store.value,
            b256!("0x00000000000000000000000000000000000000000000000000005af3107a4000")
        );

        assert!(matches!(state_updates[1], StateUpdate::Log2(_)));
        let StateUpdate::Log2(log) = &state_updates[1] else {
            bail!("Expected Log2");
        };
        assert_eq!(
            log.data,
            bytes!("0x00000000000000000000000000000000000000000000000000005af3107a4000")
        );
        assert_eq!(
            log.topic1,
            b256!("0x8ad64a0ac7700dd8425ab0499f107cb6e2cd1581d803c5b8c1c79dcb8190b1af")
        );
        assert_eq!(
            log.topic2,
            b256!("0x000000000000000000000000cb7c611933f1697f6e56929f4eee39af8f5b313e")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_delegatecall() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = DELEGATECALL_CONTRACT_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 4);
        let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &state_updates[0] else {
            bail!("Expected Store, got {:?}", state_updates[0]);
        };
        assert_eq!(
            slot,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000003")
        );
        assert_eq!(
            value,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );

        let StateUpdate::Call(IStateUpdateTypes::Call {
            target,
            value,
            callargs,
        }) = &state_updates[1]
        else {
            bail!("Expected Call, got {:?}", state_updates[1]);
        };
        assert_eq!(target, &DELEGATE_CONTRACT_A_ADDRESS);
        assert_eq!(value, &U256::from(0));
        assert_eq!(callargs, &bytes!("0xaea01afc"));

        let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &state_updates[2] else {
            bail!("Expected Store, got {:?}", state_updates[2]);
        };
        assert_eq!(
            slot,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(
            value,
            &b256!("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000")
        ); // 1 ether (use cast to-dec)

        let StateUpdate::Store(IStateUpdateTypes::Store { slot, value }) = &state_updates[3] else {
            bail!("Expected Store, got {:?}", state_updates[3]);
        };
        assert_eq!(
            slot,
            &b256!("0x0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(
            value,
            &b256!("0x00000000000000000000000000000000000000000000000029a2241af62c0000")
        ); // 3 ether (use cast to-dec)

        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_updates_call_external() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let tx_hash = SIMPLE_STORAGE_CALL_EXTERNAL_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 1);
        assert!(matches!(state_updates[0], StateUpdate::Call(_)));
        let StateUpdate::Call(call) = &state_updates[0] else {
            bail!("Expected Call");
        };

        assert_eq!(
            call.target,
            address!("0x523a103bb468a26295d7dbcb37ad919b0afbf294")
        );
        assert_eq!(call.value, U256::from(0));
        assert_eq!(call.callargs, bytes!("0x3a32b549"));

        Ok(())
    }

    #[tokio::test]
    async fn test_compute_state_update_simulate_call() -> Result<()> {
        dotenv::dotenv().ok();

        let rpc_url: Url = std::env::var("TESTNET_RPC_URL")
            .expect("TESTNET_RPC_URL must be set")
            .parse()?;

        let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

        let simple_storage =
            SimpleStorage::SimpleStorageInstance::new(SIMPLE_STORAGE_ADDRESS, &provider);
        let tx_request = simple_storage.set(U256::from(1)).into_transaction_request();

        let trace = get_trace_from_call(rpc_url, tx_request).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        assert_eq!(state_updates.len(), 2);
        assert!(matches!(state_updates[0], StateUpdate::Store(_)));
        let StateUpdate::Store(store) = &state_updates[0] else {
            bail!("Expected Store");
        };

        assert_eq!(
            store.slot,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            store.value,
            b256!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );

        assert!(matches!(state_updates[1], StateUpdate::Log1(_)));
        let StateUpdate::Log1(log) = &state_updates[1] else {
            bail!("Expected Log1");
        };
        assert_eq!(
            log.data,
            bytes!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            log.topic1,
            b256!("0x9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d49")
        );
        Ok(())
    }
}
