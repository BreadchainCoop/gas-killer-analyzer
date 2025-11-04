#[allow(dead_code)]
mod constants;
pub mod gk;
pub mod sol_types;
pub mod structs;
pub mod tx_extractor;

use chrono::Utc;
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

use alloy_rpc_types::TransactionTrait;
use anyhow::{Result, anyhow, bail};
use gk::GasKillerDefault;
use sol_types::{IStateUpdateTypes, StateUpdate, StateUpdateType};
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

pub async fn compute_state_updates(
    trace: DefaultFrame,
) -> Result<(Vec<StateUpdate>, HashSet<Opcode>)> {
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

pub async fn get_tx_trace<P: Provider>(
    provider: &P,
    tx_hash: FixedBytes<32>,
) -> Result<DefaultFrame> {
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
    let provider = ProviderBuilder::new().on_anvil_with_wallet_and_config(|config| {
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

    println!(
        "[encode_state_updates_to_abi] TUPLE ENCODING: Encoding {} state updates as (StateUpdateType[], bytes[])",
        state_update_types.len()
    );

    // Encode as tuple (StateUpdateType[], bytes[])
    // StateUpdateType is an enum which encodes as uint8 in the array
    fn write_u256_word(buf: &mut Vec<u8>, value: usize) {
        let mut word = [0u8; 32];
        let bytes = (value as u128).to_be_bytes();
        word[32 - bytes.len()..].copy_from_slice(&bytes);
        buf.extend_from_slice(&word);
    }

    fn pad32_len(len: usize) -> usize {
        len.div_ceil(32) * 32
    }

    fn encode_bytes(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + pad32_len(value.len()));
        write_u256_word(&mut out, value.len());
        out.extend_from_slice(value);
        let padding = pad32_len(value.len()) - value.len();
        if padding > 0 {
            out.extend(std::iter::repeat_n(0u8, padding));
        }
        out
    }

    fn encode_bytes_array(values: &[Bytes]) -> Vec<u8> {
        let n = values.len();
        let encoded_elements: Vec<Vec<u8>> =
            values.iter().map(|b| encode_bytes(b.as_ref())).collect();

        let head_size = 32 * n;
        let mut out = Vec::new();
        write_u256_word(&mut out, n);

        let mut running_offset = head_size;
        for enc in &encoded_elements {
            write_u256_word(&mut out, running_offset);
            running_offset += enc.len();
        }

        for enc in encoded_elements {
            out.extend_from_slice(&enc);
        }

        out
    }

    // Encode StateUpdateType[] (enum array encoded as uint8[])
    let types_as_u8: Vec<u8> = state_update_types.iter().map(|x| *x as u8).collect();
    let types_payload = encode_bytes(&types_as_u8);

    // Encode bytes[]
    let datas_payload = encode_bytes_array(&datas);

    // Build tuple with two offsets
    let offset_types = 0x40usize;
    let offset_datas = offset_types + types_payload.len();

    let mut encoded: Vec<u8> = Vec::with_capacity(64 + types_payload.len() + datas_payload.len());
    write_u256_word(&mut encoded, offset_types);
    write_u256_word(&mut encoded, offset_datas);
    encoded.extend_from_slice(&types_payload);
    encoded.extend_from_slice(&datas_payload);

    // Log first 96 bytes for sanity check
    let preview = if encoded.len() >= 96 {
        format!(
            "0x{}",
            encoded[0..96]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    } else {
        format!(
            "0x{}",
            encoded
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    };
    println!("[encode_state_updates_to_abi] *** TUPLE (StateUpdateType[], bytes[]) ENCODING ***");
    println!("[encode_state_updates_to_abi] First 96 bytes (offsets + start of types): {}", preview);
    println!(
        "[encode_state_updates_to_abi] Total encoded length: {} bytes",
        encoded.len()
    );
    println!("[encode_state_updates_to_abi] Expected decode: (StateUpdateType[], bytes[])");

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
    all_receipts: Vec<TransactionReceipt>,
    gk: GasKillerDefault,
) -> Result<Vec<GasKillerReport>> {
    let block_number = all_receipts[0]
        .block_number
        .expect("couldn't find block number in receipt");
    //TODO: filter out non-smart-contract tx
    let receipts: Vec<_> = all_receipts
        .into_iter()
        .filter(|x| x.gas_used > TURETZKY_UPPER_GAS_LIMIT && x.to.is_some())
        .collect();

    println!("got {} receipts for block {}", receipts.len(), block_number);
    let mut reports = Vec::new();
    for receipt in receipts {
        println!("processing {}", &receipt.transaction_hash);
        reports.push(
            get_report(&provider, receipt.transaction_hash, &receipt, &gk)
                .await
                .unwrap_or_else(|e| GasKillerReport::report_error(Utc::now(), &receipt, &e)),
        );
        println!("done");
    }
    Ok(reports)
}

pub async fn gas_estimate_tx(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
    gk: &GasKillerDefault,
) -> Result<GasKillerReport> {
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow!("could not get receipt for tx {}", tx_hash))?;
    let smart_contract_tx = invokes_smart_contract(&provider, &receipt).await?;
    if receipt.gas_used <= TURETZKY_UPPER_GAS_LIMIT
        || !smart_contract_tx
        || receipt.to.is_none()
        || !receipt.status()
    {
        bail!(
            "Skipped: either 1) gas used is less than or equal to TUGL or 2) no smart contract calls are made or 3) contract creation transaction or 4) transaction failed"
        )
    }

    get_report(&provider, tx_hash, &receipt, gk).await
}

pub async fn get_report(
    provider: impl Provider,
    tx_hash: FixedBytes<32>,
    receipt: &TransactionReceipt,
    gk: &GasKillerDefault,
) -> Result<GasKillerReport> {
    let details = gaskiller_reporter(&provider, tx_hash, gk, receipt).await;
    if let Err(e) = details {
        return Ok(GasKillerReport::report_error(Utc::now(), receipt, &e));
    }

    Ok(GasKillerReport::from(Utc::now(), receipt, details.unwrap()))
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
        .ok_or_else(|| anyhow!("could not get receipt for tx {}", tx_hash))?;
    let trace = get_tx_trace(&provider, tx_hash).await?;
    let (state_updates, opcodes) = compute_state_updates(trace).await?;
    let skipped_opcodes = opcodes.into_iter().collect::<Vec<_>>().join(", ");
    let gaskiller_gas_estimate = gk
        .estimate_state_changes_gas(
            receipt.to.unwrap(), // already check if this is None in gas_estimate_tx
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
        percent_savings: (gas_savings * 100) as f64 / gas_used as f64,
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

    let encoded_updates = encode_state_updates_to_abi(&state_updates);

    // Print the full hex-encoded storage updates for debugging
    println!("\n========================================");
    println!("[call_to_encoded_state_updates_with_gas_estimate] ENUM ARRAY ENCODING");
    println!("[call_to_encoded_state_updates_with_gas_estimate] Full storage_updates bytes (StateUpdateType[]):");
    println!("0x{}", encoded_updates.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("========================================\n");

    Ok((
        encoded_updates,
        gas_estimate,
        skipped_opcodes,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use alloy::primitives::{U256, address, b256, bytes};
    use constants::*;
    use csv::Writer;
    use sol_types::SimpleStorage;

    #[test]
    fn test_stateupdatetype_tuple_encoding() -> Result<()> {
        // Test encoding as (StateUpdateType[], bytes[]) tuple
        let state_updates = vec![
            StateUpdate::Store(IStateUpdateTypes::Store {
                slot: b256!("debfdfd5a50ad117c10898d68b5ccf0893c6b40d4f443f902e2e7646601bdeaf"),
                value: b256!("0000000000000000000000000000000000000000000000000000000000000001"),
            }),
            StateUpdate::Log0(IStateUpdateTypes::Log0 {
                data: Bytes::from(vec![0x00, 0x00, 0x6f, 0xee]),
            }),
            StateUpdate::Log1(IStateUpdateTypes::Log1 {
                data: Bytes::from(vec![0x00, 0x00, 0x6f, 0xee]),
                topic1: b256!("fd3dfbb3da06b2710848916c65866a3d0e050047402579a6e1714261137c19c6"),
            }),
        ];

        let encoded = encode_state_updates_to_abi(&state_updates);

        println!("\n========== (StateUpdateType[], bytes[]) TUPLE ENCODING TEST ==========");
        println!("Number of state updates: {}", state_updates.len());
        println!("Encoded length: {} bytes", encoded.len());
        println!("\nFull hex output:");
        println!("0x{}", encoded.iter().map(|b| format!("{:02x}", b)).collect::<String>());

        println!("\nBreakdown:");
        if encoded.len() >= 32 {
            println!("Offset to types[] (first 32 bytes): 0x{}",
                encoded[0..32].iter().map(|b| format!("{:02x}", b)).collect::<String>());
        }
        if encoded.len() >= 64 {
            println!("Offset to bytes[] (next 32 bytes):  0x{}",
                encoded[32..64].iter().map(|b| format!("{:02x}", b)).collect::<String>());
        }
        if encoded.len() >= 96 {
            println!("Start of types data (next 32 bytes): 0x{}",
                encoded[64..96].iter().map(|b| format!("{:02x}", b)).collect::<String>());
        }
        println!("\nExpected Solidity decode:");
        println!("(StateUpdateType[] memory types, bytes[] memory args) = abi.decode(storageUpdates, (StateUpdateType[], bytes[]));");
        println!("============================================\n");

        Ok(())
    }

    #[tokio::test]
    async fn test_csv_writer() -> Result<()> {
        dotenv::dotenv().ok();

        if std::env::var("RPC_URL").is_err() {
            eprintln!("skipping test_csv_writer: set RPC_URL to run");
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;
        let gk = GasKillerDefault::new(rpc_url, None).await?;
        let report = gas_estimate_tx(provider, SIMPLE_ARRAY_ITERATION_TX_HASH, &gk).await?;

        let _ = File::create("test.csv")?;
        let mut writer = Writer::from_path("test.csv")?;

        writer.serialize(report)?;
        writer.flush()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_estimate_state_changes_gas_set() -> Result<()> {
        dotenv::dotenv().ok();

        if std::env::var("RPC_URL").is_err() {
            eprintln!("skipping test_estimate_state_changes_gas_set: set RPC_URL to run");
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

        let tx_hash = SIMPLE_STORAGE_SET_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new(rpc_url, None).await?;
        let gas_estimate = gk
            .estimate_state_changes_gas(SIMPLE_STORAGE_ADDRESS, &state_updates)
            .await?;
        assert_eq!(gas_estimate, 32549);
        Ok(())
    }

    #[tokio::test]
    async fn test_estimate_state_changes_gas_access_control() -> Result<()> {
        dotenv::dotenv().ok();

        if std::env::var("RPC_URL").is_err() {
            eprintln!(
                "skipping test_estimate_state_changes_gas_access_control: set RPC_URL to run"
            );
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("TESRPC_URLTNET_RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

        let tx_hash = ACCESS_CONTROL_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new(rpc_url, None).await?;
        let gas_estimate = gk
            .estimate_state_changes_gas(ACCESS_CONTROL_MAIN_ADDRESS, &state_updates)
            .await?;
        assert_eq!(gas_estimate, 37185);
        Ok(())
    }

    #[tokio::test]
    async fn test_estimate_state_changes_gas_access_control_failure() -> Result<()> {
        dotenv::dotenv().ok();

        if std::env::var("RPC_URL").is_err() {
            eprintln!(
                "skipping test_estimate_state_changes_gas_access_control_failure: set RPC_URL to run"
            );
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

        let tx_hash = ACCESS_CONTROL_MAIN_RUN_TX_HASH;
        let trace = get_tx_trace(&provider, tx_hash).await?;
        let (state_updates, _) = compute_state_updates(trace).await?;

        let gk = GasKillerDefault::new(rpc_url, None).await?;
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

        if std::env::var("RPC_URL").is_err() {
            eprintln!("skipping test_compute_state_updates_set: set TESTNET_RPC_URL to run");
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

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

        if std::env::var("RPC_URL").is_err() {
            eprintln!("skipping test_compute_state_updates_deposit: set TESTNET_RPC_URL to run");
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

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

        if std::env::var("RPC_URL").is_err() {
            eprintln!(
                "skipping test_compute_state_updates_delegatecall: set TESTNET_RPC_URL to run"
            );
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

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

        if std::env::var("RPC_URL").is_err() {
            eprintln!(
                "skipping test_compute_state_updates_call_external: set TESTNET_RPC_URL to run"
            );
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;
        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

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

        if std::env::var("RPC_URL").is_err() {
            eprintln!(
                "skipping test_compute_state_update_simulate_call: set TESTNET_RPC_URL to run"
            );
            return Ok(());
        }

        let rpc_url: Url = std::env::var("RPC_URL")
            .expect("RPC_URL must be set")
            .parse()?;

        let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;

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

    #[tokio::test]
    async fn test_encoding_format() -> Result<()> {
        // Test that encoding produces the correct format for Solidity consumption
        // The bug was that StateUpdates::abi_encode wraps in an extra tuple layer

        // Create multiple state updates to match the chisel example
        let state_updates = vec![
            StateUpdate::Store(IStateUpdateTypes::Store {
                slot: b256!("debfdfd5a50ad117c10898d68b5ccf0893c6b40d4f443f902e2e7646601bdeaf"),
                value: b256!("0000000000000000000000000000000000000000000000000000000000000001"),
            }),
            StateUpdate::Log0(IStateUpdateTypes::Log0 {
                data: Bytes::from(vec![0x00, 0x00, 0x6f, 0xee]),
            }),
            StateUpdate::Log1(IStateUpdateTypes::Log1 {
                data: Bytes::from(vec![0x00, 0x00, 0x6f, 0xee]),
                topic1: b256!("fd3dfbb3da06b2710848916c65866a3d0e050047402579a6e1714261137c19c6"),
            }),
        ];

        let encoded = encode_state_updates_to_abi(&state_updates);

        // Decode it back as raw parameter list (bytes, bytes[])
        // Use abi_decode_params because we encoded a param list, not a single tuple value
        let decoded = <(Bytes, Vec<Bytes>)>::abi_decode_params(&encoded, true);

        match decoded {
            Ok((types_bytes, data)) => {
                let types: Vec<u8> = types_bytes.to_vec();
                assert_eq!(types.len(), 3, "Should have 3 state updates");
                assert_eq!(data.len(), 3, "Should have 3 data entries");
                assert_eq!(types[0], StateUpdateType::STORE as u8);
                assert_eq!(types[1], StateUpdateType::LOG0 as u8);
                assert_eq!(types[2], StateUpdateType::LOG1 as u8);

                // Verify the encoding doesn't start with 0x20 (the extra wrapper)
                // The first 32 bytes should be 0x40 (offset to types[]), not 0x20
                if encoded.len() >= 32 {
                    let first_word = &encoded[0..32];
                    let is_wrapper = {
                        let mut expected = [0u8; 32];
                        expected[31] = 0x20;
                        first_word == expected
                    };
                    if is_wrapper {
                        bail!(
                            "Encoding still has the extra wrapper! First 32 bytes should be the offset to types[] (0x40), not a wrapper (0x20)."
                        );
                    }
                }
            }
            Err(e) => {
                bail!(
                    "Failed to decode as (uint8[], bytes[]): {}. The encoding is still wrong.",
                    e
                );
            }
        }

        Ok(())
    }
}
