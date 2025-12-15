use crate::sol_types::{RevertingContext, StateUpdate};
use alloy::{
    contract,
    dyn_abi::DynSolValue,
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, FixedBytes, Selector, U256},
    providers::{
        Identity, ProviderBuilder, RootProvider,
        ext::DebugApi,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    rpc::{
        json_rpc::ErrorPayload,
        types::{
            eth::TransactionRequest,
            trace::geth::{
                DefaultFrame, GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace,
            },
        },
    },
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolError,
    transports::RpcError,
};
use alloy_dyn_abi::{ErrorExt, JsonAbiExt};
use alloy_provider::{Provider, ext::AnvilApi};
use anyhow::{Context, Error, Result, anyhow, bail};
use url::Url;

use foundry_evm_traces::identifier::SignaturesIdentifier;

sol!(
    #[sol(rpc)]
    StateChangeHandlerGasEstimator,
    "res/abi/StateChangeHandlerGasEstimator.json"
);

// I really fucking hate rust's type system sometimes
type ConnectHTTPDefaultProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;
pub type GasKillerDefault = GasKiller<ConnectHTTPDefaultProvider>;

pub struct GasKiller<P> {
    _anvil: AnvilInstance,
    provider: P,
    code: Bytes,
}

impl GasKiller<ConnectHTTPDefaultProvider> {
    /// Creates a new GasKiller instance with a forked Anvil.
    ///
    /// The Anvil instance is configured with:
    /// - `--steps-tracing`: Enable detailed step tracing for transactions
    /// - `--auto-impersonate`: Auto-impersonate any sender address
    ///
    /// This single Anvil instance is used for BOTH tracing and gas estimation,
    /// ensuring consistent state across operations.
    pub async fn new(fork_url: Url, block_number: Option<u64>) -> Result<Self> {
        let mut anvil_init = Anvil::new()
            .fork(fork_url.as_str())
            .arg("--steps-tracing")
            .arg("--auto-impersonate");

        if let Some(number) = block_number {
            anvil_init = anvil_init.fork_block_number(number);
        }

        let anvil = anvil_init.try_spawn()?;
        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(anvil.endpoint_url());

        let contract = StateChangeHandlerGasEstimator::deploy(provider.clone()).await?;
        // Alloy's sol macro generates a BYTECODE and DEPLOYED_BYTECODE fields for contracts,
        // but I don't get how is it possible since deployed bytecode is dependant on constructor arguments
        // so I'm just deploying a contract and getting the code from it
        let address = *contract.address();

        let code = provider.get_code_at(address).await?;

        Ok(Self {
            _anvil: anvil,
            provider,
            code,
        })
    }

    /// Sends a transaction and returns the trace.
    ///
    /// Uses the same Anvil instance that will be used for gas estimation,
    /// ensuring consistent blockchain state.
    pub async fn send_tx_and_get_trace(
        &self,
        tx_request: TransactionRequest,
    ) -> Result<DefaultFrame> {
        let tx_receipt = self
            .provider
            .send_transaction(tx_request)
            .await?
            .get_receipt()
            .await?;

        if !tx_receipt.status() {
            bail!("transaction failed");
        }

        let tx_hash = tx_receipt.transaction_hash;
        self.get_tx_trace(tx_hash).await
    }

    /// Gets the trace for a transaction that was already executed.
    pub async fn get_tx_trace(&self, tx_hash: FixedBytes<32>) -> Result<DefaultFrame> {
        let options = GethDebugTracingOptions {
            config: GethDefaultTracingOptions {
                enable_memory: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        let GethTrace::Default(trace) = self
            .provider
            .debug_trace_transaction(tx_hash, options)
            .await?
        else {
            return Err(anyhow!("Expected default trace"));
        };
        Ok(trace)
    }

    pub async fn estimate_state_changes_gas(
        &self,
        contract_address: Address,
        state_updates: &[StateUpdate],
    ) -> Result<u64> {
        let initial_block_number = self.provider.get_block_number().await?;
        let snapshot_id: U256 = self.provider.raw_request("evm_snapshot".into(), ()).await?;
        let original_code = self.provider.get_code_at(contract_address).await?;
        self.provider
            .anvil_set_code(contract_address, self.code.clone())
            .await?;
        let target_contract = StateChangeHandlerGasEstimator::new(contract_address, &self.provider);

        self.provider
            .anvil_set_balance(
                contract_address,
                U256::from(100000000000000000000000000000u128),
            )
            .await?;

        let (types, args) = crate::encode_state_updates_to_sol(state_updates);
        let types = types.iter().map(|x| *x as u8).collect::<Vec<_>>();
        let tx = target_contract
            .runStateUpdatesCall(types, args)
            .send()
            .await;
        // can't use map because of async
        let tx = match tx {
            Ok(tx) => tx,
            Err(e) => return Err(Self::process_simulation_error(e).await),
        };
        let receipt = tx.get_receipt().await?;
        if !receipt.status() {
            bail!("Transaction failed");
        }

        self.provider
            .anvil_set_code(contract_address, original_code)
            .await?;

        let reverted: bool = self
            .provider
            .raw_request("evm_revert".into(), (snapshot_id,))
            .await?;
        assert!(reverted);
        let final_block_number = self.provider.get_block_number().await?;
        assert_eq!(
            initial_block_number, final_block_number,
            "block number should revert to initial state"
        );
        Ok(receipt.gas_used)
    }

    async fn process_simulation_error(error: contract::Error) -> Error {
        let processed_error = match &error {
            contract::Error::TransportError(RpcError::ErrorResp(ErrorPayload {
                code: 3,
                data: Some(data),
                ..
            })) => {
                let selector_hex = format!("0x{}", hex::encode(RevertingContext::SELECTOR));
                let data_inner = data.get().trim_matches('"');
                if !data_inner.starts_with(&selector_hex) {
                    Err(None)
                } else {
                    Self::process_reverting_context_error(data_inner)
                        .await
                        .map_err(Some)
                }
            }
            _ => Err(None),
        };

        match processed_error {
            Ok(processed_error) => processed_error,
            Err(Some(processing_error)) => Err::<(), _>(processing_error)
                .context(format!("error processing error, original error: {}", error))
                .unwrap_err(),
            Err(None) => error.into(),
        }
    }

    async fn process_reverting_context_error(data: &str) -> Result<anyhow::Error> {
        let reverting_context_error_hex = hex::decode(data)
            .context("something went incredibly wrong, rpc error contained invalid hex value")?;
        let reverting_context = RevertingContext::abi_decode(&reverting_context_error_hex)
            .context("something went incredibly wrong, RevertingContext rpc error wasn't valid abi encoded")?;

        let signatures_identifier = SignaturesIdentifier::new(false).map_err(|e| anyhow!("detected RevertingContext error, but could not access SignaturesIdentifier service. error: {}", e))?;
        // TODO: possible to parallelize requests to signatures_identifier
        let revert_selector = reverting_context
            .revertData
            .get(0..4)
            .map(|bytes| Selector::try_from(bytes).unwrap());
        let error = (match revert_selector {
            Some(revert_selector) => signatures_identifier.identify_error(revert_selector).await,
            None => None,
        })
        .and_then(|identified_error| {
            match identified_error.decode_error(&reverting_context.revertData) {
                Ok(decoded_error) => Some((identified_error, decoded_error)),
                _ => None,
            }
        });

        let function_selector = reverting_context
            .callargs
            .get(0..4)
            .map(|bytes| Selector::try_from(bytes).unwrap());
        let function = (match function_selector {
            Some(function_selector) => {
                signatures_identifier
                    .identify_function(function_selector)
                    .await
            }
            None => None,
        })
        .and_then(|identified_function| {
            match identified_function.abi_decode_input(&reverting_context.callargs) {
                Ok(decoded_input) => Some((identified_function, decoded_input)),
                _ => None,
            }
        });
        let target = reverting_context.target;
        let state_update_index = reverting_context.index;

        let function_string = match function {
            Some((identified_function, decoded_input)) => {
                format!(
                    "{} with values ({})",
                    identified_function.signature(),
                    format_decoded_values(&decoded_input[..])
                )
            }
            None => format!("Unrecognized function: {:?}", reverting_context.callargs),
        };

        let error_string = match error {
            Some((identified_error, decoded_error)) => {
                format!(
                    "{} with values ({})",
                    identified_error.signature(),
                    format_decoded_values(&decoded_error.body)
                )
            }
            None => format!("Unrecognized error: {:?}", reverting_context.revertData),
        };

        Ok(anyhow!(
            "Simulation subcontext reverted. State Update Index: {} Target Address: {}, Called {} Got error: {}",
            state_update_index,
            target,
            function_string,
            error_string
        ))
    }
}

fn format_decoded_values(values: &[DynSolValue]) -> String {
    values
        .iter()
        .map(|v| format!("{:?}", v))
        .collect::<Vec<String>>()
        .join(", ")
}
