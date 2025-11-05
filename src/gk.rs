use crate::sol_types::{RevertingContext, StateUpdate};
use alloy::{
    contract,
    hex,
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, Selector, U256},
    providers::{
        Identity, ProviderBuilder, RootProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    // enable json-rpc feature in Cargo.toml for ErrorPayload
    rpc::json_rpc::ErrorPayload,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolError,
    transports::RpcError,
};
use alloy_provider::{Provider, ext::AnvilApi};
use anyhow::{Context, Error, Result, anyhow, bail};
use url::Url;

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
    pub async fn new(fork_url: Url, block_number: Option<u64>) -> Result<Self> {
        let anvil_init = Anvil::new().fork(fork_url.as_str());

        let anvil = if let Some(number) = block_number {
            anvil_init.fork_block_number(number - 1).try_spawn()?
        } else {
            anvil_init.try_spawn()?
        };
        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(anvil.endpoint_url().as_str())
            .await?;

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
        let reverting_context = RevertingContext::abi_decode(&reverting_context_error_hex, true)
            .context("something went incredibly wrong, RevertingContext rpc error wasn't valid abi encoded")?;

        // NOTE: signature identification removed for Alloy 0.12.6 + dependency constraints
        // TODO: possible to parallelize requests to signatures_identifier
        let _revert_selector = reverting_context
            .revertData
            .get(0..4)
            .map(|bytes| Selector::try_from(bytes).unwrap());
        let _error: Option<(String, Vec<u8>)> = None;

        let function: Option<(String, Vec<u8>)> = None;
        let target = reverting_context.target;
        let state_update_index = reverting_context.index;

        let function_string = match function {
            Some((_identified_function, decoded_input)) => {
                format!(
                    "Identified function with values ({})",
                    format_decoded_values(&decoded_input[..])
                )
            }
            None => format!("Unrecognized function: {:?}", reverting_context.callargs),
        };

        let error_string = format!("Unrecognized error: {:?}", reverting_context.revertData);

        Ok(anyhow!(
            "Simulation subcontext reverted. State Update Index: {} Target Address: {}, Called {} Got error: {}",
            state_update_index,
            target,
            function_string,
            error_string
        ))
    }
}

fn format_decoded_values<T: core::fmt::Debug>(values: &[T]) -> String {
    values
        .iter()
        .map(|v| format!("{:?}", v))
        .collect::<Vec<String>>()
        .join(", ")
}
