use crate::sol_types::{DelegateCallWrapper, StateUpdate};
use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, B256, Bytes},
    providers::{
        Identity, ProviderBuilder, RootProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use alloy_provider::ext::AnvilApi;
use anyhow::{Result, bail};

sol!(
    #[sol(rpc)]
    StateChangeHandlerGasEstimator,
    "res/abi/StateChangeHandlerGasEstimator.json"
);

pub enum WarmSlotsRule {
    None,
    AllStore,
}

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
    contract: StateChangeHandlerGasEstimator::StateChangeHandlerGasEstimatorInstance<P>,
}

impl GasKiller<ConnectHTTPDefaultProvider> {
    pub async fn new() -> Result<Self> {
        let anvil = Anvil::new().try_spawn()?;
        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(anvil.endpoint_url());

        let contract = StateChangeHandlerGasEstimator::deploy(provider).await?;

        Ok(Self {
            _anvil: anvil,
            contract,
        })
    }

    pub async fn estimate_state_changes_gas(
        &self,
        contract_address: Address,
        state_updates: &[StateUpdate],
        warm_slots_rule: WarmSlotsRule,
    ) -> Result<u64> {
        let provider = self.contract.provider();
        provider
            .anvil_set_code(contract_address, DelegateCallWrapper::BYTECODE.clone())
            .await?;
        let target_contract = DelegateCallWrapper::new(contract_address, &provider);
        let impl_address = *self.contract.address();

        let (types, args) = crate::encode_state_updates_to_sol(state_updates);
        let types = types.iter().map(|x| *x as u8).collect::<Vec<_>>();

        let run_state_updates_call = (StateChangeHandlerGasEstimator::runStateUpdatesCallCall {
            types: types,
            args: args,
        })
        .abi_encode();
        let tx = target_contract
            .delegatecall(impl_address, run_state_updates_call.into())
            .send()
            .await?;

        let receipt = tx.get_receipt().await?;
        if !receipt.status() {
            bail!("Transaction failed");
        }

        // Self::cool_slots(&contract, temperature_slots).await?;
        Ok(receipt.gas_used)
    }

    async fn warm_slots(
        contract: &StateChangeHandlerGasEstimator::StateChangeHandlerGasEstimatorInstance<
            &ConnectHTTPDefaultProvider,
        >,
        slots: Vec<B256>,
    ) -> Result<()> {
        let tx = contract.warmSlots(slots).send().await?;

        tx.get_receipt().await?;

        Ok(())
    }

    async fn cool_slots(
        contract: &StateChangeHandlerGasEstimator::StateChangeHandlerGasEstimatorInstance<
            &ConnectHTTPDefaultProvider,
        >,
        slots: Vec<B256>,
    ) -> Result<()> {
        let tx = contract.coolSlots(slots).send().await?;

        tx.get_receipt().await?;
        Ok(())
    }
}
