use alloy::{
    node_bindings::{Anvil, AnvilInstance}, 
    primitives::B256, 
    network::EthereumWallet,
    providers::{
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller}, 
        Identity, ProviderBuilder, RootProvider
    }, 
    signers::local::PrivateKeySigner,
    sol
};
use crate::sol_types::StateUpdate;
use anyhow::Result;

sol!(
    #[sol(rpc)]
    StateChangeHandlerGasEstimator, "res/abi/StateChangeHandlerGasEstimator.json"
);

pub enum WarmSlotsRule {
    None,
    AllStore
}

// I really fucking hate rust's type system sometimes
type ConnectHTTPDefaultProvider = FillProvider<JoinFill<JoinFill<Identity, JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>>, WalletFiller<EthereumWallet>>, RootProvider>;
pub type GasKillerDefault = GasKiller<ConnectHTTPDefaultProvider>;

pub struct GasKiller<P> {
    _anvil: AnvilInstance,
    contract: StateChangeHandlerGasEstimator::StateChangeHandlerGasEstimatorInstance<P>
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
            contract
        })
    }

    pub async fn estimate_state_changes_gas(
        &self,
        state_updates: &[StateUpdate],
        warm_slots_rule: WarmSlotsRule
    ) -> Result<u64> {
        let temperature_slots = match warm_slots_rule {
            WarmSlotsRule::None => vec![],
            WarmSlotsRule::AllStore => state_updates.iter().filter_map(|x| match x {
                StateUpdate::Store(slot) => Some(slot.slot),
                _ => None
            })
            .collect::<std::collections::HashSet<_>>() // remove duplicates
            .into_iter()
            .collect()
        };
        self.warm_slots(temperature_slots.clone()).await?;

        let (types, args) = crate::encode_state_updates_to_sol(&state_updates);
        let types = types.iter().map(|x| *x as u8).collect::<Vec<_>>();
        let tx = self.contract
            .runStateUpdatesCall(types, args)
            .send()
            .await?;
        
        // TODO: how do I check transaction was successful?
        let receipt = tx.get_receipt().await?;

        self.cool_slots(temperature_slots).await?;
        Ok(receipt.gas_used)
    }

    async fn warm_slots(&self, slots: Vec<B256>) -> Result<()> {
        let tx = self.contract
            .warmSlots(slots)
            .send()
            .await?;

        tx.get_receipt().await?;
        
        Ok(())
    }

    async fn cool_slots(&self, slots: Vec<B256>) -> Result<()> {
        let tx = self.contract
            .coolSlots(slots)
            .send()
            .await?;

        tx.get_receipt().await?;
        Ok(())
    }
}

