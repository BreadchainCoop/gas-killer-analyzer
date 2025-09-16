use crate::sol_types::StateUpdate;
use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, U256},
    providers::{
        Identity, ProviderBuilder, RootProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_provider::{Provider, ext::AnvilApi};
use anyhow::{Result, bail};
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
    pub async fn new(fork_url: Url) -> Result<Self> {
        let anvil = Anvil::new().fork(fork_url.as_str()).try_spawn()?;
        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(anvil.endpoint_url().as_str())
            .await?;

        let contract = StateChangeHandlerGasEstimator::deploy(provider.clone()).await?;
        // Alloy's sol macro generates a BYTECODE and DEPLOYED_BYTECODE fields for contracts,
        // but I don't get how is it possible since deployed bytecode is dependant on constructor arguments
        // so I'm just deploying a contract and getting the code from it
        let code = provider.get_code_at(*contract.address()).await?;

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
            .await?;
        let receipt = tx.get_receipt().await?;
        if !receipt.status() {
            bail!("Transaction failed");
        }

        self.provider
            .anvil_set_code(contract_address, original_code)
            .await?;
        Ok(receipt.gas_used)
    }
}
