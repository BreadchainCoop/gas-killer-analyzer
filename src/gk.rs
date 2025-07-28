use crate::sol_types::StateUpdate;
use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},

    primitives::{U256, Address, Bytes},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        }, Identity, ProviderBuilder, RootProvider
    },
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_provider::{{ext::AnvilApi}, Provider};
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
    pub async fn new(fork_url: Url, block_number: Option<u64>) -> Result<Self> {
        let anvil_init = Anvil::new().fork(fork_url.as_str());
        
        let anvil = if let Some(number) = block_number {
            anvil_init.fork_block_number(number - 1).try_spawn()?
        }
        else {
         anvil_init.try_spawn()?
            
        };
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
            .anvil_set_balance
            (contract_address, U256::from(100000000000000000000000000000u128))
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
        
        let reverted: bool = self.provider.raw_request("evm_revert".into(), (snapshot_id,)).await?;
        assert!(reverted);
        let final_block_number = self.provider.get_block_number().await?;
        assert_eq!(initial_block_number, final_block_number, "block number should revert to initial state");
        Ok(receipt.gas_used)
    }
}
