#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

mod proxy;

use multiversx_sc_snippets::{imports::*, multiversx_sc_scenario::meta::contract};
use multiversx_sc_snippets::multiversx_sc_scenario::api::VMHooksApi;
use multiversx_sc_snippets::sdk;
use serde::{Deserialize, Serialize};
use toml::Value;
use std::os::raw::c_int;
use std::{
    io::{Read, Write},
    path::Path,
};

use reqwest::Client;
use reqwest::Error;
use serde_json::json;
// use serde_json::Value;
use tokio::time::{sleep, Duration};
use base64;
use std::fs::File;

// const GATEWAY: &str = "http://localhost:8085";
const GATEWAY: &str = sdk::gateway::DEVNET_GATEWAY;
const STATE_FILE: &str = "state.toml";
    
#[tokio::main]
async fn main() {
    // let _= generate_wallet();
    // env_logger::init();

    // let mut args = std::env::args();
    // let _ = args.next();
    // let cmd = args.next().expect("at least one argument required");
    // let mut interact = ContractInteract::new().await;
    // match cmd.as_str() {
    //     "deploy" => interact.deploy().await,
    //     "upgrade" => interact.upgrade().await,
    //     "set_unbond_period" => interact.set_unbond_period().await,
    //     "whitelist_token" => interact.whitelist_token().await,
    //     "blacklist_token" => interact.blacklist_token().await,
    //     "lock" => interact.lock().await,
    //     "unlock" => interact.unlock().await,
    //     "unbond" => interact.unbond().await,
    //     "lockedTokenAmounts" => interact.locked_token_amounts_by_address().await,
    //     "unlockedTokenAmounts" => interact.unlocked_token_by_address().await,
    //     "lockedTokens" => interact.locked_tokens().await,
    //     "unlockedTokens" => interact.unlocked_tokens().await,
    //     "whitelistedTokens" => interact.token_whitelist().await,
    //     "unbondPeriod" => interact.unbond_period().await,
    //     _ => panic!("unknown command: {}", &cmd),
    // }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    contract_address: Option<Bech32Address>,
}

impl State {
    // Deserializes state from file
    pub fn load_state() -> Self {
        if Path::new(STATE_FILE).exists() {
            let mut file = std::fs::File::open(STATE_FILE).unwrap();
            let mut content = String::new();
            file.read_to_string(&mut content).unwrap();
            toml::from_str(&content).unwrap()
        } else {
            Self::default()
        }
    }

    /// Sets the contract address
    pub fn set_address(&mut self, address: Bech32Address) {
        self.contract_address = Some(address);
    }

    /// Returns the contract address
    pub fn current_address(&self) -> &Bech32Address {
        self.contract_address
            .as_ref()
            .expect("no known contract, deploy first")
    }
}

impl Drop for State {
    // Serializes state to file
    fn drop(&mut self) {
        let mut file = std::fs::File::create(STATE_FILE).unwrap();
        file.write_all(toml::to_string(self).unwrap().as_bytes())
            .unwrap();
    }
}

struct TokenPayments {
    token_ids: Vec<String>,
    token_nonces: Vec<u64>,
    token_amounts: Vec<u128>,
}

impl TokenPayments {
    fn new() -> Self {
        TokenPayments {
            token_ids: Vec::new(),
            token_nonces: Vec::new(),
            token_amounts: Vec::new(),
        }
    }

    fn add(&mut self, token_id: String, token_nonce: u64, token_amount: u128) {
        self.token_ids.push(token_id);
        self.token_nonces.push(token_nonce);
        self.token_amounts.push(token_amount);
    }
}

struct ContractInteract {
    interactor: Interactor,
    wallet_address: Address,
    contract_code: BytesValue,
    state: State,
}


async fn generate_wallet() -> Result<(), Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8085/simulator/initial-wallets")
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully sent GET request!");
        let body = response.text().await?;
        let aux: Value = serde_json::from_str(&body).unwrap();

        let specific_wallet = &aux["data"]["balanceWallets"]["2"];

        // Extract bech32 address and privateKeyHex directly from specific_wallet
        let bech32 = specific_wallet["address"]["bech32"].as_str().unwrap();
        let private_key_hex = specific_wallet["privateKeyHex"].as_str().unwrap();

        // Convert privateKeyHex string to a base64 encoded string
        let private_key_base64 = base64::encode(private_key_hex);

        // Split the base64 string into 64-character lines
        let formatted_key = private_key_base64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<&str>>()
            .join("\n");

        // Create the content of the .pem file
        let pem_content = format!(
            "-----BEGIN PRIVATE KEY for {}-----\n{}\n-----END PRIVATE KEY for {}-----",
            bech32, formatted_key, bech32
        );

        // Write the content to simulationWallet.pem
        let mut file = File::create("simulationWallet.pem").unwrap();
        file.write_all(pem_content.as_bytes()).unwrap();
    } else {
        println!("Failed to send GET request. Status: {}", response.status());
    }


    let body = json!({
        "454c524f4e44657364743132333435362d326566393263": "120b00152d02c7e14af6800000",
        "454c524f4e44657364744153482d653364316237": "1209008ac7230489e80000",
        "454c524f4e4465736474424b4c2d303165656330": "120a0025f273933db5700000",
        "454c524f4e4465736474434f532d316465613639": "120b000211ae7a158d9841fff6",
        "454c524f4e4465736474494f555a2d633162633735": "120400989680",
        "454c524f4e446573647449544b4e2d643364656565": "12090029a2241af62c0000",
        "454c524f4e446573647449554c4e46542d34373534666301": "080112020001",
        "454c524f4e446573647449554c544b4e32302d393161636662": "120a002f000ac26fe7ac0000",
        "454c524f4e446573647449554c544b4e33302d396530663561": "120a002c73c937742c500000",
        "454c524f4e44657364744d42542d663136363863": "1213000125dfa371a19e6f7cb54395ca0000000000",
        "454c524f4e44657364744d544b4e2d613231373730": "120a00056bc75e2d63100000",
        "454c524f4e44657364744e455645524c4f434b2d343566656261": "120a00056bc75e2d63100000",
        "454c524f4e446573647453544f4b2d396564303037": "120b00152882eca50bb1140000",
        "454c524f4e446573647453544f4b322d333933396463": "120b00152c407de377cf080000",
        "454c524f4e44657364745745474c442d613238633539": "1208001c32b3b79ed4fc",
        "454c524f4e446e6f6e636549554c4e46542d343735346663": "01",
        "454c524f4e44726f6c656573647449554c4e46542d343735346663": "0a1145534454526f6c654e4654437265617465",
        "47697448756220757365726e616d65": "20476974687562626572323032342d63727970746f"
    });
    let response = client
                            .post(format!("http://localhost:8085/simulator/address/{}/set-state", Wallet::from_pem_file("simulationWallet.pem").unwrap().address()))
                            .json(&body)
                            .send()
                            .await?;
    Ok(())
}

impl ContractInteract {    

    async fn new() -> Self {
        let mut interactor = Interactor::new(GATEWAY).await;
        //let _ = generate_wallet().await;
        let wallet_address =
            interactor.register_wallet(Wallet::from_pem_file("../ctfBlac.pem").unwrap());
            // interactor.register_wallet(Wallet::from_pem_file("simulationWallet.pem").unwrap());
        let contract_code = BytesValue::interpret_from(
            "mxsc:../output/liquid-locking.mxsc.json",
            &InterpreterContext::default(),
        );

        ContractInteract {
            interactor,
            wallet_address,
            contract_code,
            state: State::load_state(),
        }
    }

    async fn deploy(&mut self, unbond_period: u64) {
        let unbond_period = 1u64;

        let new_address = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .init(unbond_period)
            .code(&self.contract_code)
            .returns(ReturnsNewAddress)
            .prepare_async()
            .run()
            .await;
        let new_address_bech32 = bech32::encode(&new_address);
        self.state.set_address(Bech32Address::from_bech32_string(
            new_address_bech32.clone(),
        ));

        println!("new address: {new_address_bech32}");
    }

    async fn upgrade(&mut self, unbond_period: u64) {
        let state_address = self.state.current_address();

        println!("State_address {state_address:?}");

        let response = self
            .interactor
            .tx()
            .to(state_address)
            .from(&self.wallet_address)
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .upgrade(unbond_period)
            .code(&self.contract_code)
            .code_metadata(CodeMetadata::UPGRADEABLE)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn set_unbond_period(&mut self, unbond_period: u64) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .set_unbond_period(unbond_period)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn whitelist_token(&mut self, token: &str) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .whitelist_token(TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn blacklist_token(&mut self, token: &str) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .blacklist_token(TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn lock(&mut self, tokens: TokenPayments) {

        let mut tokenPayments = ManagedVec::new();

        for i in 0..tokens.token_ids.len() {
            let aux = EsdtTokenPayment::new(
                TokenIdentifier::from(&tokens.token_ids[i].to_string()),
                tokens.token_nonces[i],
                BigUint::from(tokens.token_amounts[i]),
            );

            tokenPayments.push(aux);
        }

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(40_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .lock()
            //.single_esdt(&TokenIdentifier::from(token_id), token_nonce, &BigUint::from(token_amount))
            //.payment((TokenIdentifier::from(token_id), token_nonce, token_amount))
            .payment(tokenPayments)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn unlock(&mut self, tokens: TokenPayments, expectedResult: ExpectError<'_>) {

        let mut tokenPayments = ManagedVec::new();

        for i in 0..tokens.token_ids.len() {
            let aux = EsdtTokenPayment::new(
                TokenIdentifier::from(&tokens.token_ids[i].to_string()),
                tokens.token_nonces[i],
                BigUint::from(tokens.token_amounts[i]),
            );

            tokenPayments.push(aux);
        }

            let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .unlock(tokenPayments)
            .returns( expectedResult )
            .prepare_async()
            .run()
            .await;
        
       

        println!("Result: {response:?}");
    }

    async fn unbond(&mut self, token_id: &str) {
        let tokens = ManagedVec::from_single_item(TokenIdentifier::from(token_id));

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(40_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .unbond(tokens)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn locked_token_amounts_by_address(&mut self) {
        let address = Bech32Address::from_bech32_string(String::from("erd1tjkfemhpxmch4vx306y85x2lv2n9d6hvn8qpe6atc7m82wef75pqmnws0t"));

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .locked_token_amounts_by_address(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_token_by_address(&mut self) {
        let address = Bech32Address::from_bech32_string(String::from("erd1tjkfemhpxmch4vx306y85x2lv2n9d6hvn8qpe6atc7m82wef75pqmnws0t"));

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_token_by_address(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn locked_tokens(&mut self) {
        let address = Bech32Address::from_bech32_string(String::from("erd1tjkfemhpxmch4vx306y85x2lv2n9d6hvn8qpe6atc7m82wef75pqmnws0t"));

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .locked_tokens(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_tokens(&mut self) {
        let address = Bech32Address::from_bech32_string(String::from("erd1tjkfemhpxmch4vx306y85x2lv2n9d6hvn8qpe6atc7m82wef75pqmnws0t"));

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_tokens(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn token_whitelist(&mut self) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .token_whitelist()
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unbond_period(&mut self) {
        
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unbond_period()
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }
}

fn denominate_value(input: u128) -> u128 {
    input * 10u128.pow(18)
}

#[tokio::test]
async fn test_deploy() {
    let mut contract_interactor = ContractInteract::new().await;

    let _ = contract_interactor.deploy(0).await;
    let aux = contract_interactor.state.current_address();

    println!("SC Address: {aux:?}")
}

#[tokio::test]
async fn test_upgrade() {
    let mut contract_interactor = ContractInteract::new().await;

    let aux = contract_interactor.state.current_address();

    println!("SC Address: {aux:?}");

    contract_interactor.upgrade(0).await;
}

#[tokio::test]
async fn test_whitelist() {
    let mut contract_interactor = ContractInteract::new().await;

    contract_interactor.whitelist_token("STOK2-3939dc").await;
    contract_interactor.whitelist_token("STOK-9ed007").await;
    contract_interactor.whitelist_token("NEVERLOCK-45feba").await;
}

#[tokio::test]
async fn test_blacklist() {
    let mut contract_interactor = ContractInteract::new().await;

    contract_interactor.blacklist_token("STOK2-3939dc").await;
    contract_interactor.blacklist_token("STOK-9ed007").await;
}

#[tokio::test]
async fn test_lock() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut payment = TokenPayments::new();

    payment.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1));
    payment.add(String::from("STOK-9ed007"), 0u64, denominate_value(1));

    contract_interactor.lock(payment).await;
}

#[tokio::test]
async fn test_unlock() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut payment = TokenPayments::new();

    payment.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1));
    payment.add(String::from("STOK-9ed007"), 0u64, denominate_value(1));

    contract_interactor
        .unlock(payment, ExpectError(0, ""))
        .await;
}

#[tokio::test]
async fn test_unbond() {
    let mut contract_interactor = ContractInteract::new().await;

    contract_interactor.unbond("STOK2-3939dc").await;
    // 10
}


#[tokio::test]
async fn print_views() {
    let mut contract_interactor = ContractInteract::new().await;
    println!("White-listed Tokens: ");
    contract_interactor.token_whitelist().await;
    println!("\n");
    
    println!("Locked Tokens");
    contract_interactor.locked_tokens().await;
    println!("\n");

    println!("Locked Tokens");
    contract_interactor.locked_token_amounts_by_address().await;
    println!("\n");
    
    println!("Unlocked Tokens");
    contract_interactor.unlocked_tokens().await;
    println!("\n");

    println!("Unlocked Tokens Amounts");
    contract_interactor.unlocked_token_by_address().await;
    println!("\n");

    println!("Unbond Period For Tokens");
    contract_interactor.unbond_period().await;
}

// UNLOCK SCENARIOS ##############################################################################################################################3

// token was locked before -> should pass
#[tokio::test]
async fn test_unlock_token_locked_before() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut paymentLock = TokenPayments::new();

    paymentLock.add(String::from("STOK-9ed007"), 0u64, denominate_value(1)); // valid token
    paymentLock.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1)); // valid token
    contract_interactor.lock(paymentLock).await;

    let mut paymentUnlock = TokenPayments::new();

    paymentUnlock.add(String::from("STOK-9ed007"), 0u64, denominate_value(1)); // valid token amount
    paymentUnlock.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1)); // valid token amount
    contract_interactor.unlock(paymentUnlock, ExpectError(0, "")).await;
    
}

// token not locked before -> should fail
#[tokio::test]
async fn test_unlock_token_not_locked_before() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut payment = TokenPayments::new();
    
    payment.add(String::from("NEVERLOCK-45feba"), 0u64, denominate_value(1));
    
    contract_interactor.unlock(payment, ExpectError(4, "unavailable amount")).await;
}

// no token was provided to unlock -> success?
#[tokio::test]
async fn test_unlock_no_token_provided() {
    let mut contract_interactor = ContractInteract::new().await;

    let payment = TokenPayments::new();

    contract_interactor.unlock(payment, ExpectError(0, "")).await;

}

// at least 1 token is invalid (token_amount > locked_amount) -> should fail
#[tokio::test]
async fn test_unlock_invalid_token_amount() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut paymentLock = TokenPayments::new();

    paymentLock.add(String::from("STOK-9ed007"), 0u64, denominate_value(1)); // valid token
    paymentLock.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1)); // valid token
    contract_interactor.lock(paymentLock).await;


    let mut paymentUnlock = TokenPayments::new();

    paymentUnlock.add(String::from("STOK-9ed007"), 0u64, denominate_value(1)); // valid token amount
    paymentUnlock.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1000)); // token amount > staked token
    contract_interactor.unlock(paymentUnlock, ExpectError(4, "unavailable amount")).await; 
   
}

// at least 1 token is invalid (amount == 0) -> should fail
#[tokio::test]
async fn test_unlock_invalid_token_amount2() {
    let mut contract_interactor = ContractInteract::new().await;

    let mut paymentLock = TokenPayments::new();

    paymentLock.add(String::from("STOK-9ed007"), 0u64, denominate_value(1)); // valid token
    paymentLock.add(String::from("STOK2-3939dc"), 0u64, denominate_value(1)); // valid token
    contract_interactor.lock(paymentLock).await;


    let mut paymentUnlock = TokenPayments::new();

    paymentUnlock.add(String::from("STOK-9ed007"), 0u64, denominate_value(1)); // valid token amount

    paymentUnlock.add(String::from("STOK2-3939dc"), 0u64, denominate_value(0)); // token_amount == 0
    contract_interactor.unlock(paymentUnlock, ExpectError(4, "requested amount cannot be 0")).await;
   
}