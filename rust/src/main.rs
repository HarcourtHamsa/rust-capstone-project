#![allow(unused)]
use bitcoin::hex::DisplayHex;
use bitcoin::Transaction;
use bitcoincore_rpc::bitcoin::hashes::Hash;
use bitcoincore_rpc::bitcoin::{Amount, Denomination, TxOut};
use bitcoincore_rpc::json::LoadWalletResult;
use bitcoincore_rpc::{
    bitcoin::{Address, Network, Txid},
    Auth, Client, Error, RpcApi,
};
use hex::ToHex;
use serde::Deserialize;
use serde_json::json;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;

// Node access params
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port
const RPC_USER: &str = "alice";
const RPC_PASS: &str = "password";
const COINBASE_MATURITY_BLOCK_HEIGHT: u64 = 101;
const MINER: &str = "Miner";
const TRADER: &str = "Trader";
const MINER_ADDRESS_LABEL: &str = "Mining Reward";
const TRADER_ADDRESS_LABEL: &str = "Received";

// You can use calls not provided in RPC lib API using the generic `call` function.
// An example of using the `send` RPC call, which doesn't have exposed API.
// You can also use serde_json `Deserialize` derivation to capture the returned json result.
fn send(rpc: &Client, addr: &str, change_address: Option<&str>) -> bitcoincore_rpc::Result<String> {
    // Specification detail (from test case): Vin is expected to have a lenght of 1.
    // Gets list of unspent utxo and selected a single one that contains enough value to cover the transaction
    let unspent_utxos = rpc.list_unspent(None, None, None, None, None)?;

    let selected_utxo = unspent_utxos
        .iter()
        .find(|v| v.amount > Amount::from_int_btc(20))
        .ok_or_else(|| Error::ReturnedError("No UTXO with sufficient value".to_string()))?;

    let mut option_arg = json!({
        "inputs": [{"txid": selected_utxo.txid, "vout": selected_utxo.vout}],
    });

    if let Some(change_addr) = change_address {
        option_arg["change_address"] = json!(change_addr);
    }

    let args = [
        json!([{addr : 20 }]), // recipient address
        json!(null),           // conf target
        json!(null),           // estimate mode
        json!(null),           // fee rate in sats/vb
        option_arg,
    ];

    #[derive(Deserialize)]
    struct SendResult {
        complete: bool,
        txid: String,
    }
    let send_result = rpc.call::<SendResult>("send", &args)?;
    assert!(send_result.complete);
    Ok(send_result.txid)
}

fn generate_wallet_client(wallet: &LoadWalletResult) -> Result<Client, Error> {
    let wallet_rpc_url = format!("{}/wallet/{}", RPC_URL, wallet.name);

    let wallet_rpc = Client::new(
        &wallet_rpc_url,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )
    .map_err(|_| Error::ReturnedError("Failed to load client".to_string()))?;

    Ok(wallet_rpc)
}

/// create/load wallets named `Miner` and `Trader`
fn load_wallets(rpc: &Client) -> Result<Vec<LoadWalletResult>, Error> {
    let wallet_names = [MINER, TRADER];
    let mut wallets: Vec<LoadWalletResult> = vec![];

    for name in wallet_names {
        // Load or create wallets if non-existent
        let wallet = match rpc.load_wallet(name) {
            Ok(wallet) => wallet,
            Err(_) => {
                let _ = rpc.unload_wallet(Some(name));

                // Load wallet again
                match rpc.load_wallet(name) {
                    Ok(wallet) => wallet,
                    Err(_) => rpc.create_wallet(name, Some(false), None, None, None)?,
                }
            }
        };

        wallets.push(wallet);
    }

    Ok(wallets)
}

fn main() -> bitcoincore_rpc::Result<()> {
    // Connect to Bitcoin Core RPC
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // Get blockchain info
    // let _blockchain_info = rpc.get_blockchain_info()?;

    let mut wallets: Vec<LoadWalletResult> = load_wallets(&rpc)?;

    // Load miner wallet and generate a new address
    let miner_wallet: &LoadWalletResult = wallets
        .iter()
        .find(|wallet: &&LoadWalletResult| wallet.name == MINER)
        .expect("Miner wallet not found");

    // `Miner` wallet client
    let miner_wc = generate_wallet_client(miner_wallet)?;

    let miner_address = miner_wc
        .get_new_address(Some(MINER_ADDRESS_LABEL), None)?
        .assume_checked();

    // Generates spendable balance in the Miner wallet
    rpc.generate_to_address(COINBASE_MATURITY_BLOCK_HEIGHT, &miner_address)?;

    // Load Trader wallet and generate a new address
    let trader_wallet = wallets
        .iter()
        .find(|wallet| wallet.name == TRADER)
        .expect("Trader wallet not found");

    // `Trader` wallet client
    let trader_wc = generate_wallet_client(trader_wallet)?;

    let trader_address = trader_wc
        .get_new_address(Some(TRADER_ADDRESS_LABEL), None)?
        .assume_checked();

    // Send 20 BTC from Miner to Trader
    let txid = send(
        &miner_wc,
        &trader_address.to_string(),
        Some(&miner_address.to_string()),
    )?;
    let parsed_txid = Txid::from_str(&txid).unwrap();

    // Check transaction in mempool
    let mempool = miner_wc.get_mempool_entry(&parsed_txid)?;
    println!("mempool: {mempool:?}");

    // Mine 1 block to confirm the transaction
    // let confirmation_block = miner_wc.generate_to_address(1, &miner_address)?;
    let confirmation_block = miner_wc.generate_to_address(1, &trader_address)?;

    let block_info = miner_wc.get_block_info(&confirmation_block[0])?;

    // Extract all required transaction details
    let tx_json = miner_wc.get_transaction(&parsed_txid, Some(true))?;

    let vout = tx_json.transaction()?.output;

    let change_output = vout.iter().find(|v| {
        Address::from_script(&v.script_pubkey, Network::Regtest).ok() == Some(miner_address.clone())
    });

    let trader_output = vout.iter().find(|v| {
        Address::from_script(&v.script_pubkey, Network::Regtest).ok()
            == Some(trader_address.clone())
    });

    let mut change_address: Option<Address> = None;

    if change_output.is_some() {
        let script_pubkey_buf = &change_output.unwrap().script_pubkey.as_script();
        change_address = Address::from_script(script_pubkey_buf, Network::Regtest).ok();
    }

    // Write the data to ../out.txt in the specified format given in readme.md
    let filename = "out.txt";
    let filepath = format!("../{filename}");

    let file_buffer = File::create(&filepath);

    match file_buffer {
        Ok(mut file) => {
            writeln!(file, "{txid}")?;
            writeln!(file, "{miner_address}")?;
            writeln!(
                file,
                "{}",
                miner_wc
                    .get_balance(None, Some(true))?
                    .to_float_in(Denomination::Bitcoin)
            )?;
            writeln!(file, "{trader_address}")?;

            if trader_output.is_some() {
                writeln!(
                    file,
                    "{}",
                    trader_output
                        .unwrap()
                        .value
                        .to_float_in(Denomination::Bitcoin)
                )?;
            }

            if change_address.is_some() {
                writeln!(file, "{:?}", change_address.unwrap())?;
            }

            if change_output.is_some() {
                writeln!(
                    file,
                    "{}",
                    change_output
                        .unwrap()
                        .value
                        .to_float_in(Denomination::Bitcoin)
                )?;
            }

            writeln!(
                file,
                "{}",
                tx_json.fee.unwrap().to_float_in(Denomination::Bitcoin)
            )?;

            writeln!(file, "{}", block_info.height)?;

            let mut block_hash_bytes = block_info.hash.to_byte_array();
            block_hash_bytes.reverse();

            writeln!(file, "{}", hex::encode(block_hash_bytes))?;
        }
        Err(e) => {
            println!("Failed to create file: {e}");
        }
    }

    Ok(())
}
