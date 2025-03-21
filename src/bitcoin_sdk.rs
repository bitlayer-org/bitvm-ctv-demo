use std::{str::FromStr, time::Duration};

use bitcoin::{consensus::encode, Address, Amount, OutPoint, Transaction, Txid};
use bitcoincore_rpc::{
    bitcoin::Address as RPCAddress,
    bitcoin::Amount as RPCAmount,
    jsonrpc::{self, simple_http::Builder},
    Client, Result, RpcApi,
};


#[derive(Clone)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub amount: Amount,
}
pub struct RPCClient {
    client: Client,
}

impl RPCClient {
    pub fn new(url: &str, user: &str, password: &str) -> Self {
        let mut builder = Builder::new().url(&url).expect("invalid rpc info");
        builder = builder
            .auth(user, Some(password))
            .timeout(Duration::from_secs(100));
        let transport = jsonrpc::Client::with_transport(builder.build());
        Self {
            client: Client::from_jsonrpc(transport),
        }
    }
    pub fn prepare_utxo_for_address(&self, amount: Amount, address: &Address) -> UTXO {
        let txid = self
            .client
            .send_to_address(
                &RPCAddress::from_str(&address.to_string()).expect("msg").assume_checked(),
                RPCAmount::from_sat(amount.to_sat()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("send tx failed");

        let tx_result = self.client.get_transaction(&txid, None).expect("error");
        UTXO {
            outpoint: OutPoint {
                txid: Txid::from_str(&txid.to_string()).expect("msg"),
                vout: tx_result.details[0].vout,
            },
            amount,
        }
    }

    pub fn send_transaction(&self, tx: &Transaction) -> Result<Txid> {
        let tx_bytes: Vec<u8> = encode::serialize(&tx);
        let txid = self.client.send_raw_transaction(&tx_bytes)?;
        Ok(Txid::from_str(&txid.to_string()).expect("msg"))
    }
}
