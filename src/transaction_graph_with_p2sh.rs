use bitcoin::hex::DisplayHex;
use bitcoincore_rpc::bitcoin::transaction;
use ctvlib::{Error, TemplateHash};
use lazy_static::lazy_static;
use std::str::FromStr;

use bitcoin::script::Builder;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message, SecretKey},
    Address, EcdsaSighashType, PrivateKey, PublicKey, SegwitV0Sighash, XOnlyPublicKey,
};
use bitcoin::{
    opcodes::all::OP_NOP4, script::PushBytesBuf, transaction::Version, Amount, ScriptBuf,
    Transaction, TxOut,
};
use bitcoin::{Network, OutPoint, TxIn, Txid, Witness};
use secp256k1::{rand, SECP256K1};

use crate::bitcoin_sdk::UTXO;
use crate::common::{
    build_taptree_with_script, calc_locking_script, convert_from, create_btc_tx, dummy_input, dummy_utxo, P2SHKeypair, Params, SignerInfo, TaprootInfo
};

pub struct TransactionGraph {
    kickoff: Transaction,
    kickoff_utxo: UTXO,
    happy_take: Transaction,

    pub p2sh_signer: P2SHKeypair,
    // challenge: Transaction,
    // assert: Transaction,
    // disprove: Transaction,

    // taproot_info: TaprootInfo,
}

impl TransactionGraph {

    pub fn get_p2sh_tx_signature(tx: &Transaction, p2sh_signer: &P2SHKeypair, input_index: usize, sighash_type: EcdsaSighashType) -> ScriptBuf {
        let mut sighash_cache = SighashCache::new(tx);

        let sighash = sighash_cache
            .legacy_signature_hash(
                input_index,
                &p2sh_signer.script,
                sighash_type.to_u32(),
            )
            .unwrap();
        println!("sighash: {}", sighash);

        let signature = p2sh_signer.sign_ecdsa_legacy(
            sighash,
            sighash_type,
        );
        println!("signature: {}", signature.to_hex_string(bitcoin::hex::Case::Lower));
        println!("pubkey: {}", p2sh_signer.public);


        Builder::new()
            .push_slice(&convert_from(signature))
            .push_slice(convert_from(p2sh_signer.script.clone().into()))
            .into_script()
    }

    pub fn new(operator: &Address, params: &Params, start_utxo: UTXO) -> Self {
        let temp_key = P2SHKeypair::new(Network::Regtest);
 
        let kickoff_amount = start_utxo.amount - params.gas_amt;
        let kickoff = create_btc_tx(
            &vec![start_utxo.clone()],
            vec![(temp_key.p2sh_address.script_pubkey(), kickoff_amount)],
        );
 
        let happy_take_output = TxOut {
            value: params.depoist_amt + params.stake_amt
                - params.gas_amt
                - params.gas_amt
                - params.gas_amt, // for pegin, happytake, kickoff
            script_pubkey: operator.script_pubkey(),
        };
 
        let p2sh_trick_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff.txid(),
                vout: 0,
            },
            amount: kickoff_amount,
        };
 
        let mut happy_take = create_btc_tx(
            &vec![dummy_utxo(), p2sh_trick_utxo],
            vec![(happy_take_output.script_pubkey.clone(), happy_take_output.value / 2), (happy_take_output.script_pubkey, happy_take_output.value - happy_take_output.value / 2)],
        );
 
        let unlocking_script = Self::get_p2sh_tx_signature(&happy_take, &temp_key, 1, EcdsaSighashType::SinglePlusAnyoneCanPay);
        happy_take.input[1].script_sig = unlocking_script;
 
        Self {
           p2sh_signer: temp_key,
            kickoff,
            kickoff_utxo: start_utxo,
            happy_take,
            // challenge,
            // assert,
            // disprove,
            // taproot_info
        }
    }


    pub fn get_first_script(&self) -> Result<ScriptBuf, Error> {
        let first_ctv_hash = self
            .happy_take
            .template_hash(0)
            .expect("calc kickoff ctv hash");
        calc_locking_script(first_ctv_hash)
    }

    pub fn get_kickoff_tx(&self, signer: &SignerInfo) -> Transaction {
        let mut tx = self.kickoff.clone();

        let hash_tx = tx.clone();
        let mut sighash_cache = SighashCache::new(&hash_tx);
        let utxos = vec![self.kickoff_utxo.clone()];
        // we only have an input as a fund to start.
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                0,
                &signer.address.script_pubkey(),
                utxos[0].amount,
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap();

        let signature = signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(signer.get_pk());

        tx.input[0].witness = witness;

        tx
    }

    pub fn get_happy_take_tx(&self, pegin_outpoint: OutPoint) -> Transaction {
        let mut tx = self.happy_take.clone();
        tx.input[0].previous_output = pegin_outpoint;
        tx
    }

    /*
    pub fn get_challenge_tx(&self, kickoff_utxo: UTXO) -> Transaction {
        let mut tx = self.challenge.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        let challenge_script = self.taproot_info.scripts[1].clone();
        let tsi = self.taproot_info.clone();
        let cb = tsi
            .taproot_spend_info.control_block(&(challenge_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| Error::UnknownError("Taproot construction error".into())).expect("get control block");
        tx.input[0].witness.push(challenge_script);
        tx.input[0].witness.push(cb.serialize());

        tx
    }

    pub fn get_assert_tx(&self, kickoff_utxo: UTXO) -> Transaction {
        let mut tx = self.assert.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        tx
    }

    pub fn get_disprove_tx(&self, kickoff_utxo: UTXO, receiver: &SignerInfo) -> (Transaction, Transaction) {
        let mut tx = self.disprove.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        let params = Params::default();
        let amount = tx.output[0].value + tx.output[1].value - params.gas_amt;
        let anchor_utxo = UTXO {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout: 0,
            },
            amount: tx.output[0].value
        };
        let anchor_utxo1 = UTXO {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout: 1,
            },
            amount: tx.output[1].value,
        };
        let ins = vec![anchor_utxo, anchor_utxo1];
        let reward_tx = create_btc_tx(&ins, vec![(receiver.address.script_pubkey(), amount)]);

        (tx, reward_tx)
    }
    */
}

mod test {
    use bitcoin::{consensus::serde::hex::Upper, hex::DisplayHex, opcodes::OP_0, script::Builder, sighash::SighashCache, OutPoint, Witness};
    use local_ip_address::local_ip;

    use crate::{
        bitcoin_sdk::{RPCClient, UTXO},
        common::{convert_from, create_btc_tx, P2SHKeypair, Params, Pegin, SignerInfo},
        transaction_graph_with_p2sh::TransactionGraph,
    };

    #[test]
    pub fn test_transaction_graph() {
        println!("=======happy path: pegin -> kickoff -> happytake=========================");
        {
            let params = Params::default();
            let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);

            let url = format!("{}:18443", local_ip().expect("find one").to_string());
            let user = "admin".to_string();
            let password = "admin".to_string();

            let client = RPCClient::new(&url, &user, &password);
            let start_utxo =
                client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);

            let transaction_graph =
                TransactionGraph::new(&operator_siggner.address, &params, start_utxo);
            let first_script = transaction_graph
                .get_first_script()
                .expect("get first script");
            let utxo =
                client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
            let pegin = Pegin::new(utxo.outpoint, utxo.amount, first_script, &params);
            let pegin_tx = pegin.sign(&operator_siggner);
            let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
            println!("pegin txid: {}", pegin_txid);
            let kickoff_tx = transaction_graph.get_kickoff_tx(&operator_siggner);
            let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
            println!("kickoff txid: {}", kickoff_txid);

            let pegin_outpoint = OutPoint {
                txid: pegin_txid,
                vout: 0,
            };
            let happy_take = transaction_graph.get_happy_take_tx(pegin_outpoint);
            let _ = TransactionGraph::get_p2sh_tx_signature(&happy_take, &transaction_graph.p2sh_signer, 0, bitcoin::EcdsaSighashType::SinglePlusAnyoneCanPay);
            let happy_take_txid = client
                .send_transaction(&happy_take)
                .expect("");
            println!("happy take txid: {}", happy_take_txid);
        }
    }

    #[test]
    fn test_p2sh_only() {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let p2sh_signer = P2SHKeypair::new(bitcoin::Network::Regtest);

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let start_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &p2sh_signer.p2sh_address);
        let another_utxo = client.prepare_utxo_for_address(params.stake_amt, &p2sh_signer.p2sh_address);

        let ins = vec![start_utxo.clone(), another_utxo.clone()];
        let outs = vec![(operator_siggner.address.script_pubkey(), another_utxo.amount - params.gas_amt), (operator_siggner.address.script_pubkey(), start_utxo.amount)];
        let mut happy_take = create_btc_tx(&ins, outs);
        let unlocking_script = TransactionGraph::get_p2sh_tx_signature(&happy_take, &p2sh_signer, 0, bitcoin::EcdsaSighashType::SinglePlusAnyoneCanPay);
        let unlocking_script1 = TransactionGraph::get_p2sh_tx_signature(&happy_take, &p2sh_signer, 1, bitcoin::EcdsaSighashType::SinglePlusAnyoneCanPay);
        println!("script_pubkey: {}", p2sh_signer.p2sh_address.script_pubkey());
        println!("script_sig: {}", unlocking_script);
        // happy_take.input[0].witness = unlocking_script;
        happy_take.input[0].script_sig = unlocking_script;
        happy_take.input[1].script_sig = unlocking_script1;
        let happy_take_txid = client
                .send_transaction(&happy_take)
                .expect("");
            println!("happy take txid: {}", happy_take_txid);
    }

    #[test]
    fn test_p2wsh_only() {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let p2sh_signer = P2SHKeypair::new(bitcoin::Network::Regtest);

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let start_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &p2sh_signer.p2wsh_address);

        let another =
            client.prepare_utxo_for_address(params.stake_amt, &p2sh_signer.p2wsh_address);


        let ins = vec![start_utxo.clone(), another.clone()];
        let outs = vec![(operator_siggner.address.script_pubkey(), start_utxo.amount + another.amount - params.gas_amt)];
        let mut happy_take = create_btc_tx(&ins, outs);
        let unlocking_script = {
            let mut sighash_cache = SighashCache::new(&happy_take);

            let sighash = sighash_cache
                .p2wsh_signature_hash(
                    0,
                    &p2sh_signer.script,
                    start_utxo.amount,
                    bitcoin::sighash::EcdsaSighashType::All,
                )
                .unwrap();
            println!("sighash: {}", sighash);

            let signature = p2sh_signer.sign_ecdsa(
                sighash,
                bitcoin::sighash::EcdsaSighashType::All,
            );
            let mut script_sig_first_part = Vec::new();
            script_sig_first_part.extend(signature.clone());
            println!("signature: {}", signature.to_hex_string(bitcoin::hex::Case::Lower));
            println!("pubkey: {}", p2sh_signer.public);


            let mut witness = Witness::new();
            witness.push(signature);
            witness.push(p2sh_signer.script.as_bytes());
            witness
        };

        let unlocking_script1 = {
            let mut sighash_cache = SighashCache::new(&happy_take);

            let sighash = sighash_cache
                .p2wsh_signature_hash(
                    1,
                    &p2sh_signer.script,
                    start_utxo.amount,
                    bitcoin::sighash::EcdsaSighashType::All,
                )
                .unwrap();
            println!("sighash: {}", sighash);

            let signature = p2sh_signer.sign_ecdsa(
                sighash,
                bitcoin::sighash::EcdsaSighashType::All,
            );
            let mut script_sig_first_part = Vec::new();
            script_sig_first_part.extend(signature.clone());
            println!("signature: {}", signature.to_hex_string(bitcoin::hex::Case::Lower));
            println!("pubkey: {}", p2sh_signer.public);


            let mut witness = Witness::new();
            witness.push(signature);
            witness.push(p2sh_signer.script.as_bytes());
            witness
        };
        println!("script_pubkey: {}", p2sh_signer.p2wsh_address.script_pubkey());
        println!("script_sig: {:?}", unlocking_script);
        happy_take.input[0].witness = unlocking_script;
        let happy_take_txid = client
                .send_transaction(&happy_take)
                .expect("");
            println!("happy take txid: {}", happy_take_txid);
    }
}
