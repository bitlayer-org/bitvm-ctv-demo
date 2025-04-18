use std::{ops::Add, str::FromStr};

use bitcoin::{
    hashes::{ripemd160, sha256, Hash}, key, opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_NOP4}, script::{Builder, PushBytesBuf}, sighash::SighashCache, taproot::{TaprootBuilder, TaprootSpendInfo}, transaction::Version, Address, Amount, EcdsaSighashType, LegacySighash, Network, OutPoint, PrivateKey, PublicKey, Script, ScriptBuf, SegwitV0Sighash, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey
};
use ctvlib::Error;
use lazy_static::lazy_static;
use secp256k1::{
    rand::{self},
    All, Keypair, Message, Secp256k1, SecretKey, SECP256K1,
};
use serde::Serialize;

use crate::bitcoin_sdk::UTXO;

pub struct Params {
    pub depoist_amt: Amount,
    pub stake_amt: Amount,
    pub gas_amt: Amount,
    pub dust_amt: Amount,
    pub reward_amt: Amount,
    pub crowd_amt: Amount,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            depoist_amt: Amount::from_btc(2.0).expect(""),
            stake_amt: Amount::from_btc(1.0).expect(""),
            gas_amt: Amount::from_sat(1500),
            dust_amt: Amount::from_sat(556),
            reward_amt: Amount::from_btc(0.5).expect(""),
            crowd_amt: Amount::from_btc(1.0).expect("")
        }
    }
}

lazy_static! {
    pub static ref UNSPENDABLE_TAPROOT_PUBLIC_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51"
    )
    .unwrap();
}

#[derive(Clone)]
pub struct TaprootInfo {
    pub address: Address,
    pub scripts: Vec<ScriptBuf>,
    pub taproot_spend_info: TaprootSpendInfo,
}

pub fn build_taptree_with_script(
    scripts: Vec<ScriptBuf>,
    network: Network,
) -> Result<TaprootInfo, Error> {
    let n = scripts.len();
    let taproot_builder = if n > 1 {
        let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
        let k = 2_usize.pow(m.into()) - n;
        (0..n).fold(TaprootBuilder::new(), |acc, i| {
            acc.add_leaf(m - ((i >= n - k) as u8), scripts[i].clone())
                .unwrap()
        })
    } else {
        TaprootBuilder::new()
            .add_leaf(0, scripts[0].clone())
            .unwrap()
    };
    let taproot_spend_info = taproot_builder
        .finalize(SECP256K1, *UNSPENDABLE_TAPROOT_PUBLIC_KEY)
        .expect("msg");

    let secp: Secp256k1<All> = Secp256k1::new();
    let address = Address::p2tr(
        &secp,
        *UNSPENDABLE_TAPROOT_PUBLIC_KEY,
        taproot_spend_info.merkle_root(),
        network,
    );

    Ok(TaprootInfo {
        address: address.clone(),
        scripts,
        taproot_spend_info,
    })
}

pub fn generate_p2a_script() -> ScriptBuf {
    ScriptBuf::from_hex("51024e73")
                    .expect("statically valid script")
}

pub struct P2SHKeypair {
    secp: Secp256k1<All>,
    secret_key: SecretKey,
    private: key::PrivateKey,
    pub public: key::PublicKey,
    pub script: ScriptBuf,
    pub p2wsh_address: Address,
    pub p2sh_address: Address,
    pub network: Network,
}
impl P2SHKeypair {
    pub fn new(network: Network) -> P2SHKeypair {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let private = key::PrivateKey {
            compressed: true,
            inner: secret_key,
            network: network,
        };
        let public = private.public_key(&secp);
            
        let script = Builder::new()
            .push_slice(convert_from(public.to_bytes()))
            .push_opcode(OP_CHECKSIGVERIFY)
            .into_script();

        let p2wsh_address = Address::p2wsh(&script, network);
        let p2sh_address = Address::p2sh(&script, network).expect("find");

        return P2SHKeypair {
            secp,
            secret_key,
            private,
            public,
            script,
            p2wsh_address,
            p2sh_address,
            network
        };
    }

    pub fn sign_ecdsa(&self, hash: SegwitV0Sighash, sign_type: EcdsaSighashType) -> Vec<u8> {
        let msg = Message::from_digest_slice(&hash[..]).expect("should be SegwitV0Sighash");
        let signature = self.secp.sign_ecdsa(&msg, &self.secret_key);
        println!("real signature: {}", signature);
        let mut vec = signature.serialize_der().to_vec();
        vec.push(sign_type.to_u32() as u8);
        vec
    }

    pub fn sign_ecdsa_legacy(&self, hash: LegacySighash, sign_type: EcdsaSighashType) -> Vec<u8> {
        let msg = Message::from_digest_slice(&hash[..]).expect("should be SegwitV0Sighash");
        let signature = self.secp.sign_ecdsa(&msg, &self.secret_key);
        let mut vec = signature.serialize_der().to_vec();
        vec.push(sign_type.to_u32() as u8);
        vec
    }
}

#[derive(Clone)]
pub struct SignerInfo {
    pub secp: Secp256k1<All>,
    pub pk: PublicKey,
    pub sk: SecretKey,
    pub keypair: Keypair,
    pub address: Address,
    pub xonly_pk: XOnlyPublicKey,
}

impl SignerInfo {
    fn generate_signer_info(
        sk: SecretKey,
        secp: Secp256k1<All>,
        network: bitcoin::Network,
    ) -> Self {
        let private_key = PrivateKey::new(sk, network);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly_pk, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey = PublicKey::from_private_key(&secp, &private_key);

        let address = Address::p2wpkh(&pubkey, network).expect("msg");

        SignerInfo {
            pk: private_key.public_key(&secp),
            secp,
            sk,
            keypair,
            address,
            xonly_pk,
        }
    }
    pub fn new(network: bitcoin::Network) -> Self {
        let secp: Secp256k1<All> = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());

        Self::generate_signer_info(sk, secp, network)
    }

    pub fn get_pk(&self) -> Vec<u8> {
        self.pk.to_bytes().clone()
    }

    pub fn get_raw_pk(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn sign_ecdsa(&self, hash: SegwitV0Sighash, sign_type: EcdsaSighashType) -> Vec<u8> {
        let msg = Message::from_digest_slice(&hash[..]).expect("should be SegwitV0Sighash");
        let signature = self.secp.sign_ecdsa(&msg, &self.sk);
        let mut vec = signature.serialize_der().to_vec();
        vec.push(sign_type.to_u32() as u8);
        vec
    }

    

}

pub struct Pegin {
    previous_output: OutPoint,
    amt: Amount,

    pegin: Transaction,
}

impl Pegin {
    pub fn new(
        previous_output: OutPoint,
        amt: Amount,
        first_script: ScriptBuf,
        params: &Params,
    ) -> Self {
        let input = TxIn {
            previous_output: previous_output.clone(),
            sequence: bitcoin::Sequence(0xFFFFFFFF),
            script_sig: Builder::new().into_script(),
            witness: Witness::new(),
        };
        let output = TxOut {
            script_pubkey: first_script,
            value: amt - params.gas_amt,
        };
        let pegin = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![input.clone()], // it should be modified on demand
            output: vec![output],
        };

        Self {
            previous_output,
            amt,
            pegin,
        }
    }

    pub fn sign(&self, signer: &SignerInfo) -> Transaction {
        let mut tx = self.pegin.clone();
        let mut sighash_cache = SighashCache::new(&tx);
        let input_index = 0 as usize;
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                input_index,
                &signer.address.script_pubkey(),
                self.amt,
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap();

        let signature = signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(signer.get_pk());

        tx.input[input_index].witness = witness;
        tx
    }
}

pub fn dummy_utxo(amount: Amount) -> UTXO {
    UTXO {
        outpoint: OutPoint {
            txid: Txid::from_str(
                "defc8c2634291f74cf42dc16508b091d4a1ce1fb27f5a6861fe922e42a3c898b",
            )
            .expect(""),
            vout: 0,
        },
        amount,
    }
}

pub fn dummy_input() -> TxIn {
    TxIn {
        previous_output: dummy_utxo(Amount::ZERO).outpoint,
        sequence: bitcoin::Sequence(0xFFFFFFFF),
        script_sig: Builder::new().into_script(),
        witness: Witness::new(),
    }
}

pub fn create_btc_tx(ins: &Vec<UTXO>, outs: Vec<(ScriptBuf, Amount)>) -> Transaction {
    let input = ins
        .into_iter()
        .map(|i| TxIn {
            previous_output: i.outpoint,
            sequence: bitcoin::Sequence(0xFFFFFFFF),
            script_sig: Builder::new().into_script(),
            witness: Witness::new(),
        })
        .collect();

    let output = outs
        .into_iter()
        .map(|o| TxOut {
            script_pubkey: o.0,
            value: o.1,
        })
        .collect();

    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input,
        output,
    }
}

pub fn calc_locking_script(tmplhash: Vec<u8>) -> Result<ScriptBuf, Error> {
    Ok(bitcoin::script::Builder::new()
        .push_slice(convert_from(tmplhash))
        // OP_NOP4 is OP_CTV actually, you can find here: https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
        .push_opcode(OP_NOP4)
        .into_script())
}

pub fn convert_from(preimage: Vec<u8>) -> PushBytesBuf {
    let mut pbf = PushBytesBuf::new();
    pbf.extend_from_slice(&preimage).expect("convert failed");
    pbf
}
