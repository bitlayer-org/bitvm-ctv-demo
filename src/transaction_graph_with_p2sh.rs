use bitcoin::consensus::serde::hex::Upper;
use bitcoin::hex::DisplayHex;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DUP};
use bitcoincore_rpc::bitcoin::transaction;
use ctvlib::{Error, TemplateHash};
use lazy_static::lazy_static;
use std::ops::Add;
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
    build_taptree_with_script, calc_locking_script, convert_from, create_btc_tx, dummy_input,
    dummy_utxo, generate_p2a_script, P2SHKeypair, Params, SignerInfo, TaprootInfo,
};

pub struct TransactionGraph {
    kickoff: Transaction,
    kickoff_utxo: UTXO,
    happy_take: Transaction,
    unhappy_take: Transaction,
    challenge: Transaction,
    assert: Transaction,
    disprove: Transaction,
    // assert_timeout: Transaction,
    time: Transaction,
    pub p2sh_signer: P2SHKeypair,
    connector_a: TaprootInfo,
    connector_b: TaprootInfo,
    connector_c: TaprootInfo,
    connector_d: TaprootInfo,
    // taproot_info: TaprootInfo,
}

impl TransactionGraph {
    pub fn get_p2sh_tx_signature(
        tx: &Transaction,
        p2sh_signer: &P2SHKeypair,
        input_index: usize,
        sighash_type: EcdsaSighashType,
    ) -> ScriptBuf {
        let mut sighash_cache = SighashCache::new(tx);

        let sighash = sighash_cache
            .legacy_signature_hash(input_index, &p2sh_signer.script, sighash_type.to_u32())
            .unwrap();

        let signature = p2sh_signer.sign_ecdsa_legacy(sighash, sighash_type);

        Builder::new()
            .push_slice(&convert_from(signature))
            .push_slice(convert_from(p2sh_signer.script.clone().into()))
            .into_script()
    }

    // refer to https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/8
    pub fn get_improved_p2sh_tx_signature(
        tx: &Transaction,
        p2sh_signer: &P2SHKeypair,
        input_index: usize,
        sighash_type: EcdsaSighashType,
    ) -> ScriptBuf {
        let sighash_cache = SighashCache::new(tx);

        let sighash = sighash_cache
            .legacy_signature_hash(input_index, &p2sh_signer.script, sighash_type.to_u32())
            .unwrap();

        let p2sh_signer_new = P2SHKeypair::new(p2sh_signer.network.clone());

        let signature1 = p2sh_signer.sign_ecdsa_legacy(sighash, sighash_type);
        let signature2 = p2sh_signer_new.sign_ecdsa_legacy(sighash, sighash_type);
        println!("sig1: {}, sig2: {}", signature1.to_hex_string(bitcoin::hex::Case::Upper), signature2.to_hex_string(bitcoin::hex::Case::Upper));


        Builder::new()
            .push_slice(&convert_from(signature1))
            // .push_opcode(OP_DUP)
            .push_slice(&convert_from(signature2))
            .push_slice(convert_from(p2sh_signer_new.public.to_bytes()))
            .push_opcode(OP_CHECKSIG)
            .push_slice(convert_from(p2sh_signer.script.clone().into()))
            .into_script()
    }

    // only need to add fund outpoint
    pub fn create_refund_tx(
        p2sh_inputs: &Vec<UTXO>,
        fund_amount: Amount,
        target_addres: &Address,
        params: &Params,
        p2sh_signer: &P2SHKeypair,
    ) -> Transaction {
        assert!(p2sh_inputs.len() > 0);
        let mut sum_amt = fund_amount - params.dust_amt /* for first input's dust amount */;
        p2sh_inputs.iter().for_each(|utxo| sum_amt += utxo.amount);
        sum_amt -= params.gas_amt * 2;

        let dummy_fund_input = dummy_utxo(params.dust_amt);

        let mut inputs = p2sh_inputs.clone();
        inputs.insert(0, dummy_fund_input);

        let mut outputs = vec![(target_addres.script_pubkey(), params.dust_amt)];
        let per_share = sum_amt / 3;
        for _ in 0..p2sh_inputs.len() - 1 {
            outputs.push((target_addres.script_pubkey(), per_share));
            sum_amt -= per_share;
        }
        outputs.push((target_addres.script_pubkey(), sum_amt));

        let mut tx = create_btc_tx(&inputs, outputs);
        for idx in 0..p2sh_inputs.len() {
            let real_input_idx = idx + 1 /* skip the fund input */;
            tx.input[real_input_idx].script_sig = Self::get_p2sh_tx_signature(
                &tx,
                p2sh_signer,
                idx + 1,
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            );
        }

        tx
    }

    pub fn create_slash_tx(
        p2sh_input: UTXO,
        fund_amount: Amount,
        burn: &Address,
        params: &Params,
    ) -> Transaction {
        let first_amt = p2sh_input.amount + fund_amount - params.gas_amt - params.reward_amt;
        let p2a_script = generate_p2a_script();
        let second_amt = params.reward_amt;
        let outputs = vec![(burn.script_pubkey(), first_amt), (p2a_script, second_amt)];
        let fund_dummy_input = dummy_utxo(fund_amount);
        create_btc_tx(&vec![p2sh_input, fund_dummy_input], outputs)
    }

    pub fn new(operator: &Address, params: &Params, kickoff_utxo: UTXO, stake_utxo: UTXO) -> Self {
        // TODO, maybe we need multiple p2sh key?
        // keys
        let temp_key = P2SHKeypair::new(Network::Regtest);
        let operator_presign_key = SignerInfo::new(Network::Regtest);

        let burn_signer = SignerInfo::new(Network::Regtest);

        // connectors
        let connector_b = {
            build_taptree_with_script(
                vec![operator.script_pubkey(), operator.script_pubkey()],
                Network::Regtest,
            )
            .expect("build success")
        };

        let connector_c = {
            build_taptree_with_script(
                vec![
                    operator.script_pubkey(),
                    operator.script_pubkey(),
                    operator.script_pubkey(),
                ],
                Network::Regtest,
            )
            .expect("build success")
        };

        let connector_d = {
            build_taptree_with_script(
                vec![
                    temp_key.p2sh_address.script_pubkey(),
                    temp_key.p2sh_address.script_pubkey(),
                ],
                Network::Regtest,
            )
            .expect("build success")
        };

        // kickoff
        let mut kickoff_outputs = vec![
            (temp_key.p2sh_address.script_pubkey(), params.dust_amt),
            (temp_key.p2sh_address.script_pubkey(), params.dust_amt),
            (
                temp_key.p2sh_address.script_pubkey(),
                params.dust_amt + params.gas_amt,
            ),
            // (connector_b.address.script_pubkey(), params.dust_amt),
            // (connector_c.address.script_pubkey(), params.dust_amt),
        ];
        let kickoff = create_btc_tx(&vec![kickoff_utxo.clone()], kickoff_outputs.clone());

        let kickoff_txid = kickoff.txid();
        let mut happy_take_inputs = vec![];
        for idx in 0..3 {
            happy_take_inputs.push(UTXO {
                outpoint: OutPoint {
                    txid: kickoff_txid,
                    vout: idx,
                },
                amount: kickoff_outputs[idx as usize].1,
            });
        }
        // dummy happy take
        let happy_take = Self::create_refund_tx(
            &happy_take_inputs,
            params.depoist_amt - params.gas_amt,
            operator,
            params,
            &temp_key,
        );

        let mut challenge = {
            let ins = vec![UTXO {
                outpoint: OutPoint {
                    txid: kickoff_txid,
                    vout: 1,
                },
                amount: params.dust_amt,
            }];
            create_btc_tx(&ins, vec![(operator.script_pubkey(), params.crowd_amt)])
        };

        let challenge_script_sig = Self::get_p2sh_tx_signature(
            &challenge,
            &temp_key,
            0,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        );
        challenge.input[0].script_sig = challenge_script_sig;

        let assert_input_amt = kickoff.output[2].value;
        let mut assert = {
            let ins = vec![UTXO {
                outpoint: OutPoint {
                    txid: kickoff_txid,
                    vout: 2,
                },
                amount: assert_input_amt,
            }];
            create_btc_tx(
                &ins,
                vec![
                    (temp_key.p2sh_address.script_pubkey(), params.dust_amt),
                    (temp_key.p2sh_address.script_pubkey(), params.dust_amt),
                ],
            )
        };

        let assert_script_sig =
            Self::get_p2sh_tx_signature(&assert, &temp_key, 0, EcdsaSighashType::All);
        assert.input[0].script_sig = assert_script_sig;

        let p2sh_inputs = (0..2)
            .map(|idx| UTXO {
                outpoint: OutPoint {
                    txid: assert.txid(),
                    vout: idx,
                },
                amount: assert.output[idx as usize].value,
            })
            .collect();

        let unhappy_take = Self::create_refund_tx(
            &p2sh_inputs,
            params.depoist_amt - params.gas_amt,
            operator,
            params,
            &temp_key,
        );

        let disprove_p2sh_input = UTXO {
            outpoint: OutPoint {
                txid: assert.txid(),
                vout: 1,
            },
            amount: assert.output[1].value,
        };
        let mut disprove = Self::create_slash_tx(
            disprove_p2sh_input,
            stake_utxo.amount - params.gas_amt,
            &burn_signer.address,
            params,
        );
        let disprove_script_sig = Self::get_p2sh_tx_signature(
            &disprove,
            &temp_key,
            0,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        );

        disprove.input[0].script_sig = disprove_script_sig;

        let time = {
            let locking_script =
                calc_locking_script(disprove.template_hash(1).expect("msg")).expect("msg");
            create_btc_tx(
                &vec![stake_utxo.clone()],
                vec![(locking_script, stake_utxo.amount - params.gas_amt)],
            )
        };
        disprove.input[1].previous_output = OutPoint {
            txid: time.txid(),
            vout: 0,
        };

        let connector_a = {
            let happy_take_ctv_hash = happy_take.template_hash(0).expect("");
            let unhappy_take_ctv_hash = unhappy_take.template_hash(0).expect("");
            let happy_take_script = calc_locking_script(happy_take_ctv_hash).expect("");
            let unhappy_take_script = calc_locking_script(unhappy_take_ctv_hash).expect("");
            build_taptree_with_script(
                vec![happy_take_script, unhappy_take_script],
                Network::Regtest,
            )
            .expect("build success")
        };

        Self {
            p2sh_signer: temp_key,
            kickoff,
            kickoff_utxo,
            happy_take,
            challenge,
            assert,
            unhappy_take,
            disprove,
            time,
            connector_a,
            connector_b,
            connector_c,
            connector_d, // disprove,
                         // taproot_info
        }
    }

    pub fn get_first_script(&self) -> ScriptBuf {
        self.connector_a.address.script_pubkey()
    }

    fn calc_p2wpkh_witness(
        target_amt: Amount,
        transaction: &Transaction,
        input_idx: usize,
        signer: &SignerInfo,
        sighash_type: EcdsaSighashType,
    ) -> Witness {
        let mut sighash_cache = SighashCache::new(transaction);
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                input_idx,
                &signer.address.script_pubkey(),
                target_amt,
                sighash_type,
            )
            .unwrap();

        let signature = signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(signer.get_pk());

        witness
    }
    pub fn get_kickoff_tx(&self, signer: &SignerInfo) -> Transaction {
        let mut tx = self.kickoff.clone();

        let utxos = vec![self.kickoff_utxo.clone()];

        let witness =
            Self::calc_p2wpkh_witness(utxos[0].amount, &tx, 0, signer, EcdsaSighashType::All);
        tx.input[0].witness = witness;

        tx
    }

    pub fn get_happy_take_tx(&self, pegin_outpoint: OutPoint) -> Transaction {
        let mut tx = self.happy_take.clone();
        tx.input[0].previous_output = pegin_outpoint;

        let happy_take_script = self.connector_a.scripts[0].clone();
        let tsi = self.connector_a.clone();
        let cb = tsi
            .taproot_spend_info
            .control_block(&(happy_take_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| Error::UnknownError("Taproot construction error".into()))
            .expect("get control block");
        tx.input[0].witness.push(happy_take_script);
        tx.input[0].witness.push(cb.serialize());
        tx
    }

    pub fn get_challenge_tx(
        &self,
        crowd_utxo: UTXO,
        params: &Params,
        crowd_signer: &SignerInfo,
    ) -> Transaction {
        assert!(crowd_utxo.amount >= params.crowd_amt + params.gas_amt);
        let mut tx = self.challenge.clone();
        let mut crowd_input = dummy_input();
        crowd_input.previous_output = crowd_utxo.outpoint;
        tx.input.push(crowd_input);

        let witness = Self::calc_p2wpkh_witness(
            crowd_utxo.amount,
            &tx,
            1,
            crowd_signer,
            EcdsaSighashType::All,
        );
        tx.input[1].witness = witness;

        tx
    }

    pub fn get_assert_tx(&self, kickoff_utxo: UTXO) -> Transaction {
        let mut tx = self.assert.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        tx
    }

    pub fn get_unhappy_tx(&self, pegin_outpoint: OutPoint) -> Transaction {
        let mut tx = self.unhappy_take.clone();
        tx.input[0].previous_output = pegin_outpoint;

        let unhappy_take_script = self.connector_a.scripts[1].clone();
        let tsi = self.connector_a.clone();
        let cb = tsi
            .taproot_spend_info
            .control_block(&(unhappy_take_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| Error::UnknownError("Taproot construction error".into()))
            .expect("get control block");
        tx.input[0].witness.push(unhappy_take_script);
        tx.input[0].witness.push(cb.serialize());

        tx
    }

    pub fn get_disprove_tx(&self) -> Transaction {
        let tx = self.disprove.clone();
        tx
    }

    pub fn get_time_tx(&self, signer_info: &SignerInfo, target_amt: Amount) -> Transaction {
        let mut tx = self.time.clone();
        let witness =
            Self::calc_p2wpkh_witness(target_amt, &tx, 0, signer_info, EcdsaSighashType::All);
        tx.input[0].witness = witness;

        tx
    }
}

mod test {
    use std::{fs::create_dir, os::unix::net};

    use bitcoin::{
        consensus::serde::hex::Upper,
        hex::DisplayHex,
        key,
        opcodes::{
            all::{OP_2DROP, OP_CHECKSIG},
            OP_0, OP_TRUE,
        },
        script::Builder,
        sighash::SighashCache,
        Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, Witness,
    };
    use ctvlib::TemplateHash;
    use local_ip_address::local_ip;
    use secp256k1::Secp256k1;

    use crate::{
        bitcoin_sdk::{RPCClient, UTXO},
        common::{
            calc_locking_script, convert_from, create_btc_tx, dummy_utxo, P2SHKeypair, Params,
            Pegin, SignerInfo,
        },
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

            let kickoff_utxo = client.prepare_utxo_for_address(
                params.dust_amt * 3 + params.gas_amt * 2,
                &operator_siggner.address,
            );

            let stake_utxo =
                client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);

            let transaction_graph =
                TransactionGraph::new(&operator_siggner.address, &params, kickoff_utxo, stake_utxo);
            let first_script = transaction_graph.get_first_script();
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
            let happy_take_txid = client.send_transaction(&happy_take).expect("");
            println!("happy take txid: {}", happy_take_txid);
        }

        // unhappytake: pegin -> kickoff->challenge->assert->unhappytake
        println!("unhappy path");
        {
            let params = Params::default();
            let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);

            let url = format!("{}:18443", local_ip().expect("find one").to_string());
            let user = "admin".to_string();
            let password = "admin".to_string();

            let client = RPCClient::new(&url, &user, &password);

            let kickoff_utxo = client.prepare_utxo_for_address(
                params.dust_amt * 3 + params.gas_amt * 2, /* kickoff, assert */
                &operator_siggner.address,
            );

            let stake_utxo =
                client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
            let transaction_graph =
                TransactionGraph::new(&operator_siggner.address, &params, kickoff_utxo, stake_utxo);
            let first_script = transaction_graph.get_first_script();
            let utxo =
                client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
            let pegin = Pegin::new(utxo.outpoint, utxo.amount, first_script, &params);
            let pegin_tx = pegin.sign(&operator_siggner);
            let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
            println!("pegin txid: {}", pegin_txid);
            let kickoff_tx = transaction_graph.get_kickoff_tx(&operator_siggner);
            let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
            println!("kickoff txid: {}", kickoff_txid);

            let crowd_signer = &SignerInfo::new(bitcoin::Network::Regtest);
            let crowd_utxo = client
                .prepare_utxo_for_address(params.crowd_amt + params.gas_amt, &crowd_signer.address);
            let challenge = transaction_graph.get_challenge_tx(crowd_utxo, &params, crowd_signer);
            let challenge_txid = client.send_transaction(&challenge).expect("msg");
            println!("challenge txid: {}", challenge_txid);

            let assert_input_utxo = UTXO {
                outpoint: OutPoint {
                    txid: kickoff_txid,
                    vout: 2,
                },
                amount: kickoff_tx.output[2].value,
            };
            let assert = transaction_graph.get_assert_tx(assert_input_utxo);
            let assert_txid = client.send_transaction(&assert).expect("msg");
            println!("assert txid: {}", assert_txid);

            let pegin_outpoint = OutPoint {
                txid: pegin_txid,
                vout: 0,
            };
            let unhappy_take = transaction_graph.get_unhappy_tx(pegin_outpoint);
            let unhappy_take_txid = client.send_transaction(&unhappy_take).expect("");
            println!("unhappy take txid: {}", unhappy_take_txid);
        }

        // disprove path: pegin -> kickoff->challenge->assert->time->disprove
        println!("disprove path");
        {
            let params = Params::default();
            let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);

            let url = format!("{}:18443", local_ip().expect("find one").to_string());
            let user = "admin".to_string();
            let password = "admin".to_string();

            let client = RPCClient::new(&url, &user, &password);

            let kickoff_utxo = client.prepare_utxo_for_address(
                params.dust_amt * 3 + params.gas_amt * 2, /* kickoff, assert */
                &operator_siggner.address,
            );

            let stake_utxo =
                client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
            let transaction_graph = TransactionGraph::new(
                &operator_siggner.address,
                &params,
                kickoff_utxo,
                stake_utxo.clone(),
            );
            let first_script = transaction_graph.get_first_script();
            let utxo =
                client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
            let pegin = Pegin::new(utxo.outpoint, utxo.amount, first_script, &params);
            let pegin_tx = pegin.sign(&operator_siggner);
            let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
            println!("pegin txid: {}", pegin_txid);
            let kickoff_tx = transaction_graph.get_kickoff_tx(&operator_siggner);
            let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
            println!("kickoff txid: {}", kickoff_txid);

            let crowd_signer = &SignerInfo::new(bitcoin::Network::Regtest);
            let crowd_utxo = client
                .prepare_utxo_for_address(params.crowd_amt + params.gas_amt, &crowd_signer.address);
            let challenge = transaction_graph.get_challenge_tx(crowd_utxo, &params, crowd_signer);
            let challenge_txid = client.send_transaction(&challenge).expect("msg");
            println!("challenge txid: {}", challenge_txid);

            let assert_input_utxo = UTXO {
                outpoint: OutPoint {
                    txid: kickoff_txid,
                    vout: 2,
                },
                amount: kickoff_tx.output[2].value,
            };
            let assert = transaction_graph.get_assert_tx(assert_input_utxo);
            let assert_txid = client.send_transaction(&assert).expect("msg");
            println!("assert txid: {}", assert_txid);

            let time = transaction_graph.get_time_tx(&operator_siggner, stake_utxo.amount);
            let time_txid = client.send_transaction(&time).expect("msg");
            println!("time txid: {}", time_txid);

            let disprove = transaction_graph.get_disprove_tx();
            let disprove_txid = client.send_transaction(&disprove).expect("");
            println!("diprove txid: {}", disprove_txid);
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
        let another_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &p2sh_signer.p2sh_address);

        let ins = vec![start_utxo.clone(), another_utxo.clone()];
        let outs = vec![
            (
                operator_siggner.address.script_pubkey(),
                another_utxo.amount - params.gas_amt,
            ),
            (operator_siggner.address.script_pubkey(), start_utxo.amount),
        ];
        let mut happy_take = create_btc_tx(&ins, outs);
        let unlocking_script = TransactionGraph::get_p2sh_tx_signature(
            &happy_take,
            &p2sh_signer,
            0,
            bitcoin::EcdsaSighashType::SinglePlusAnyoneCanPay,
        );
        let unlocking_script1 = TransactionGraph::get_p2sh_tx_signature(
            &happy_take,
            &p2sh_signer,
            1,
            bitcoin::EcdsaSighashType::SinglePlusAnyoneCanPay,
        );
        println!(
            "script_pubkey: {}",
            p2sh_signer.p2sh_address.script_pubkey()
        );
        println!("script_sig: {}", unlocking_script);
        // happy_take.input[0].witness = unlocking_script;
        happy_take.input[0].script_sig = unlocking_script;
        happy_take.input[1].script_sig = unlocking_script1;
        let happy_take_txid = client.send_transaction(&happy_take).expect("");
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

        let another = client.prepare_utxo_for_address(params.stake_amt, &p2sh_signer.p2wsh_address);

        let ins = vec![start_utxo.clone(), another.clone()];
        let outs = vec![(
            operator_siggner.address.script_pubkey(),
            start_utxo.amount + another.amount - params.gas_amt,
        )];
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

            let signature =
                p2sh_signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
            let mut script_sig_first_part = Vec::new();
            script_sig_first_part.extend(signature.clone());
            println!(
                "signature: {}",
                signature.to_hex_string(bitcoin::hex::Case::Lower)
            );
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

            let signature =
                p2sh_signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
            let mut script_sig_first_part = Vec::new();
            script_sig_first_part.extend(signature.clone());
            println!(
                "signature: {}",
                signature.to_hex_string(bitcoin::hex::Case::Lower)
            );
            println!("pubkey: {}", p2sh_signer.public);

            let mut witness = Witness::new();
            witness.push(signature);
            witness.push(p2sh_signer.script.as_bytes());
            witness
        };
        println!(
            "script_pubkey: {}",
            p2sh_signer.p2wsh_address.script_pubkey()
        );
        println!("script_sig: {:?}", unlocking_script);
        happy_take.input[0].witness = unlocking_script;
        let happy_take_txid = client.send_transaction(&happy_take).expect("");
        println!("happy take txid: {}", happy_take_txid);
    }

    #[test]
    pub fn test_broken_case_of_p2sh() {
        let network = Network::Regtest;
        let params = Params::default();
        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);

        // refer to this case: https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/8
        let utxo_b_key = P2SHKeypair::new(network);
        let utxo_b = client.prepare_utxo_for_address(params.depoist_amt, &utxo_b_key.p2sh_address);

        let temp_signer = SignerInfo::new(network);
        let temp_utxo = client.prepare_utxo_for_address(params.depoist_amt + params.depoist_amt, &temp_signer.address);
        let utxo_c_script = Builder::new()
            .push_opcode(OP_2DROP)
            .push_opcode(OP_TRUE)
            .into_script();
        let mut utxo_c_tx = create_btc_tx(
            &vec![temp_utxo.clone()],
            vec![(utxo_c_script, params.depoist_amt - params.gas_amt), (temp_signer.address.script_pubkey(), params.depoist_amt)],
        );
        let witness = TransactionGraph::calc_p2wpkh_witness(
            temp_utxo.amount,
            &utxo_c_tx,
            0,
            &temp_signer,
            EcdsaSighashType::All,
        );
        utxo_c_tx.input[0].witness = witness;
        let utxo_c_txid = client.send_transaction(&utxo_c_tx).unwrap();
        let utxo_c = UTXO {
            outpoint: OutPoint {
                txid: utxo_c_txid,
                vout: 0,
            },
            amount: utxo_c_tx.output[0].value,
        };

        let ins = vec![dummy_utxo(Amount::ZERO), utxo_b.clone()];
        let outs = vec![
            (
                utxo_b_key.p2wsh_address.script_pubkey(),
                params.depoist_amt - params.gas_amt - params.gas_amt - params.gas_amt,
            ),
            (
                utxo_b_key.p2wsh_address.script_pubkey(),
                params.depoist_amt,
            ),
        ];
        let mut temp_target_tx = create_btc_tx(&ins, outs);
        let unlocking_script_sig = TransactionGraph::get_p2sh_tx_signature(
            &temp_target_tx,
            &utxo_b_key,
            1,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        );
        temp_target_tx.input[1].script_sig = unlocking_script_sig;
        let ctv_hash = temp_target_tx.template_hash(0).unwrap();
        let ctv_locking_script = calc_locking_script(ctv_hash).unwrap();

        let temp_signer = SignerInfo::new(network);
        let temp_utxo = client.prepare_utxo_for_address(params.depoist_amt, &temp_signer.address);

        let mut utxo_a_tx = create_btc_tx(
            &vec![temp_utxo.clone()],
            vec![(ctv_locking_script, params.depoist_amt - params.gas_amt)],
        );
        let witness = TransactionGraph::calc_p2wpkh_witness(
            temp_utxo.amount,
            &utxo_a_tx,
            0,
            &temp_signer,
            EcdsaSighashType::All,
        );
        utxo_a_tx.input[0].witness = witness;
        let utxo_a_txid = client.send_transaction(&utxo_a_tx).unwrap();
        let utxo_a = UTXO {
            outpoint: OutPoint {
                txid: utxo_a_txid,
                vout: 0,
            },
            amount: utxo_a_tx.output[0].value,
        };

        // using utxo_a and utxo_c(it is expected to be utxo_b)
        temp_target_tx.input[0].previous_output = utxo_a.outpoint;
        temp_target_tx.input[1].previous_output = utxo_c.outpoint;

        // it works! we can use utxo_c instead of utxo_b, but utxo_c is an non-standard tx.
        client.send_transaction(&temp_target_tx).unwrap();
    }

    #[test]
    pub fn test_improved_case_of_p2sh() {
        let network = Network::Regtest;
        let params = Params::default();
        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);

        // refer to this case: https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/8
        let utxo_b_key = P2SHKeypair::new(network);
        let utxo_b = client.prepare_utxo_for_address(params.depoist_amt, &utxo_b_key.p2sh_address);

        let temp_signer = SignerInfo::new(network);
        let temp_utxo = client.prepare_utxo_for_address(params.depoist_amt + params.depoist_amt, &temp_signer.address);
        let utxo_c_script = Builder::new()
            .push_opcode(OP_2DROP)
            .push_opcode(OP_TRUE)
            .into_script();
        let mut utxo_c_tx = create_btc_tx(
            &vec![temp_utxo.clone()],
            vec![(utxo_c_script, params.depoist_amt - params.gas_amt), (temp_signer.address.script_pubkey(), params.depoist_amt)],
        );
        let witness = TransactionGraph::calc_p2wpkh_witness(
            temp_utxo.amount,
            &utxo_c_tx,
            0,
            &temp_signer,
            EcdsaSighashType::All,
        );
        utxo_c_tx.input[0].witness = witness;
        let utxo_c_txid = client.send_transaction(&utxo_c_tx).unwrap();
        let utxo_c = UTXO {
            outpoint: OutPoint {
                txid: utxo_c_txid,
                vout: 0,
            },
            amount: utxo_c_tx.output[0].value,
        };

        let ins = vec![dummy_utxo(Amount::ZERO), utxo_b.clone()];
        let outs = vec![
            (
                utxo_b_key.p2wsh_address.script_pubkey(),
                params.depoist_amt - params.gas_amt - params.gas_amt - params.gas_amt,
            ),
            (
                utxo_b_key.p2wsh_address.script_pubkey(),
                params.depoist_amt,
            ),
        ];
        let mut temp_target_tx = create_btc_tx(&ins, outs);
        // use a new way to unlock the utxo_b
        let unlocking_script_sig = TransactionGraph::get_improved_p2sh_tx_signature(
            &temp_target_tx,
            &utxo_b_key,
            1,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        );
        temp_target_tx.input[1].script_sig = unlocking_script_sig;
        let ctv_hash = temp_target_tx.template_hash(0).unwrap();
        let ctv_locking_script = calc_locking_script(ctv_hash).unwrap();

        let temp_signer = SignerInfo::new(network);
        let temp_utxo = client.prepare_utxo_for_address(params.depoist_amt, &temp_signer.address);

        let mut utxo_a_tx = create_btc_tx(
            &vec![temp_utxo.clone()],
            vec![(ctv_locking_script, params.depoist_amt - params.gas_amt)],
        );
        let witness = TransactionGraph::calc_p2wpkh_witness(
            temp_utxo.amount,
            &utxo_a_tx,
            0,
            &temp_signer,
            EcdsaSighashType::All,
        );
        utxo_a_tx.input[0].witness = witness;
        let utxo_a_txid = client.send_transaction(&utxo_a_tx).unwrap();
        let utxo_a = UTXO {
            outpoint: OutPoint {
                txid: utxo_a_txid,
                vout: 0,
            },
            amount: utxo_a_tx.output[0].value,
        };

        // using utxo_a and utxo_c(it is expected to be utxo_b)
        temp_target_tx.input[0].previous_output = utxo_a.outpoint;
        temp_target_tx.input[1].previous_output = utxo_b.outpoint;

        // it works! we can use utxo_c instead of utxo_b, but utxo_c is an non-standard tx.
        client.send_transaction(&temp_target_tx).unwrap();
    }
}
