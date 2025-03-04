use bitcoin::{Network, OutPoint};
use bitcoin_sdk::{RPCClient, UTXO};
use local_ip_address::local_ip;
use transaction_graph::{Params, Pegin, SignerInfo, TransactionGraph};

pub mod bitcoin_sdk;
pub mod transaction_graph;
fn main() {
    // happy path: pegin -> kickoff -> happytake
    println!("=======happy path: pegin -> kickoff -> happytake=========================");
    {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let transaction_graph = TransactionGraph::new(&operator_siggner.address, &params);
        let kickoff_script = transaction_graph
            .get_first_script()
            .expect("get first script");

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let params = Params::default();
        let utxo = client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
        let pegin = Pegin::new(utxo.outpoint, utxo.amount, kickoff_script, &params);
        let pegin_tx = pegin.sign(&operator_siggner);
        let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
        println!("pegin txid: {}", pegin_txid);
        let pegin_utxo = UTXO {
            outpoint: OutPoint {
                txid: pegin_txid,
                vout: 0,
            },
            amount: pegin_tx.output[0].value,
        };
        let stake_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
        let kickoff_tx =
            transaction_graph.get_kickoff_tx(pegin_utxo, stake_utxo, &operator_siggner);
        let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
        println!("kickoff txid: {}", kickoff_txid);
        let kickoff_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_txid,
                vout: 0,
            },
            amount: kickoff_tx.output[0].value,
        };

        let happy_take_txid = client
            .send_transaction(&transaction_graph.get_happy_take_tx(kickoff_utxo))
            .expect("");
        println!("happy take txid: {}", happy_take_txid);
    }

    // 
    println!("=======pegin -> kickoff -> challenge -> assert -> disprove+reward========");
    {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let transaction_graph = TransactionGraph::new(&operator_siggner.address, &params);
        let kickoff_script = transaction_graph
            .get_first_script()
            .expect("get first script");

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let params = Params::default();
        let utxo = client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
        let pegin = Pegin::new(utxo.outpoint, utxo.amount, kickoff_script, &params);
        let pegin_tx = pegin.sign(&operator_siggner);
        let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
        println!("pegin txid: {}", pegin_txid);
        let pegin_utxo = UTXO {
            outpoint: OutPoint {
                txid: pegin_txid,
                vout: 0,
            },
            amount: pegin_tx.output[0].value,
        };
        let stake_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
        let kickoff_tx =
            transaction_graph.get_kickoff_tx(pegin_utxo, stake_utxo, &operator_siggner);
        let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
        println!("kickoff txid: {}", kickoff_txid);
        let kickoff_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_txid,
                vout: 0,
            },
            amount: kickoff_tx.output[0].value,
        };

        let challenge_tx = transaction_graph.get_challenge_tx(kickoff_utxo);
        let challenge_txid = client.send_transaction(&challenge_tx).expect("");
        println!("challenge txid: {}", challenge_txid);

        let challenge_utxo = UTXO {
            outpoint: OutPoint {
                txid: challenge_txid,
                vout: 0,
            },
            amount: challenge_tx.output[0].value,
        };
        let assert_tx = &transaction_graph.get_assert_tx(challenge_utxo);
        let assert_txid = client.send_transaction(&assert_tx).expect("");
        println!("assert txid: {}", assert_txid);

        let assert_utxo = UTXO {
            outpoint: OutPoint {
                txid: assert_txid,
                vout: 0,
            },
            amount: assert_tx.output[0].value,
        };

        let receiver = SignerInfo::new(Network::Regtest);
        let (disprove_tx, reward_tx) = transaction_graph.get_disprove_tx(assert_utxo, &receiver);
        let disprove_txid = client.send_transaction(&disprove_tx).expect("");
        println!("disprove txid: {}", disprove_txid);

        let reward_txid = client.send_transaction(&reward_tx).expect("");
        println!(
            "reward txid: {}, amt: {}",
            reward_txid, reward_tx.output[0].value
        );
    }
}
