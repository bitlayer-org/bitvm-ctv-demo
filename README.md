# bitvm-ctv-demo
step1: Download and install [Bitcoin0.28](https://github.com/bitcoin-inquisition/bitcoin). which supports OP_CTV.

step2: Start Bitcoin using the script: `scripts/start_btc_local_testnet.sh`. Ensure that the path to bitcoind (installed in Step 1) is correct in this script.

step3: Run `cargo run` in the project root directory.

a write-up about this demo: https://hackmd.io/@MarkYnx/Sk6mmVrsJl

wip: OP_CTV with P2SH trick test: cargo test --package bitvm-ctv-demo --bin bitvm-ctv-demo -- transaction_graph_with_p2sh::test::test_transaction_graph --exact --show-output 