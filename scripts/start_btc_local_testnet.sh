#!/bin/bash
rm -rf  /Users/dash/Library/Application\ Support/Bitcoin/regtest
# nohup bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcbind=0.0.0.0 -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1 -walletrejectlongchains=0 -maxtxfee=0.1 -acceptnonstdtxn=1 > /dev/null 2>&1 &

local_ip=$(ipconfig getifaddr en0)
echo $local_ip

nohup ./bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcbind=0.0.0.0 -server=1 -rpcallowip=0.0.0.0/0 -rpcport=18443  -fallbackfee=0.00001 -wallet=admin -txindex=1 -walletrejectlongchains=0 -maxtxfee=0.1 -acceptnonstdtxn=1 -maxmempool=20000 -limitancestorsize=500000 -limitdescendantsize=500000 > /dev/null 2>&1 &
                                                                                                                                                                                                                        
sleep 5

curl --user admin:admin --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "createwallet", "params": ["admin"] }' -H 'content-type: text/plain;' http://${local_ip}:18443/
root=$(curl --user admin:admin --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": [] }' -H 'content-type: text/plain;' http://${local_ip}:18443/ | jq -r '.result')
echo $root
curl --user admin:admin --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "generatetoaddress", "params": [100, "'"$root"'"] }' -H 'content-type: text/plain;' http://${local_ip}:18443/

generate_blocks() {
    local address=$(curl --user admin:admin --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": [] }' -H 'content-type: text/plain;' http://${local_ip}:18443/ | jq -r '.result')
    curl --user admin:admin --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "generatetoaddress", "params": [1, "'"$address"'"] }' -H 'content-type: text/plain;' http://${local_ip}:18443/
}

while true; do
    generate_blocks
    sleep 10
done
