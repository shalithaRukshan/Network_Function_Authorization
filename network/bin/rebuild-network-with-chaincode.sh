
echo 'Removing old config and create new config'
./create_network.sh

sleep 10
echo 'Restarting the network ...'
./restart_dev_env.sh

echo 'Restarting successful. Deploying the chaincode ...'
sleep 30

./deploy-chaincode.sh 1
echo 'Network is redeployed successfully with the chaincode'

sleep 10
./invoke_init.sh basic

./query-all.sh basic

echo "Chaincode deployed successfully"

