. ./set_env.sh --source-only

CHANNEL_NAME="mychannel"
CC_RUNTIME_LANGUAGE="java"
VERSION="1"
CC_NAME=$1



chaincodeQuery() {
    
    setGlobalsForPeer0Org1
    peer chaincode query -C $CHANNEL_NAME -n ${CC_NAME} -c '{"Args":["GetAllMNOs"]}' | jq

}





chaincodeQuery
