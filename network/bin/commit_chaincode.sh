

. ./set_env.sh --source-only

export PRIVATE_DATA_CONFIG=${1}/collections_config.json

CHANNEL_NAME="mychannel"
CC_RUNTIME_LANGUAGE="java"
VERSION=$3
CC_SRC_PATH=$1
CC_NAME=$2




commitChaincodeDefination() {
    setGlobalsForPeer0Org1
    peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
        --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA \
        --channelID $CHANNEL_NAME --name ${CC_NAME} \
        --peerAddresses localhost:7051 --tlsRootCertFiles $PEER0_ORG1_CA \
        --version ${VERSION} --sequence ${VERSION} --init-required

        echo "===================== Commit Successfull ===================== "

}


commitChaincodeDefination