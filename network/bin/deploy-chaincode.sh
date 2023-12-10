./package_chaincode.sh "./../../hyperledger" "basic" $1
./install_chaincode.sh "./../../hyperledger" "basic" $1
./approve_chaincode.sh "./../../hyperledger" "basic" $1
./commit_chaincode.sh "./../../hyperledger" "basic" $1


echo "===================== Invoking Init ====================="
# ./invoke_init.sh fabcar $1