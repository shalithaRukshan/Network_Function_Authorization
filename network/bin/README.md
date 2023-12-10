#### Fabric 2.0

Starting the Fabric Network
===========================

Creating Crypto Assets, Genesis Block, Channel Configuration and Anchor Peers
-----------------------------------------------------------------------------
```sh
cd network/bin
chmod -R 755 ./*
./create_network.sh 
```

Starting the network
--------------------
This will start the ../devenv/docker-compose.base.yaml docker compose enviroment. 
```sh
./init_dev_env.sh      
```

Creating the channel and join Peers to the Channel
--------------------------------------------------
```sh
./create_channel.sh 
```

Deploying the sample Chaincode
==============================

Getting dependecies and packaging the chain code 
------------------------------------------------
```sh
./package_chaincode.sh [path_to_src] [chaincode_name] [version]
```
```sh
./package_chaincode.sh "./../../gocc/src/github.com/tharindupr/sample" "samplecontract" 1
```

Installing chaincode on two orgs
--------------------------------
```sh
./install_chaincode.sh [path_to_src] [chaincode_name] [version]
```

```sh
./install_chaincode.sh "./../../gocc/src/github.com/tharindupr/sample" "samplecontract" 1
```

Aproving the chaincode on two orgs
---------------------------------
```sh
./approve_chaincode.sh [path_to_src] [chaincode_name] [version]
```
```sh
./approve_chaincode.sh "./../../gocc/src/github.com/tharindupr/sample" "samplecontract" 1
```

Committing the chaincode on two orgs
---------------------------------
```sh
./commit_chaincode.sh [path_to_src] [chaincode_name] [version]
```
```sh
./commit_chaincode.sh "./../../gocc/src/github.com/tharindupr/sample" "samplecontract" 1
```

Invoking the init function
---------------------------------
```sh
./invoke_init.sh samplecontract 1
```

Invoking the createSampleContract 
---------------------------------
```sh
./invoke_createSampleRecord.sh
```

### Learn more on the Chaincode lifecyle : <a href="https://hyperledger-fabric.readthedocs.io/en/release-2.0/chaincode_lifecycle.html#fabric-chaincode-lifecycle"> Here </a>

