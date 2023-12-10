Fabric 2.0
==========
September 2021

Prerequisites
==============
Ubuntu 18 or higher <br/>
Docker version 17.06.2-ce or greater is required.<br/>
Go version 1.12.x is required. <br/>


Installing Prerequisites
------------------------
<!-- ## If you are on Windows 
Make sure to install Virtual Box and Vagrant
cd into this directory.
vagrant up -->


### 1. Change permissions
```sh
cd installation  
chmod -R 755 ./*  
```

### 2. Installing Docker, GoLang and NodeJS
This will install the minimum version required. 
```sh
./install-prereqs.sh  
source ~/.profile  
source ~/.bashrc 
```

### 3. Validate
Make sure everything went well. You might need to restart the terminal to reflect the path changes. 
```sh
sudo ./validate-prereqs.sh
```

### 4. Installing Govendor 
```sh
sudo ./install-gotools.sh
```

Installing Fabric 2.0
---------------------
### 1. Install the Fabric binaries & images
```sh
sudo curl -sSL http://bit.ly/2ysbOFE -o bootstrap.sh
chmod 777 ./bootstrap.sh
./bootstrap.sh 2.1.0 1.4.6 -s
sudo cp ./bin/*    /usr/local/bin
```

### 2. Validate
```sh
sudo ./validate-fabric.sh 
```

### 3. Install Go Fabric Shim package
This is required for developing Chaincodes
```sh
go get github.com/hyperledger/fabric-chaincode-go/shim
go get github.com/hyperledger/fabric-chaincode-go/shimtest
```
