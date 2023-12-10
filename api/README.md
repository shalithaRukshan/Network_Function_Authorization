# hyperledger-fabric-scaffold

Starting the Nodejs API
=======================

Update the connection Profiles
------------------------------
Update the app/config/connection-org1.json and app/config/connection-org2.json tlsCACerts values with the latest certficates in the <br>
network\config\crypto-config\peerOrganizations\org1.example.com\tlsca\tlsca.org1.example.com-cert.pem and <br>
network\config\crypto-config\peerOrganizations\org2.example.com\tlsca\tlsca.org2.example.com-cert.pem


Running the API
---------------
```sh
cd app
npm install
node app.js
```

Test API
--------
Import the Postman collection SampleRecord.postman_collection.json into Postman to test the API end points. 
