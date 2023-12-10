package com.ucd.mno;/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Running TestApp:
// gradle ru

import com.ucd.util.Constants;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.sql.Timestamp;
import java.time.Instant;


public class Application {

    private static final Logger logger = LogManager.getLogger(Application.class);
    public static KeyPair keyPair;
    public static String host = "10.0.2.15";
    public static int port = 9500;

    static {
        System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
    }

    // helper function for getting connected to the gateway
    public static Gateway connect() throws Exception {
        // Load a file system based wallet for managing identities.
        Path walletPath = Paths.get("wallet");
        Wallet wallet = Wallets.newFileSystemWallet(walletPath);
        // load a CCP
        Path networkConfigPath = Paths.get("connection-acme.json");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(wallet, Constants.MNO_NAME).networkConfig(networkConfigPath).discovery(true);
        return builder.connect();
    }

    public static void main(String[] args) throws Exception {
        // enrolls the admin and registers the user
        System.out.println("starting app ");
        logger.info("teafdafsafdafst");
        if (args.length != 0) {
            host = args[0];
            port = Integer.parseInt(args[1]);
            Constants.MNO_NAME = args[2];
            logger.info("Host : " + host + " port : " + port);
        }
        try {
            EnrollAdmin.enrollAdmin(null);
            RegisterUser.enrollUser(null);
        } catch (Exception e) {
            System.err.println(e);
        }

        // connect to the network and invoke the smart contract
        try (Gateway gateway = connect()) {

            // get the network and contract
            Network network = gateway.getNetwork("mychannel");
            System.out.println(network.getChannel().getPeers());
            Contract contract = network.getContract("basic");

            System.out.println(contract);
            byte[] result;


            System.out.println("\n");
            result = contract.evaluateTransaction("GetAllMNOs");
            System.out.println("Evaluate Transaction: GetAllAssets, result: " + new String(result));

            logger.info("Creating MNO");

            keyPair = getPoint();
            contract.submitTransaction("CreateMno", Constants.MNO_NAME,
                    Constants.MNO_NAME, host, String.valueOf(port),
                    String.valueOf(new BigInteger(keyPair.getPublic().getEncoded())));

            System.out.println("\n");
            result = contract.evaluateTransaction("GetAllMNOs");
            logger.info("Evaluate Transaction: GetAllAssets, result: " + new String(result));
            handlesocket();


        } catch (Exception e) {
            System.err.println(e);
        }

    }

    public static void handlesocket() {

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            Socket socket = null;
            while(true) {
                try {
                    socket = serverSocket.accept();
                } catch (IOException e) {
                    System.out.println("I/O error: " + e);
                }
                // new thread for a client
                new MnoThread(socket).start();
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

    public static class MnoThread extends Thread {
        protected Socket socket;

        public MnoThread(Socket clientSocket) {
            this.socket = clientSocket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                logger.info("socket started");
                String line = in.readLine();
                logger.info("received message: " + line);
                String response = generateResponse(line);
                out.println(response);
                logger.info("Response sent to the contract");
                in.close();
                out.close();
                socket.close();
                logger.info("Connections closed");
            } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | SignatureException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
    }

    public static String generateResponse(String request) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, SignatureException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException {

        String[] requestParts = decryptMsgMNO(request);
        BigInteger e = new BigInteger(requestParts[0]);
        String sessionId = requestParts[1];
        String signId = requestParts[2];
        long reqTimestamp = Long.parseLong(requestParts[3]);

        KeyPair initPoint = getPoint();

        BCECPublicKey ephemeralPublicKey = (BCECPublicKey) initPoint.getPublic();
        BCECPrivateKey ephemeralPrivateKey = (BCECPrivateKey) initPoint.getPrivate();


        BigInteger a = e.multiply(((BCECPrivateKey) keyPair.getPrivate()).getD()).add(ephemeralPrivateKey.getD());
        BigInteger R = new BigInteger(ephemeralPublicKey.getEncoded());

        String responseInit = Constants.MNO_NAME + "||" + sessionId + "||" + a + "||" + R + "||" + getTimestamp();
        logger.info("Unencrypted msg: " + responseInit);
        String hmac = calHMAC(signId, responseInit);
        logger.info("Hash of the msg:" + hmac);
        String response = responseInit + "||" + calSign(hmac);
        logger.info("Final response for the contract: " + response);
        return response;

    }

    public static BigInteger calSign(String data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        Signature sig = Signature.getInstance("ECDSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();
        return new BigInteger(signatureBytes);

    }

    private static KeyPair getPoint() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());

        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;

    }

    public static String calHMAC(String signId, String msg) {

        return String.valueOf(HmacUtils.hmacSha256(signId, msg));
    }

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

    public static String[] decryptMsgMNO(String request) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
        BigInteger reqBg = new BigInteger(request);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decMsg = cipher.doFinal(reqBg.toByteArray());
        String decryptedReq = new String(new BigInteger(decMsg).toByteArray());
        logger.info("decrytped text " + decryptedReq);
        String[] requestParts = decryptedReq.split("\\|\\|");
        logger.info("Received message contains " + requestParts.length + " parts");

        if (requestParts.length == 4) {
            logger.info("Executing the dos resolving process");
            return requestParts;
        } else {
            logger.error("Unknown msg type");
        }
        return null;
    }
}
