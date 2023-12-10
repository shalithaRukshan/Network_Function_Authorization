/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Running TestApp: 
// gradle runApp 

package application.java;

import com.owlike.genson.Genson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import util.Constants;
import util.KeyAlgorithmDefinition;
import util.M2mSignatureAlgorithmOids;
import util.SignatureAlgorithms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;


public class App {

    private static final Logger logger = LogManager.getLogger(App.class);
    public static KeyPair keyPair;
    private static final Genson genson = new Genson();
    public static String KEY_ALGO = "AES/CBC/PKCS5PADDING";
    public static String SALT = "SALT";
    public static String FACTORY_INSTANCE_TYPE = "PBKDF2WithHmacSHA256";
    public static String KEY_SPEC_TYPE = "AES";
    public static int KEY_LEN = 256;
    public static String AESPW = "pw";
    public static final int CA_PORT = 8999;
    public static final String CA_HOST = "localhost";

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

    public static void main(String[] args) {
        // enrolls the admin and registers the user

        try {
            int k = 0;
            List<Double> timeList = new ArrayList<>();
            int start = 0;
            int end = 10;
            int noOfMnos = 5;
            System.out.println("Running for nf cert");
            NFCertMultiThreaded.multiCall();

//            System.out.println("MNO testing ");
//            String filename = "mnocert-3-256.txt";
//            timeList.clear();
//            try {
//                Files.write(Paths.get(filename), ("oursystem"+noOfMnos+ "\n").getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
//            for (int i = start; i < end; i++) {
//                k++;
//                Double time = DistBCImpl(i);
//
//                try {
//                    Files.write(Paths.get(filename), (String.valueOf(time) + "\n").getBytes(), StandardOpenOption.APPEND);
//                } catch (IOException error) {
//                    //exception handling left as an exercise for the reader
//                }
//
//                timeList.clear();
//
//
//            }
//            timeList.clear();
//            try {
//                Files.write(Paths.get("results.txt"), "oursystem \n".getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
//            for (int i = start; i < end; i++) {
//                k++;
//                Double time = DistBCImpl(i);
//                timeList.add(time);
//                if (k == 5) {
//                    Double avgTime = timeList.stream().mapToDouble(d -> d).average().orElse(0.0);
//                    try {
//                        Files.write(Paths.get("results.txt"), (String.valueOf(avgTime) + "\n").getBytes(), StandardOpenOption.APPEND);
//                    } catch (IOException error) {
//                        //exception handling left as an exercise for the reader
//                    }
//                    k = 0;
//                    timeList.clear();
//                }
//
//            }
//
//            timeList.clear();
//            try {
//                Files.write(Paths.get("results.txt"), "Traditional CA\n".getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
//            for (int i = start; i < end; i++) {
//                k++;
//
//                Double time = TraditionalCA.CAImpl(i);
//                timeList.add(time);
//                if (k == 5) {
//                    Double avgTime = timeList.stream().mapToDouble(d -> d).average().orElse(0.0);
//                    try {
//                        Files.write(Paths.get("results.txt"), (String.valueOf(avgTime) + "\n").getBytes(), StandardOpenOption.APPEND);
//                    } catch (IOException error) {
//                        //exception handling left as an exercise for the reader
//                    }
//                    k = 0;
//                    timeList.clear();
//                }
//
//            }
//
//            timeList.clear();
//            try {
//                Files.write(Paths.get("results.txt"), "Traditional CA after BC\n".getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
//            for (int i = start; i < end; i++) {
//                k++;
//                Double time = TraditionalCAafterBC.BCwithCAImpl(i);
//                timeList.add(time);
//                if (k == 5) {
//                    Double avgTime = timeList.stream().mapToDouble(d -> d).average().orElse(0.0);
//                    try {
//                        Files.write(Paths.get("results.txt"), (String.valueOf(avgTime) + "\n").getBytes(), StandardOpenOption.APPEND);
//                    } catch (IOException error) {
//                        //exception handling left as an exercise for the reader
//                    }
//                    k = 0;
//                    timeList.clear();
//                }
//
//            }
//
//            timeList.clear();
//            try {
//                Files.write(Paths.get("results.txt"), "Traditional CA before BC\n".getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
//            for (int i = start; i < end; i++) {
//                k++;
//
//                Double time = TraditionalCABeforeBC.getCertfromCA(i);
//                timeList.add(time);
//                if (k == 5) {
//                    Double avgTime = timeList.stream().mapToDouble(d -> d).average().orElse(0.0);
//                    try {
//                        Files.write(Paths.get("results.txt"), (String.valueOf(avgTime) + "\n").getBytes(), StandardOpenOption.APPEND);
//                    } catch (IOException error) {
//                        //exception handling left as an exercise for the reader
//                    }
//                    k = 0;
//                    timeList.clear();
//                }
//
//            }
        } catch (Exception er) {
            logger.error(er.getMessage());
        }


    }


    public static double DistBCImpl(int j) throws Exception {

        System.out.println("starting app ");
        try {
            EnrollAdmin.enrollAdmin(null);
            RegisterUser.enrollUser(null);
        } catch (Exception e) {
            System.err.println(e);
        }

        // connect to the network and invoke the smart contract
        try (Gateway gateway = connect()) {

            KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
            caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

            SignatureAlgorithms caAlgorithm =
                    SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

            X962Parameters x9params = new X962Parameters(new ASN1ObjectIdentifier(caAlgorithm.getSecOid()));

            AlgorithmIdentifier algorithmId;
            ECParameterSpec curveParameters =
                    ECNamedCurveTable.getParameterSpec(caAlgorithm.getCryptoAlgorithm().getAlgorithmName());
            algorithmId =
                    new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x9params.toASN1Primitive());

            // get the network and contract
            Network network = gateway.getNetwork("mychannel");
            Contract contract = network.getContract("basic");

            byte[] result;

//            handlesocket();
//            System.out.println("\n");
//            result = contract.evaluateTransaction("GetAllMNOs");
//            System.out.println("Evaluate Transaction: GetAllAssets, result: " + new String(result));
//
//            System.out.println("\n");
//            result = contract.evaluateTransaction("GetAllMNOs");
//            System.out.println("Evaluate Transaction: GetAllAssets, result: " + new String(result));

            long starttime = getTimestamp();
            result = contract.submitTransaction("CertRequest", ProposedFramework.M1toContract());
            logger.info("Received response from the contract: " + new String(result));

            result = contract.submitTransaction("M3fromRequestedOP", ProposedFramework.decryptMsgMNO(new String(result)));
            logger.info("Response from contract for private key generation: " + new String(result));

            String[] resultParts = new String(result).split("\\|\\|");

            logger.info("Total received parts: " + resultParts.length);
            int numberOfContributions = Integer.parseInt(resultParts[0]);
            logger.info("Number of contributions: " + numberOfContributions);
            List<BigInteger> contributionList = new ArrayList<>();
            for (int i = 0; i < numberOfContributions; i++) {
                contributionList.add(new BigInteger(resultParts[i + 1]));

            }

            BigInteger e = new BigInteger(resultParts[numberOfContributions + 1]);
            String sessionId = resultParts[numberOfContributions + 2];
            PrivateKey genPriKey = calculatePriKey(algorithmId, e, ProposedFramework.ephemeralPrivateKey, contributionList);
            logger.info("Generated private key:" + genPriKey.toString());
            result = contract.evaluateTransaction("GetPublicCert", sessionId);
            logger.info(new String(result));
            PublicKey genPubKey = getPublicKeyFromArray(new BigInteger(new String(result)).toByteArray());
            logger.info("generated public key:" + genPubKey.toString());
            logger.info("Verification started....");
            byte[] data = "data".getBytes("UTF8");

            Signature sig = Signature.getInstance("ECDSA");
            sig.initSign(genPriKey);
            sig.update(data);
            byte[] signatureBytes = sig.sign();

            sig.initVerify(genPubKey);
            sig.update(data);

            System.out.println("Signature verifying " + sig.verify(signatureBytes));
            long endtime = getTimestamp();
            return (endtime - starttime);
//            System.out.println("time to get: " + (endtime - starttime));
//            String res = j + ", ours, 4," + (endtime - starttime) + "\n";
//            try {
//                Files.write(Paths.get("results.txt"), res.getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
        } catch (Exception e) {
            System.err.println(e);
            throw new Exception(e);
        }
    }

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

    private static PublicKey getPublicKeyFromArray(byte[] pubKeyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static PrivateKey calculatePriKey(AlgorithmIdentifier algorithmId,
                                              BigInteger e, BCECPrivateKey ephemeralPrivateKey,
                                              List<BigInteger> contributionList) throws IOException {

        BigInteger du = ephemeralPrivateKey.getD().multiply(e);
        for (BigInteger a : contributionList) {
            du = du.add(a);
        }

        return BouncyCastleProvider.getPrivateKey(new PrivateKeyInfo(algorithmId,
                new ASN1Integer(du.toByteArray())));
    }

    public static void handlesocket() throws IOException {
        ServerSocket serverSocket = new ServerSocket(7788);

        Socket socket = serverSocket.accept();

        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        logger.info("socket started");
        System.out.println(in.readLine());
    }
}
