package application.java;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.ContractException;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import org.hyperledger.fabric.gateway.X509Identity;
import util.Constants;
import util.KeyAlgorithmDefinition;
import util.M2mSignatureAlgorithmOids;
import util.SignatureAlgorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class WorkerThread implements Runnable {

    private String message;
    private final Logger logger = LogManager.getLogger(WorkerThread.class);
    PublicKey publicKey;
    PrivateKey privateKey;
    public BCECPrivateKey ephemeralPrivateKey;
    public BCECPublicKey ephemeralPublicKey;

    public Gateway connect() throws Exception {
        // Load a file system based wallet for managing identities.
        Path walletPath = Paths.get("wallet");
        Wallet wallet = Wallets.newFileSystemWallet(walletPath);
        // load a CCP
        Path networkConfigPath = Paths.get("connection-acme.json");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(wallet, "mno_30").networkConfig(networkConfigPath).discovery(true);
        return builder.connect();
    }

    public WorkerThread(String s) {
        this.message = s;
    }

    public void run() {
        System.out.println(Thread.currentThread().getName() + " (Start) message = " + message);
        callContract();//call processmessage method that sleeps the thread for 2 seconds
        System.out.println(Thread.currentThread().getName() + " (End)");//prints thread name
    }

    public void callContract() {
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

//        System.out.println("starting app ");
//        try {
//            EnrollAdmin.enrollAdmin(null);
//            RegisterUser.enrollUser(null);
//        } catch (Exception e) {
//            System.err.println(e);
//        }

        try (Gateway gateway = connect()) {
            Network network = gateway.getNetwork("mychannel");
            System.out.println(network.getChannel().getPeers());
            Contract contract = network.getContract("basic");

            byte[] result = contract.submitTransaction("NFCertRequest", M1toContract());
            logger.info("Received response from the contract for NF cert request: " + new String(result));

            generateNFCert(contract, algorithmId, result);

        } catch (Exception e) {
            logger.error(e.getMessage());
        }

    }

    public String M1toContract() throws IOException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());
        String mnoId = Constants.MNO_ID;
        Path walletPath = Paths.get("wallet");
        Wallet wallet = Wallets.newFileSystemWallet(walletPath);
        X509Identity x509Identity = (X509Identity) wallet.get(Constants.MNO_NAME);

        privateKey = x509Identity.getPrivateKey();
        publicKey = x509Identity.getCertificate().getPublicKey();
        String certRequest = "";

        String randomS = getAlphaNumericString(Constants.RANDOM_PARAM_LEN);
        String cInfo = "certinfo";

        KeyPair pair = getInitialPoint();

        ephemeralPublicKey = (BCECPublicKey) pair.getPublic();
        ephemeralPrivateKey = (BCECPrivateKey) pair.getPrivate();
        String initialPoint = String.valueOf(new BigInteger(ephemeralPublicKey.getEncoded()));
        logger.info(initialPoint);

        long timestamp = Timestamp.from(Instant.now()).getTime();
        String data = mnoId + "||" + randomS + "||" + initialPoint + "||" + cInfo + "||" + timestamp;
        logger.info("Initial message to the contract: " + data);
        String datahash = DigestUtils.sha256Hex(data);
        logger.info("hashed message to contract: " + datahash);

        certRequest = data + "||" + calSign(datahash);
        logger.info("Full request to contract: " + certRequest);

        return certRequest;
    }

    public void generateNFCert(Contract contract, AlgorithmIdentifier algorithmId,
                               byte[] result) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchProviderException, ContractException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        logger.info("Response from contract for private key generation: " + new String(result));

        BigInteger reqBg = new BigInteger(new String(result));
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        System.out.println(privateKey);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        System.out.println("aklsdfklafalfkj");
        byte[] decMsg = cipher.doFinal(reqBg.toByteArray());
        System.out.println(decMsg);
        String decryptedReq = new String(new BigInteger(decMsg).toByteArray());
        logger.info("decrytped text " + decryptedReq);
        String[] resultParts = decryptedReq.split("\\|\\|");
        logger.info("Received message contains " + resultParts.length + " parts");

        String contribution = resultParts[1];
        BigInteger e = new BigInteger(resultParts[2]);
        String sessionId = resultParts[0];
        long timestamp = Long.parseLong(resultParts[3]);
        PrivateKey genPriKey = calculatePriKey(algorithmId, e, ephemeralPrivateKey, new BigInteger(contribution));
        logger.info("Generated private key:" + genPriKey.toString());
        result = contract.evaluateTransaction("GetPublicCert", sessionId);
        System.out.println(new String(result));
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
    }

    private PublicKey getPublicKeyFromArray(byte[] pubKeyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private PrivateKey calculatePriKey(AlgorithmIdentifier algorithmId,
                                       BigInteger e, BCECPrivateKey ephemeralPrivateKey,
                                       BigInteger contribution) throws IOException {

        BigInteger du = ephemeralPrivateKey.getD().multiply(e);
        du = du.add(contribution);

        return BouncyCastleProvider.getPrivateKey(new PrivateKeyInfo(algorithmId,
                new ASN1Integer(du.toByteArray())));
    }

    private String getAlphaNumericString(final int n) {

        String alphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "0123456789"
                + "abcdefghijklmnopqrstuvxyz";

        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {
            int index
                    = (int) (alphaNumericString.length()
                    * Math.random());
            sb.append(alphaNumericString
                    .charAt(index));
        }
        return sb.toString();
    }

    private KeyPair getInitialPoint() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());

        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;

    }

    public BigInteger calSign(String data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        Signature sig = Signature.getInstance("ECDSA");
        sig.initSign(privateKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();
        return new BigInteger(signatureBytes);

    }
}


public class NFCertMultiThreaded {

    public static void multiCall() throws Exception {

        String filename = "rerunnf.txt";
        for (int k = 1; k < 11; k++) {
            System.out.println(k);
            try {
                Files.write(Paths.get(filename), (k + "============\n").getBytes(), StandardOpenOption.APPEND);
            } catch (IOException error) {
                //exception handling left as an exercise for the reader
                System.out.println(error);
            }
            for (int m = 0; m < 6; m++) {
                System.out.println(m);
                long starg = getTimestamp();
                int numberOfObjs = k;
                ExecutorService executor = Executors.newFixedThreadPool(numberOfObjs);//creating a pool of 5 threads
                for (int i = 0; i < numberOfObjs; i++) {
                    Runnable worker = new WorkerThread("" + i);
                    executor.execute(worker);//calling execute method of ExecutorService
                }
                executor.shutdown();
                while (!executor.isTerminated()) {
                }

                Double times = Double.valueOf(getTimestamp() - starg);
                System.out.println(getTimestamp() - starg);
                try {
                    Files.write(Paths.get(filename), (times + "\n").getBytes(), StandardOpenOption.APPEND);
                } catch (IOException error) {
                    //exception handling left as an exercise for the reader
                    System.out.println(error);
                }
                System.out.println("Finished all threads");
            }
        }
    }


    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }
}
