package application.java;

import org.apache.commons.math3.util.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;
import util.Constants;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;

public class TraditionalCABeforeBC {

    private static final Logger logger = LogManager.getLogger(TraditionalCA.class);
    public static String KEY_ALGO = "AES/CBC/PKCS5PADDING";
    public static String SALT = "SALT";
    public static String FACTORY_INSTANCE_TYPE = "PBKDF2WithHmacSHA256";
    public static String KEY_SPEC_TYPE = "AES";
    public static int KEY_LEN = 256;
    public static String AESPW = "pw";
    public static final int CA_PORT = 8999;
    public static final String CA_HOST = "localhost";

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


    public static double getCertfromCA(int j) throws Exception {

        logger.info("starting app ");
        try {
            EnrollAdmin.enrollAdmin(null);
            RegisterUser.enrollUser(null);
        } catch (Exception e) {
            System.err.println(e);
        }

        // connect to the network and invoke the smart contract
        try (Gateway gateway = connect()) {

            Network network = gateway.getNetwork("mychannel");
            System.out.println(network.getChannel().getPeers());
            Contract contract = network.getContract("basic");

            Pair<SecretKey, IvParameterSpec> keyIvParameterSpecPair = getKeyPair();
            String domain = "abc.com";
            X509Certificate caCert = CAcert();

            Cipher cipher = Cipher.getInstance("ECIES", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, caCert.getPublicKey());

            String keyParam = String.valueOf(new BigInteger(keyIvParameterSpecPair.getFirst().getEncoded()));

            byte[] encKeyParam = cipher.doFinal(new BigInteger(keyParam).toByteArray());
            byte[] encIVParam = cipher.doFinal(new BigInteger(keyIvParameterSpecPair.getSecond().getIV()).toByteArray());
            String req = domain + "||" + new BigInteger(encKeyParam) + "||" + new BigInteger(encIVParam);

            long starttime = getTimestamp();
            Socket mySocket = new Socket(CA_HOST, 8999);
            InputStream is = null;
            is = mySocket.getInputStream();

            OutputStream os = mySocket.getOutputStream();

            BufferedReader in =
                    new BufferedReader(new InputStreamReader(is));
            PrintWriter out = new PrintWriter(os, true);
            out.println(req);
            String resEnc = in.readLine();
            String[] resParts = resEnc.split(("\\|\\|"));

            logger.info("Total response: " + resEnc);
            String cert = resParts[0];
            String priKey = decrypt(KEY_ALGO, resParts[1], keyIvParameterSpecPair.getFirst(), keyIvParameterSpecPair.getSecond());
            logger.info("Decrypted privatekey: " + priKey);

            InputStream inputStream = new ByteArrayInputStream(new BigInteger(cert).toByteArray());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(inputStream);
            logger.info("Decoded certificate=======================================================================");
            logger.info(certificate);
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            EncodedKeySpec prilicKeySpec = new PKCS8EncodedKeySpec(new BigInteger(priKey).toByteArray());
            PrivateKey privateKey = keyFactory.generatePrivate(prilicKeySpec);
            logger.info("Decoded private key=======================================================================");
            logger.info(privateKey);
            byte[] result = contract.submitTransaction("StoreCert", domain + j, certificate.toString());
            System.out.println(new String(result));
            long endtime = getTimestamp();

            System.out.println("total time: " + (endtime - starttime));

            return (endtime - starttime);
//            String res = j + ", tradCA," + (endtime - starttime) + "\n";
//            try {
//                Files.write(Paths.get("results.txt"), res.getBytes(), StandardOpenOption.APPEND);
//            } catch (IOException error) {
//                //exception handling left as an exercise for the reader
//            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            throw new Exception(e);
        }
    }

    private static Pair<SecretKey, IvParameterSpec> getKeyPair() throws InvalidKeySpecException, NoSuchAlgorithmException {


        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_INSTANCE_TYPE);
        KeySpec spec = new PBEKeySpec(AESPW.toCharArray(), SALT.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), KEY_SPEC_TYPE);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Pair<SecretKey, IvParameterSpec> secretKeyIvParameterSpecPair = new Pair<>(secret, new IvParameterSpec(iv));
        return secretKeyIvParameterSpecPair;
    }

    private static String decrypt(String algorithm, String cipherText, SecretKey key,
                                  IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

    private static X509Certificate CAcert() {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            FileInputStream cert = new FileInputStream("cert.crt");
            X509Certificate caCert = (X509Certificate) fac.generateCertificate(cert);
            cert.close();
            return caCert;
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
