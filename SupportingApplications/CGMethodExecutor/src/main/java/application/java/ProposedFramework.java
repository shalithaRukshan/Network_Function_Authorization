package application.java;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.sql.Timestamp;
import java.time.Instant;

public class ProposedFramework {

    static PublicKey publicKey;
    static PrivateKey privateKey;
    public static BCECPrivateKey ephemeralPrivateKey;
    public static BCECPublicKey ephemeralPublicKey;
    private static Logger logger = LogManager.getLogger(ProposedFramework.class);

//    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
//
//        Security.addProvider(new BouncyCastleProvider());
//        String certreq = M1toContract();
////        String dos = M1Contract(certreq);
////        resolveDoS(dos);
//    }

    public static String M1toContract() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {

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


    public static boolean checkFreshness(long reqTimestamp) {
        return true;
//        return Timestamp.from(Instant.now()).getTime() - Constants.MAX_TIME_ALLOWED < reqTimestamp;
    }

    public static String decryptMsgMNO(String request) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
        BigInteger reqBg = new BigInteger(request);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decMsg = cipher.doFinal(reqBg.toByteArray());
        String decryptedReq = new String(new BigInteger(decMsg).toByteArray());
        logger.info("decrytped text " + decryptedReq);
        String[] requestParts = decryptedReq.split("\\|\\|");
        logger.info("Received message contains " + requestParts.length + " parts");

        if (requestParts.length == 4) {
            logger.info("Executing the dos resolving process");
            return M2fromContract(requestParts);
        } else if (requestParts.length == 6) {
            //todo

        } else {
            logger.error("Unknown msg type");
        }
        return null;
    }

    public static String M2fromContract(String[] requestParts) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {

        String response = "";

        String sessionId = requestParts[0];
        String signId = requestParts[1];
        long timestamp = Long.parseLong(requestParts[2]);
        int dosPuzzle = Integer.parseInt(requestParts[3]);
        long nonce = resolveDosPuzzle(sessionId + signId, dosPuzzle);

        String plainResponse = sessionId + "||" + nonce + "||" + getTimestamp();
        String hmacOfResp = calHMAC(signId, plainResponse);


        response = plainResponse + "||" + calSign(hmacOfResp);
        logger.info("Total response back to the contract with dos solution:" + response);
        return response;
    }

    public static BigInteger calSign(String data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        Signature sig = Signature.getInstance("ECDSA");
        sig.initSign(privateKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();
        return new BigInteger(signatureBytes);

    }

    public static MessageDigest createMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
        caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

        SignatureAlgorithms algorithm =
                SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

        return MessageDigest.getInstance(
                algorithm.getDigestAlgorithm().getDigestName(), BouncyCastleProvider.PROVIDER_NAME);
    }


    public BigInteger calculateE(BigInteger n, byte[] messageDigest) {
        // n.bitLength() == ceil(log2(n < 0 ? -n : n+1)
        // we actually want floor(log_2(n)) which is n.bitLength()-1
        int log2n = n.bitLength() - 1;
        int messageBitLength = messageDigest.length * 8;

        if (log2n >= messageBitLength) {
            return new BigInteger(1, messageDigest);
        } else {
            BigInteger trunc = new BigInteger(1, messageDigest);

            trunc = trunc.shiftRight(messageBitLength - log2n);

            return trunc;
        }
    }


    public static String calHMAC(String signId, String msg) {

        return String.valueOf(HmacUtils.hmacSha256(signId, msg));
    }

    public static long resolveDosPuzzle(String input, int dos) throws NoSuchAlgorithmException {
        long nonce = 0;
        String sha256hex = DigestUtils.sha256Hex(input + nonce);
        String dosStr = "";
        for (int i = 0; i < dos; i++) {
            dosStr = dosStr.concat("0");
        }
        logger.info("calculated dos str " + dosStr);
        logger.info("Calculating nonce ...");
        while (!sha256hex.substring(0, dos).equals(dosStr)) {
            if (nonce % 100000 == 0) {
                logger.info("current nonce is " + nonce);
            }
            nonce++;
            sha256hex = DigestUtils.sha256Hex(input + nonce);
        }
        logger.info("Dos puzzle resolved");
        logger.info("Input string for dos: " + input + nonce);
        logger.info("Resolved response for Dos :" + sha256hex);
        logger.info("Resolved nonce for dos:" + nonce);
        return nonce;
    }

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

    private static boolean validateSignature(final String proto, final String data, final BigInteger signature) {
        boolean isValid = false;
        String hash;
        try {
            if (proto.equals(Constants.HASH)) {
                hash = DigestUtils.sha256Hex(data);
            } else {
                //todo change the key to read from the blockchain
                hash = String.valueOf(HmacUtils.hmacSha256("", data));
            }
            Signature sig = Signature.getInstance("ECDSA");
            sig.initVerify(publicKey);
            sig.update(hash.getBytes(StandardCharsets.UTF_8));
            isValid = sig.verify(signature.toByteArray());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println(e.getLocalizedMessage());
        }
        return isValid;

    }

    private static String getAlphaNumericString(final int n) {

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


    private static KeyPair getInitialPoint() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());

        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;

    }

}
