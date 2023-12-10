package org.hyperledger.fabric.samples.mnodetails;

import com.owlike.genson.Genson;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contact;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.License;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;
import org.hyperledger.fabric.util.Constants;
import org.hyperledger.fabric.util.ECOperations;
import org.hyperledger.fabric.util.KeyAlgorithmDefinition;
import org.hyperledger.fabric.util.M2mSignatureAlgorithmOids;
import org.hyperledger.fabric.util.RandomPointResponse;
import org.hyperledger.fabric.util.SignatureAlgorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

@Contract(
        name = "basic",
        info = @Info(
                title = "Mno details",
                description = "The hyperlegendary asset transfer",
                version = "0.0.1-SNAPSHOT",
                license = @License(
                        name = "Apache 2.0 License",
                        url = "http://www.apache.org/licenses/LICENSE-2.0.html"),
                contact = @Contact(
                        email = "mahadurage.wijethilaka@ucdconnect.ie",
                        name = "Shalitha Wijethilaka",
                        url = "https://hyperledger.example.com")))
@Default
public final class MnoDetails implements ContractInterface {

    private static final Logger logger = LogManager.getLogger(MnoDetails.class);
    private static final Genson genson = new Genson();

    private static final int MAX_ALLOWED_TIME = 1000000;
    private static final String CERTIFICATE_REQUEST_PREFIX = "CR_";
    private static final String NF_CERTIFICATE_REQUEST_PREFIX = "NCR_";
    private static final String DOS_RESPONSE_PREFIX = "DR_";
    private static final String OTHER_MNO_RESPONSE_PREFIX = "OR_";
    private static final String MNO_PREFIX = "MNO_";
    private static final String CERTIFICATE_PREFIX = "C_";
    private static final String NF_CERTIFICATE_PREFIX = "NC_";
    private static final String PUBLIC_KEY_PREFIX = "PK_";
    private static final String NF_PUBLIC_KEY_PREFIX = "NPK_";
    private static final String DOS_KEY_PREFIX = "DK_";
    private static final String INIT_POINT_PREFIX = "IP_";
    private static final String NF_INIT_POINT_PREFIX = "NIP_";
    private static final String OTHER_MNO_REQ_PREFIX = "OQ_";

    private static final String CA_HOST = "10.0.2.15";
    private static final int CA_PORT = 8999;
    private static final String CERT_HASH_PREFIX = "CH_";
    private static final String CERT_PREFIX = "C_";
    private static final boolean IS_CERT_STORE_NEEDED = false;

    private ECOperations ecOperations = new ECOperations();

    private enum CertificateErrors {
        MNO_NOT_FOUND,
        MNO_ALREADY_EXIST,
        INVALID_CERTIFICATE_REQUEST,
        INVALID_SIGNATURE,
        FRESHNESS_EXPIRED,
        IDENTITY_ISSUE,
        INVALID_MNO_RESPONSE
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public void InitLedger(final Context ctx) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ChaincodeStub stub = ctx.getStub();
        logger.info("initializing the ledger");

        ctx.getStub().putStringState("EC_Param", "EC_param");
        logger.info("Initialization successful");


    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String StoreCert(final Context ctx, String domain, String certificate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ChaincodeStub stub = ctx.getStub();
        logger.info("Started to store certificate");

        ctx.getStub().putStringState(domain, certificate);

        logger.info("Storing successful");
        return "success";

    }

    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String ValidateCert(final Context ctx, String certHash) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ChaincodeStub stub = ctx.getStub();
        logger.info("Started to store certificate");

        ctx.getStub().getStringState(certHash);

        logger.info("Storing successful");
        return "success";

    }

    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String ValidateSlice(final Context ctx, String sliceId, String vnfId) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ChaincodeStub stub = ctx.getStub();
        logger.info("Started to store certificate");

        ctx.getStub().getStringState(sliceId);

        logger.info("Storing successful");
        return "success";

    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String CA(final Context ctx, final String domain, final String request) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ChaincodeStub stub = ctx.getStub();
        logger.info("CA calling");

        try {
            Socket mySocket = new Socket(CA_HOST, CA_PORT);
            InputStream is = mySocket.getInputStream();
            OutputStream os = mySocket.getOutputStream();
            logger.info("socket created");
            BufferedReader in =
                    new BufferedReader(new InputStreamReader(is));
            PrintWriter out = new PrintWriter(os, true);

            out.println(request);
            String response = in.readLine();
            logger.info("Response from CA:" + response);
            String[] parts = response.split("\\|\\|");
            String certificate = parts[0];

            if (IS_CERT_STORE_NEEDED) {
                ctx.getStub().putStringState(CERT_PREFIX + domain, genson.serialize(new Data(CERT_PREFIX,
                        CERT_PREFIX + domain, certificate)));
            } else {
                ctx.getStub().putStringState(CERT_PREFIX + domain, genson.serialize(new Data(CERT_PREFIX,
                        CERT_PREFIX + domain, DigestUtils.sha256Hex(certificate))));
            }

            logger.info("connection with CA is closing");
            in.close();
            out.close();
            mySocket.close();
            return response;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Creates a new MNO on the ledger.
     *
     * @param ctx     the transaction context
     * @param mnoId   the ID of the new asset
     * @param mnoName the color of the new asset
     * @param host    the size for the new asset
     * @param port    the size for the new asset
     * @return the created asset
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Mno CreateMno(final Context ctx, final String mnoId, final String mnoName,
                         final String host, final String port, final String publicKey) {

        ChaincodeStub stub = ctx.getStub();
        logger.info("Starting MNO creation process" + mnoId + " " + mnoName + " " + publicKey);
        if (MnoExists(ctx, mnoId)) {
            String errorMessage = String.format("Mno %s already exists", mnoId);
            logger.error(errorMessage);
            throw new ChaincodeException(errorMessage, CertificateErrors.MNO_ALREADY_EXIST.toString());
        }

        Mno mno = new Mno(mnoId, mnoName, host, Integer.parseInt(port), new BigInteger(publicKey).toByteArray());
        //Use Genson to convert the Asset into string, sort it alphabetically and serialize it into a json string
        String sortedJson = genson.serialize(mno);
        System.out.println(sortedJson);
        stub.putStringState(MNO_PREFIX + mnoId, sortedJson);
        return mno;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String NFCertRequest(final Context ctx, final String request) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        ChaincodeStub stub = ctx.getStub();
        System.out.println("Request came for generating certificate " + request);
        String[] requestParts = request.split("\\|\\|");
        if (requestParts.length != 6) {
            System.out.println("Invalid request");
            throw new ChaincodeException("invalid request", CertificateErrors.INVALID_CERTIFICATE_REQUEST.toString());
        }

        String id = requestParts[0];
        String sessionId = requestParts[1];
        String initialPoint = requestParts[2];
        String certInfo = requestParts[3];
        long reqTimestamp = Long.parseLong(requestParts[4]);
        String signature = requestParts[5];
        BigInteger sigInt = new BigInteger(signature);
        String data = id + "||" + sessionId + "||" + initialPoint + "||" + certInfo + "||" + reqTimestamp;
        logger.info("Received Message: " + data);

        if (!validateSignature(ctx, Constants.HASH, data, NF_CERTIFICATE_REQUEST_PREFIX, sigInt,
                ctx.getClientIdentity().getX509Certificate().getPublicKey())) {
            logger.error("Invalid signature");
            throw new ChaincodeException("Invalid signature", CertificateErrors.INVALID_SIGNATURE.toString());
        }

        if (!checkFreshness(reqTimestamp)) {
            logger.error("Freshness expired");
            throw new ChaincodeException("Freshness expired", CertificateErrors.FRESHNESS_EXPIRED.toString());
        }

        String uId = NF_CERTIFICATE_REQUEST_PREFIX + sessionId;


        String secondRandom = getAlphaNumericString(Constants.RANDOM_STR_LEN);

        logger.debug("Adding the request to the ledger");
        stub.putStringState(uId, genson.serialize(new Data(NF_CERTIFICATE_REQUEST_PREFIX, uId, request)));

        logger.debug("Adding the initial point to the ledger");
        stub.putStringState(INIT_POINT_PREFIX + sessionId, genson.serialize(new Data(INIT_POINT_PREFIX,
                INIT_POINT_PREFIX + sessionId, initialPoint)));


        logger.info("Selecting n number of MNOs");
        Mno mno = null;
        QueryResultsIterator<KeyValue> mnos = stub.getQueryResult("{\"selector\":{\"type\":\"MNO\"}}");
        for (KeyValue result : mnos) {
            mno = genson.deserialize(result.getStringValue(), Mno.class);
            if (mno.getMnoName() == id) {
                logger.info("Security orchestrator found");
                break;
            }

        }
        logger.info("loaded mno: " + mno.toString());
        logger.info("Getting public parameter for the certificate");
        ECPoint p = getPforNFCert(ctx, sessionId, mno, initialPoint);

        logger.info("Getting certHash for the the certificate");
        BigInteger e = getEforCert(p);

        logger.info("starting sending requests...");
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");

        logger.info("sending cert request to mno " + mno.getMnoName());
        String signId = getAlphaNumericString(Constants.RANDOM_STR_LEN);

        String requestMNO = e + "||" + sessionId + "||" + signId + "||" + getTimestamp();
        BigInteger bg = new BigInteger(requestMNO.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromArray(mno.getPublicKey()));
        byte[] encryptedMessage = cipher.doFinal(bg.toByteArray());
        BigInteger requestBigInt = new BigInteger(encryptedMessage);

        logger.info("Adding details to the ledger");
        ctx.getStub().putStringState(OTHER_MNO_REQ_PREFIX + sessionId + mno.getMnoName(),
                genson.serialize(new Data(OTHER_MNO_REQ_PREFIX,
                        OTHER_MNO_REQ_PREFIX + sessionId + mno.getMnoId(), signId)));

        String host = mno.getHost();
        int port = mno.getPort();

        logger.info("attempting to create socket in host: " + host + " port: " + port);
        Socket mnoSocket = new Socket(host, port);
        logger.info("socket created");
        InputStream is = mnoSocket.getInputStream();
        OutputStream os = mnoSocket.getOutputStream();

        BufferedReader in =
                new BufferedReader(new InputStreamReader(is));
        PrintWriter out = new PrintWriter(os, true);
        logger.info("Starting communication with security orchestrator");
        out.println(requestBigInt);
        String line = in.readLine();
        RandomPointResponse socResponse = decodeMNOresponse(ctx, mno, line, signId);
        in.close();
        out.close();
        mnoSocket.close();

        logger.info("Calculating the public key");
        KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
        caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

        SignatureAlgorithms caAlgorithm =
                SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

        X962Parameters x9params = new X962Parameters(new ASN1ObjectIdentifier(caAlgorithm.getSecOid()));

        AlgorithmIdentifier algorithmId =
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x9params.toASN1Primitive());

        PublicKey calcPubKey = calculateNFPubKey(algorithmId, e, p, socResponse);
        logger.info("Calcuated public key for:  " + sessionId + "=> " + calcPubKey.toString());

        ctx.getStub().putStringState(PUBLIC_KEY_PREFIX + sessionId, genson.serialize(new Data(PUBLIC_KEY_PREFIX,
                PUBLIC_KEY_PREFIX + sessionId, String.valueOf(new BigInteger(calcPubKey.getEncoded())))));
        logger.debug("Calcuated public key is added to the ledger: " + PUBLIC_KEY_PREFIX + sessionId);

        ECQVCertificate ecqvCertificate = new ECQVCertificate(id, certInfo, p.toString(), String.valueOf(getTimestamp()), String.valueOf(getTimestamp() + 1000000000), calcPubKey.toString());
        Certificate certificate = new Certificate(sessionId, DigestUtils.sha256Hex(ecqvCertificate.toString().getBytes()), ecqvCertificate.toString(), false);

        String response = sessionId + "||" + socResponse.getEphermeralPrivateKey() + "||" + e + "||" + getTimestamp();

        ctx.getStub().putStringState(NF_CERTIFICATE_REQUEST_PREFIX + sessionId, genson.serialize(certificate));
        BigInteger bi = new BigInteger(response.getBytes());

        BigInteger encResp = null;
        try {
            cipher = Cipher.getInstance("ECIES", "BC");

            cipher.init(Cipher.ENCRYPT_MODE, ctx.getClientIdentity().getX509Certificate().getPublicKey());
            encryptedMessage = cipher.doFinal(bi.toByteArray());
            encResp = new BigInteger(encryptedMessage);
            logger.info("Response for client " + encResp);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidKeyException error) {
            logger.error(error.getMessage());
            throw new ChaincodeException(error.getLocalizedMessage(), CertificateErrors.IDENTITY_ISSUE.toString());
        }

        return String.valueOf(encResp);

    }

    /**
     * Retrieves an mno with the specified ID from the ledger.
     *
     * @param ctx     the transaction context
     * @param request the certificate request
     * @return the asset found on the ledger if there was one
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String CertRequest(final Context ctx, final String request) {
        ChaincodeStub stub = ctx.getStub();
        System.out.println("Request came for generating certificate " + request);
        String[] requestParts = request.split("\\|\\|");
        if (requestParts.length != 6) {
            System.out.println("Invalid request");
            throw new ChaincodeException("invalid request", CertificateErrors.INVALID_CERTIFICATE_REQUEST.toString());
        }

        String id = requestParts[0];
        String sessionId = requestParts[1];
        String initialPoint = requestParts[2];
        String certInfo = requestParts[3];
        long reqTimestamp = Long.parseLong(requestParts[4]);
        String signature = requestParts[5];
        BigInteger sigInt = new BigInteger(signature);
        String data = id + "||" + sessionId + "||" + initialPoint + "||" + certInfo + "||" + reqTimestamp;
        logger.info("Received Message: " + data);

        if (!validateSignature(ctx, Constants.HASH, data, CERTIFICATE_REQUEST_PREFIX, sigInt,
                ctx.getClientIdentity().getX509Certificate().getPublicKey())) {
            logger.error("Invalid signature");
            throw new ChaincodeException("Invalid signature", CertificateErrors.INVALID_SIGNATURE.toString());
        }

        if (!checkFreshness(reqTimestamp)) {
            logger.error("Freshness expired");
            throw new ChaincodeException("Freshness expired", CertificateErrors.FRESHNESS_EXPIRED.toString());
        }

        String uId = CERTIFICATE_REQUEST_PREFIX + sessionId;

        String response = "";
        String secondRandom = getAlphaNumericString(Constants.RANDOM_STR_LEN);

        response = sessionId + "||" + secondRandom + "||" + getTimestamp() + "||" + Constants.DOS_PUZZLE;

        BigInteger bg = new BigInteger(response.getBytes());
        System.out.println(response);
        Cipher cipher = null;
        BigInteger encResp = null;
        try {
            cipher = Cipher.getInstance("ECIES", "BC");

            cipher.init(Cipher.ENCRYPT_MODE, ctx.getClientIdentity().getX509Certificate().getPublicKey());
            byte[] encryptedMessage = cipher.doFinal(bg.toByteArray());
            encResp = new BigInteger(encryptedMessage);
            logger.info("Response for client " + encResp);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidKeyException e) {
            logger.error(e.getMessage());
            throw new ChaincodeException(e.getLocalizedMessage(), CertificateErrors.IDENTITY_ISSUE.toString());
        }

        logger.debug("Adding the request to the ledger");
        stub.putStringState(uId, genson.serialize(new Data(CERTIFICATE_REQUEST_PREFIX, uId, request)));

        logger.debug("Adding the initial point to the ledger");
        stub.putStringState(INIT_POINT_PREFIX + sessionId, genson.serialize(new Data(INIT_POINT_PREFIX,
                INIT_POINT_PREFIX + sessionId, initialPoint)));

        logger.info("Adding the dos key to the ledger");
        stub.putStringState(DOS_KEY_PREFIX + sessionId, genson.serialize(new Data(DOS_KEY_PREFIX,
                DOS_KEY_PREFIX + sessionId, secondRandom)));

        return String.valueOf(encResp);
    }


    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public static String M3fromRequestedOP(final Context ctx, final String request) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {

        logger.info("Resolved dos puzzle from MNO: " + request);
        String[] requestParts = request.split("\\|\\|");

        if (requestParts.length != 4) {
            logger.error("Dos response should have 4 parts");
        }

        String sessionId = requestParts[0];
        String nonce = requestParts[1];
        long reqTimestamp = Long.parseLong(requestParts[2]);
        String signature = requestParts[3];

        BigInteger sigInt = new BigInteger(signature);
        String data = sessionId + "||" + nonce + "||" + reqTimestamp;
        logger.info("Received data from mno: " + data);

        if (!validateSignature(ctx, Constants.HMAC, data, DOS_KEY_PREFIX + sessionId, sigInt,
                ctx.getClientIdentity().getX509Certificate().getPublicKey())) {
            System.out.println("Invalid signature");

        } else {
            System.out.println("Signature is valid");
        }

        if (!checkFreshness(reqTimestamp)) {
            logger.error("Received message is not fresh");
        }

        if (!validateNonce(ctx, nonce, sessionId)) {
            logger.error("Invalid nonce response from the MNO");
        }

        logger.info("Selecting n number of MNOs");
        Map<String, Mno> mnoMap = calReputationScore(ctx);

        logger.info("Getting public parameter for the certificate");
        ECPoint p = getPforMNOCert(ctx, sessionId, mnoMap);

        logger.info("Getting certHash for the the certificate");
        BigInteger e = getEforCert(p);

        logger.info("Sending requests to each selected MNO");
//        List<RandomPointResponse> mnoResponseList = sendMsgToMNOs(ctx, sessionId, mnoMap, e);

        logger.info("starting sending requests...");
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");

        String signId = "";

        List<RandomPointResponse> mnoResponseList = new ArrayList<>();
        for (String key : mnoMap.keySet()) {
            Mno mno = mnoMap.get(key);
            logger.info("sending cert request to mno " + mno.getMnoName());
            signId = getAlphaNumericString(Constants.RANDOM_STR_LEN);

            String requestMNO = e + "||" + sessionId + "||" + signId + "||" + getTimestamp();
            BigInteger bg = new BigInteger(requestMNO.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromArray(mno.getPublicKey()));
            byte[] encryptedMessage = cipher.doFinal(bg.toByteArray());
            BigInteger requestBigInt = new BigInteger(encryptedMessage);

            logger.info("Adding details to the ledger");
            ctx.getStub().putStringState("test", "test");
            ctx.getStub().putStringState(OTHER_MNO_REQ_PREFIX + sessionId + mno.getMnoName(),
                    genson.serialize(new Data(OTHER_MNO_REQ_PREFIX,
                            OTHER_MNO_REQ_PREFIX + sessionId + mno.getMnoId(), signId)));

            String host = mno.getHost();
            int port = mno.getPort();

            logger.info("attempting to create socket in host: " + host + " port: " + port);
            Socket mnoSocket = new Socket(host, port);
            logger.info("socket created");
            InputStream is = mnoSocket.getInputStream();
            OutputStream os = mnoSocket.getOutputStream();

            BufferedReader in =
                    new BufferedReader(new InputStreamReader(is));
            PrintWriter out = new PrintWriter(os, true);
            logger.info("Starting communication with other mno");
            out.println(requestBigInt);
            String line = in.readLine();
            mnoResponseList.add(decodeMNOresponse(ctx, mno, line, signId));
            in.close();
            out.close();
            mnoSocket.close();

        }

        logger.info("Calculating the public key");
        KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
        caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

        SignatureAlgorithms caAlgorithm =
                SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

        X962Parameters x9params = new X962Parameters(new ASN1ObjectIdentifier(caAlgorithm.getSecOid()));

        AlgorithmIdentifier algorithmId =
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x9params.toASN1Primitive());

        PublicKey calcPubKey = calculatePubKey(algorithmId, e, p, mnoResponseList);
        logger.info("Calcuated public key for:  " + sessionId + "=> " + calcPubKey.toString());

        ctx.getStub().putStringState(PUBLIC_KEY_PREFIX + sessionId, genson.serialize(new Data(PUBLIC_KEY_PREFIX,
                PUBLIC_KEY_PREFIX + sessionId, String.valueOf(new BigInteger(calcPubKey.getEncoded())))));
        logger.debug("Calcuated public key is added to the ledger: " + PUBLIC_KEY_PREFIX + sessionId);

        ECQVCertificate ecqvCertificate = new ECQVCertificate(mnoMap.keySet().toString(), ctx.getClientIdentity().getId(), p.toString(), String.valueOf(getTimestamp()), String.valueOf(getTimestamp() + 1000000000), calcPubKey.toString());
        Certificate certificate = new Certificate(sessionId, DigestUtils.sha256Hex(ecqvCertificate.toString().getBytes()), ecqvCertificate.toString(), false);

        ctx.getStub().putStringState(CERTIFICATE_REQUEST_PREFIX + sessionId, genson.serialize(certificate));

        return M6toRequestedOp(ctx, e, mnoResponseList, sessionId);

    }

    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public static String GetPublicCert(final Context ctx, final String sessionId) {
        ChaincodeStub stub = ctx.getStub();
        List<Data> queryResults = new ArrayList<Data>();
        logger.info("Reading all info about MNOs");
        // To retrieve all assets from the ledger use getStateByRange with empty startKey & endKey.
        // Giving empty startKey & endKey is interpreted as all the keys from beginning to end.
        // As another example, if you use startKey = 'asset0', endKey = 'asset9' ,
        // then getStateByRange will retrieve asset with keys between asset0 (inclusive) and asset9 (exclusive) in lexical order.
//        QueryResultsIterator<KeyValue> results = stub.getStateByRange("MNO", "MNO");
//        QueryResultsIterator<KeyValue> results = stub.getStateByPartialCompositeKey(MNO_PREFIX + "*");
        QueryResultsIterator<KeyValue> results = stub.getQueryResult("{\"selector\":{\"key\":\"" + PUBLIC_KEY_PREFIX + sessionId + "\"}}");
        for (KeyValue result : results) {
            Data data = genson.deserialize(result.getStringValue(), Data.class);
            logger.debug(data);
            queryResults.add(data);
        }

        final String response = queryResults.get(0).getValue();

        return response;
    }

    public static String M6toRequestedOp(Context ctx, BigInteger e, List<RandomPointResponse> responseList, String sessionId) {

        StringBuilder response = new StringBuilder();
        int numberOfContributedMNOs = responseList.size();

        response.append(numberOfContributedMNOs).append("||");
        for (RandomPointResponse rp : responseList) {

            response.append(rp.getEphermeralPrivateKey()).append("||");
        }

        response.append(e);
        response.append("||");
        response.append(sessionId);
        response.append("||");
        response.append(getTimestamp());
        logger.info("M6 to the requested operator: " + response);

        ctx.getClientIdentity().getX509Certificate().getPublicKey();
        return response.toString();

    }

    public static boolean checkFreshness(long reqTimestamp) {
        return true;
//        return Timestamp.from(Instant.now()).getTime() - Constants.MAX_TIME_ALLOWED < reqTimestamp;
    }

    public static boolean validateNonce(Context ctx, String nonce, String sessionId) {

        logger.info("Checking the validity of nonce: " + nonce);
        boolean isValidNonce = false;
        //todo: read these values from blockchain
        int dos = Constants.DOS_PUZZLE;

        String signId = readLedger(ctx, DOS_KEY_PREFIX + sessionId);
        String dosAns = DigestUtils.sha256Hex(sessionId + signId + nonce);

        String dosStr = "";
        for (int i = 0; i < dos; i++) {
            System.out.println(i);
            dosStr = dosStr.concat("0");
        }
        logger.info("calculated hash for dos" + dosAns.substring(0, dos));
        logger.info("dos str:" + dos);
        if (dosAns.substring(0, dos).equals(dosStr)) {
            isValidNonce = true;
        }
        logger.info("Result for dos validation:" + isValidNonce);
        return isValidNonce;

    }

    private static String readLedger(Context ctx, String queryKey) {
        logger.info("Query key: " + queryKey);
        QueryResultsIterator<KeyValue> results = ctx.getStub().getQueryResult("{\"selector\":{\"key\":\"" + queryKey + "\"}}");
        System.out.println(results);
        Data data1 = null;
        for (KeyValue result : results) {
            data1 = genson.deserialize(result.getStringValue(), Data.class);
            logger.info(data1);
        }
        if (data1 != null) {
            return data1.getValue();
        } else {
            throw new ChaincodeException();
        }
    }

    private static Map<String, Mno> calReputationScore(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();

        boolean isRemovalRequired = false;
        Map<String, Mno> mnoMap = new HashMap<>();
        QueryResultsIterator<KeyValue> mnos = stub.getQueryResult("{\"selector\":{\"type\":\"MNO\"}}");
        for (KeyValue result : mnos) {
            Mno mno = genson.deserialize(result.getStringValue(), Mno.class);
            logger.info("loaded mno: " + mno.toString());
            mnoMap.put(mno.getMnoName(), mno);
        }

        if (isRemovalRequired) {
            logger.info("Older MNO map: " + mnoMap);
            Random r = new Random();
            int low = 0;
            int high = mnoMap.size();
            int result = r.nextInt(high - low) + low;
            logger.info("Removing mno with number: " + result);
            int keyN = 0;
            String removingKey = "";
            for (String key : mnoMap.keySet()) {
                if (keyN == result) {
                    removingKey = key;
                    logger.info("Removing key: " + removingKey);
                }
                keyN++;
            }
            mnoMap.remove(removingKey);
        }
        logger.info("New mnoMap:" + mnoMap.toString());
//        int noOfIssuedCerts;
//        int noOfRevokedCerts;
//        int noOfContributedCerts;
//
//        List<Certificate> certList = new ArrayList<>();
//        Map<String, Float> repCal = new HashMap<>();
//        QueryResultsIterator<KeyValue> results = stub.getStateByPartialCompositeKey(CERTIFICATE_PREFIX);
//
//        for (KeyValue result : results) {
//            Certificate mno = genson.deserialize(result.getStringValue(), Certificate.class);
//            System.out.println(mno);
//            certList.add(mno);
//        }
        return mnoMap;

    }

    public static ECPoint getPforNFCert(final Context ctx, String sessionId, Mno mno, String initialPoint) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        logger.info("Calculating P parameter");
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

        logger.info("Initial point:" + initialPoint);
        BCECPublicKey pPublicKey = getPublicKeyFromArray(new BigInteger(initialPoint).toByteArray());
        logger.info("Initial public param: " + pPublicKey);
        ECPoint p = pPublicKey.getQ();

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(mno.getPublicKey());
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        BCECPublicKey mnoBCECPublicKey = (BCECPublicKey) publicKey;
        p = p.add(mnoBCECPublicKey.getQ());

        return p;
    }

    public static ECPoint getPforMNOCert(final Context ctx, String sessionId, Map<String, Mno> mnoMap) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        logger.info("Calculating P parameter");
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

        String initialPoint = readLedger(ctx, INIT_POINT_PREFIX + sessionId);
        logger.info("Initial point:" + initialPoint);
        BCECPublicKey pPublicKey = getPublicKeyFromArray(new BigInteger(initialPoint).toByteArray());
        logger.info("Initial public param: " + pPublicKey);
        ECPoint p = pPublicKey.getQ();
        for (String key : mnoMap.keySet()) {
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(mnoMap.get(key).getPublicKey());
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            BCECPublicKey mnoBCECPublicKey = (BCECPublicKey) publicKey;
            p = p.add(mnoBCECPublicKey.getQ());
        }

        return p;
    }

    public static BigInteger getEforCert(ECPoint p) throws NoSuchAlgorithmException, NoSuchProviderException {

        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");

        BigInteger n = ecParameterSpec.getN();
        byte[] tbsCertificate = {0x01};

        byte[] reconstructionPoint = p.getEncoded(true);

        MessageDigest messageDigest = createMessageDigest();
        for (byte b : tbsCertificate) {
            messageDigest.update(b);
        }

        for (byte b : reconstructionPoint) {
            messageDigest.update(b);
        }

        return ECOperations.calculateE(n, messageDigest.digest()).mod(n);
    }

    public static List<RandomPointResponse> sendMsgToMNOs(Context ctx, String sessionId,
                                                          Map<String, Mno> mnoMap, BigInteger e)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        ChaincodeStub stub = ctx.getStub();
        logger.info("starting sending requests...");
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");

        String signId = "";

        List<RandomPointResponse> mnoResponseList = new ArrayList<>();
        for (String key : mnoMap.keySet()) {
            Mno mno = mnoMap.get(key);
            logger.info("sending cert request to mno " + mno.getMnoName());
            signId = getAlphaNumericString(Constants.RANDOM_STR_LEN);

            String request = e + "||" + sessionId + "||" + signId + "||" + getTimestamp();
            BigInteger bg = new BigInteger(request.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromArray(mno.getPublicKey()));
            byte[] encryptedMessage = cipher.doFinal(bg.toByteArray());
            BigInteger requestBigInt = new BigInteger(encryptedMessage);

            logger.info("Adding details to the ledger");
            ctx.getStub().putStringState("test", "test");
            ctx.getStub().putStringState(OTHER_MNO_REQ_PREFIX + sessionId + mno.getMnoName(),
                    genson.serialize(new Data(OTHER_MNO_REQ_PREFIX,
                            OTHER_MNO_REQ_PREFIX + sessionId + mno.getMnoId(), signId)));

            String host = mno.getHost();
            int port = mno.getPort();

            logger.info("attempting to create socket in host: " + host + " port: " + port);
            Socket mnoSocket = new Socket(host, port);
            logger.info("socket created");
            InputStream is = mnoSocket.getInputStream();
            OutputStream os = mnoSocket.getOutputStream();

            BufferedReader in =
                    new BufferedReader(new InputStreamReader(is));
            PrintWriter out = new PrintWriter(os, true);
            logger.info("Starting communication with other mno");
            out.println(requestBigInt);
            String line = in.readLine();
            mnoResponseList.add(decodeMNOresponse(ctx, mno, line, signId));
            in.close();
            out.close();
            mnoSocket.close();

        }

        return mnoResponseList;

    }

    private static BCECPublicKey getPublicKeyFromArray(byte[] pubKeyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        return (BCECPublicKey) (keyFactory.generatePublic(publicKeySpec));
    }

    private static RandomPointResponse decodeMNOresponse(Context ctx, Mno mno, String response, String sign)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        String[] requestParts = response.split("\\|\\|");

        if (requestParts.length != 6) {
            logger.error("Invalid response from " + mno.getMnoName());
            throw new ChaincodeException("invalid request", CertificateErrors.INVALID_MNO_RESPONSE.toString());
        }

        String id = requestParts[0];
        String sessionId = requestParts[1];
        String privateKeyParam = requestParts[2];
        String publicKeyParam = requestParts[3];
        long respTimestamp = Long.parseLong(requestParts[4]);
        String signature = requestParts[5];

        String data = id + "||" + sessionId + "||" + privateKeyParam + "||" + publicKeyParam + "||" + respTimestamp;
        logger.info("Received data: " + data);
//        if (!validateSignature(ctx, Constants.HMAC, data, OTHER_MNO_REQ_PREFIX +
//                        sessionId + mno.getMnoId(), new BigInteger(signature),
//                getPublicKeyFromArray(mno.getPublicKey()))) {
//            logger.error("Invalid signature");
//            throw new ChaincodeException("Invalid signature", CertificateErrors.INVALID_SIGNATURE.toString());
//        }

        //todo: check freshness and do cross validation of session Id and mno ID
        RandomPointResponse randomPointResponse = new RandomPointResponse();
        randomPointResponse.setMnoId(id);
        randomPointResponse.setEphermeralPrivateKey(new BigInteger(privateKeyParam));
        randomPointResponse.setPublicKey(new BigInteger(publicKeyParam).toByteArray());
        return randomPointResponse;
    }

    private PrivateKey calculatePriKey(AlgorithmIdentifier algorithmId,
                                       BigInteger e, ECPoint p, BCECPrivateKey ephemeralPrivateKey,
                                       List<RandomPointResponse> randomPointResponses) throws IOException {

        BigInteger du = ephemeralPrivateKey.getD().multiply(e);
        ECPoint qU = p.multiply(e);
        for (RandomPointResponse randomPointResponse : randomPointResponses) {
            du = du.add(randomPointResponse.getEphermeralPrivateKey());
        }
        PrivateKey generatedPrivateKey = BouncyCastleProvider.getPrivateKey(new PrivateKeyInfo(algorithmId,
                new ASN1Integer(du.toByteArray())));

        return generatedPrivateKey;
    }

    private static PublicKey calculateNFPubKey(AlgorithmIdentifier algorithmId,
                                               BigInteger e, ECPoint p, RandomPointResponse randomPointResponse) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        ECPoint qU = p.multiply(e);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        logger.info("Calculating public key");

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(randomPointResponse.getPublicKey());
        BCECPublicKey midKey = (BCECPublicKey) (keyFactory.generatePublic(publicKeySpec));
        qU = qU.add(midKey.getQ());
        logger.info("================ response ===================");

        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId, qU.getEncoded(true));
        PublicKey generatedPublicKey = BouncyCastleProvider.getPublicKey(publicKeyInfo);
        return generatedPublicKey;
    }

    private static PublicKey calculatePubKey(AlgorithmIdentifier algorithmId,
                                             BigInteger e, ECPoint p, List<RandomPointResponse> randomPointResponses) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        ECPoint qU = p.multiply(e);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        logger.info("Calculating public key");
        for (RandomPointResponse randomPointResponse :
                randomPointResponses) {
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(randomPointResponse.getPublicKey());
            BCECPublicKey midKey = (BCECPublicKey) (keyFactory.generatePublic(publicKeySpec));
            qU = qU.add(midKey.getQ());
            logger.info("================ response ===================");
        }

        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId, qU.getEncoded(true));
        PublicKey generatedPublicKey = BouncyCastleProvider.getPublicKey(publicKeyInfo);
        return generatedPublicKey;
    }

    public static MessageDigest createMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
        caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256R1);

        SignatureAlgorithms algorithm =
                SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());

        return MessageDigest.getInstance(
                algorithm.getDigestAlgorithm().getDigestName(), BouncyCastleProvider.PROVIDER_NAME);
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

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

    private static boolean validateSignature(final Context ctx, final String proto, final String data,
                                             String queryKey, final BigInteger signature,
                                             final PublicKey publicKey) {
        boolean isValid = false;
        logger.info("Validating signature");
        String hash;
        try {
            if (proto.equals(Constants.HASH)) {
                hash = DigestUtils.sha256Hex(data);
            } else {
                String signId = readLedger(ctx, queryKey);
                logger.info("Key for hmac: " + signId);
                hash = String.valueOf(HmacUtils.hmacSha256(signId, data));
            }
            Signature sig = Signature.getInstance("ECDSA");
            sig.initVerify(publicKey);
            sig.update(hash.getBytes(StandardCharsets.UTF_8));
            isValid = sig.verify(signature.toByteArray());
            logger.info("Signature validation result :" + isValid);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println(e.getLocalizedMessage());
        }
        return isValid;

    }

    /**
     * Retrieves an mno with the specified ID from the ledger.
     *
     * @param ctx   the transaction context
     * @param mnoId the ID of the asset
     * @return the asset found on the ledger if there was one
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public Mno ReadMno(final Context ctx, final String mnoId) {
        ChaincodeStub stub = ctx.getStub();
        String mnoJSON = stub.getStringState(mnoId);

        if (mnoJSON == null || mnoJSON.isEmpty()) {
            String errorMessage = String.format("Mno %s does not exist", mnoId);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, CertificateErrors.MNO_NOT_FOUND.toString());
        }

        Mno mno = genson.deserialize(mnoJSON, Mno.class);
        return mno;
    }

    /**
     * Updates the properties of an asset on the ledger.
     *
     * @param ctx       the transaction context
     * @param mnoId     the ID of the asset being updated
     * @param mnoName   the color of the asset being updated
     * @param host      the size of the asset being updated
     * @param port      the size of the asset being updated
     * @param publicKey the public key of the mno
     * @return the updated mno
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Mno UpdateMno(final Context ctx, final String mnoId, final String mnoName,
                         final String host, final int port, final byte[] publicKey) {
        ChaincodeStub stub = ctx.getStub();

        if (!MnoExists(ctx, mnoId)) {
            String errorMessage = String.format("Mno %s does not exist", mnoId);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, CertificateErrors.MNO_NOT_FOUND.toString());
        }

        Mno newMno = new Mno(mnoId, mnoName, host, port, publicKey);
        //Use Genson to convert the Asset into string, sort it alphabetically and serialize it into a json string
        String sortedJson = genson.serialize(newMno);
        stub.putStringState(mnoId, sortedJson);
        return newMno;
    }

    /**
     * Deletes asset on the ledger.
     *
     * @param ctx   the transaction context
     * @param mnoId the ID of the asset being deleted
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public void DeleteMno(final Context ctx, final String mnoId) {
        ChaincodeStub stub = ctx.getStub();

        if (!MnoExists(ctx, mnoId)) {
            String errorMessage = String.format("Mno %s does not exist", mnoId);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, CertificateErrors.MNO_NOT_FOUND.toString());
        }

        stub.delState(mnoId);
    }

    /**
     * Checks the existence of the asset on the ledger
     *
     * @param ctx   the transaction context
     * @param mnoId the ID of the asset
     * @return boolean indicating the existence of the asset
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public boolean MnoExists(final Context ctx, final String mnoId) {
        ChaincodeStub stub = ctx.getStub();
        String mnoJson = stub.getStringState(mnoId);

        return (mnoJson != null && !mnoJson.isEmpty());
    }

//    /**
//     * Changes the owner of a asset on the ledger.
//     *
//     * @param ctx      the transaction context
//     * @param mnoId  the ID of the asset being transferred
//     * @param mnoName the new owner
//     * @return the old owner
//     */
//    @Transaction(intent = Transaction.TYPE.SUBMIT)
//    public String TransferAsset(final Context ctx, final String assetID, final String newOwner) {
//        ChaincodeStub stub = ctx.getStub();
//        String assetJSON = stub.getStringState(assetID);
//
//        if (assetJSON == null || assetJSON.isEmpty()) {
//            String errorMessage = String.format("Asset %s does not exist", assetID);
//            System.out.println(errorMessage);
//            throw new ChaincodeException(errorMessage, AssetTransfer.AssetTransferErrors.ASSET_NOT_FOUND.toString());
//        }
//
//        Asset asset = genson.deserialize(assetJSON, Asset.class);
//
//        Asset newAsset = new Asset(asset.getAssetID(), asset.getColor(), asset.getSize(), newOwner, asset.getAppraisedValue());
//        //Use a Genson to conver the Asset into string, sort it alphabetically and serialize it into a json string
//        String sortedJson = genson.serialize(newAsset);
//        stub.putStringState(assetID, sortedJson);
//
//        return asset.getOwner();
//    }

    /**
     * Retrieves all assets from the ledger.
     *
     * @param ctx the transaction context
     * @return array of assets found on the ledger
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public static String GetAllMNOs(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();
        List<Mno> queryResults = new ArrayList<Mno>();
        logger.info("Reading all info about MNOs");
        // To retrieve all assets from the ledger use getStateByRange with empty startKey & endKey.
        // Giving empty startKey & endKey is interpreted as all the keys from beginning to end.
        // As another example, if you use startKey = 'asset0', endKey = 'asset9' ,
        // then getStateByRange will retrieve asset with keys between asset0 (inclusive) and asset9 (exclusive) in lexical order.
//        QueryResultsIterator<KeyValue> results = stub.getStateByRange("MNO", "MNO");
//        QueryResultsIterator<KeyValue> results = stub.getStateByPartialCompositeKey(MNO_PREFIX + "*");
        QueryResultsIterator<KeyValue> results = stub.getQueryResult("{\"selector\":{\"type\":\"MNO\"}}");
        for (KeyValue result : results) {
            Mno mno = genson.deserialize(result.getStringValue(), Mno.class);
            logger.debug(mno);
            queryResults.add(mno);
        }

        final String response = genson.serialize(queryResults);

        return response;
    }
}
