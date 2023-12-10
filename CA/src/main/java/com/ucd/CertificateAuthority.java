package com.ucd;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.javatuples.Pair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class CertificateAuthority {

    public static String KEY_ALGO = "AES/CBC/PKCS5PADDING";
    public static String KEY_SPEC_TYPE = "AES";
    public static final int port = 8999;
    public static final Logger logger = LogManager.getLogger(CertificateAuthority.class);
    public static GeneratedCert rootCA = null;
    public static GeneratedCert issuer = null;


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
//        logger.info("storing credentials of CA");

//        rootCA = createCertificate("test_certs_root",   /*domain=*/null,     /*issuer=*/null,  /*isCa=*/true);
//        issuer = createCertificate("test_certs_issuer", /*domain=*/null, rootCA,           /*isCa=*/true);
        logger.info("loading credentials of CA");
//        storeCert();
        readIssuer();
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            Socket socket = null;
            while (true) {
                try {
                    socket = serverSocket.accept();
                } catch (IOException e) {
                    System.out.println("I/O error: " + e);
                }
                // new thread for a client
                new CertThread(socket).start();
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }


    private static void validateCert() {
        try {
            Cipher cipher = Cipher.getInstance("ECIES", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, issuer.certificate.getPublicKey());

            byte[] decMsg = cipher.doFinal(new BigInteger("123879").toByteArray());
            String decryptedReq = new String(new BigInteger(decMsg).toByteArray());

            cipher.init(Cipher.DECRYPT_MODE, issuer.privateKey);
            System.out.println(issuer.privateKey.getAlgorithm());
            System.out.println(new BigInteger(cipher.doFinal(decMsg)));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private static void readIssuer() {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            FileInputStream cert = new FileInputStream("cert.crt");
            X509Certificate certificate = (X509Certificate) fac.generateCertificate(cert);
            cert.close();

            System.out.println(certificate);

            FileInputStream priKey = new FileInputStream("issuer.pk");
            PrivateKey privateKey = getPrivateKeyFromArray(priKey.readAllBytes());
            priKey.close();

            Cipher cipher = Cipher.getInstance("ECIES", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());

            byte[] decMsg = cipher.doFinal(new BigInteger("123879").toByteArray());
            String decryptedReq = new String(new BigInteger(decMsg).toByteArray());

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            System.out.println(privateKey.getAlgorithm());
            System.out.println(new BigInteger(cipher.doFinal(decMsg)));
            issuer = new GeneratedCert(privateKey, certificate);

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException |
                IOException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }


    private static PrivateKey getPrivateKeyFromArray(byte[] pubKeyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(new BigInteger(pubKeyBytes).toByteArray());
        return keyFactory.generatePrivate(keySpec);
    }

    private static void storeCert() throws Exception {
        rootCA = createCertificate("test_certs_root",   /*domain=*/null,     /*issuer=*/null,  /*isCa=*/true);
        issuer = createCertificate("test_certs_issuer", /*domain=*/null, rootCA,           /*isCa=*/true);
        System.out.println(issuer.certificate);
        try {
            FileOutputStream fc = new FileOutputStream("cert.crt");
            fc.write(issuer.certificate.getEncoded());
            fc.close();

            FileOutputStream key = new FileOutputStream("issuer.pk");
            key.write(new BigInteger(issuer.privateKey.getEncoded()).toByteArray());
            key.close();
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
        }

    }

    // To create a certificate chain we need the issuers certificate and private key. Keep these togheter to pass around
    final static class GeneratedCert {
        public final PrivateKey privateKey;
        public final X509Certificate certificate;

        public GeneratedCert(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
    }

    private static String decodeKeyParam(String req) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("ECIES", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, issuer.privateKey);
            return String.valueOf(new BigInteger(cipher.doFinal(new BigInteger(req).toByteArray())));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static class CertThread extends Thread {
        protected Socket socket;

        public CertThread(Socket clientSocket) {
            this.socket = clientSocket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                logger.info("socket started");
                String request = in.readLine();
                logger.info("Certificate request received");
                logger.info("Request: " + request);
                String[] reqParts = request.split("\\|\\|");
                String domainName = reqParts[0];
                String key = decodeKeyParam(reqParts[1]);
                String iv = decodeKeyParam(reqParts[2]);
                logger.info("AES key and IV decoded successfully");
                Pair<SecretKey, IvParameterSpec> keyPair = genKey(key, iv);

                GeneratedCert cert = createCertificate(domainName, domainName, issuer, false);
                logger.info("Generated certificate: " + cert.certificate.toString());
                logger.info("Generated private key: " + cert.privateKey.toString());
                String response = new BigInteger(cert.certificate.getEncoded()) + "||" +
                        AESOperations.encrypt(KEY_ALGO, String.valueOf(
                                new BigInteger(cert.privateKey.getEncoded())), keyPair.getValue0(), keyPair.getValue1());

//                String respEncoded = AESOperations.encrypt(KEY_ALGO, response, keyPair.getValue0(), keyPair.getValue1());
                logger.info("Response encoded: " + response);
                out.println(response);
                logger.info("Response sent to the contract");
                in.close();
                out.close();
                socket.close();
                logger.info("Connections closed");
            } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | SignatureException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();

                try {
                    socket.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                logger.info("Connections closed");
            } catch (Exception e) {
                e.printStackTrace();
                try {
                    socket.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                logger.info("Connections closed");
            }
        }
    }

    public static Pair<SecretKey, IvParameterSpec> genKey(String key, String iv) {


        SecretKey skey = new SecretKeySpec(new BigInteger(key).toByteArray(), KEY_SPEC_TYPE);
        IvParameterSpec ivspec = new IvParameterSpec(new BigInteger(iv).toByteArray());

        return new Pair<SecretKey, IvParameterSpec>(skey, ivspec);
    }

    /**
     * @param cnName The CN={name} of the certificate. When the certificate is for a domain it should be the domain name
     * @param domain Nullable. The DNS domain for the certificate.
     * @param issuer Issuer who signs this certificate. Null for a self-signed certificate
     * @param isCA   Can this certificate be used to sign other certificates
     * @return Newly created certificate with its private key
     */
    private static GeneratedCert createCertificate(String cnName, String domain, GeneratedCert issuer, boolean isCA) throws Exception {

        // Generate the key-pair with the official Java API's
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());

        KeyPair certKeyPair = keyPairGenerator.generateKeyPair();
        X500Name name = new X500Name("CN=" + cnName);
        // If you issue more than just test certificates, you might want a decent serial number schema ^.^
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant validFrom = Instant.now();
        Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);

        // If there is no issuer, we self-sign our certificate.
        X500Name issuerName;
        PrivateKey issuerKey;
        if (issuer == null) {
            issuerName = name;
            issuerKey = certKeyPair.getPrivate();
        } else {
            issuerName = new X500Name(issuer.certificate.getSubjectDN().getName());
            issuerKey = issuer.privateKey;
        }

        // The cert builder to build up our certificate information
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                Date.from(validFrom), Date.from(validUntil),
                name, certKeyPair.getPublic());

        // Make the cert to a Cert Authority to sign more certs when needed
        if (isCA) {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
        }
        // Modern browsers demand the DNS name entry
        if (domain != null) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, domain)));
        }

        // Finally, sign the certificate:
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").build(issuerKey);
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new GeneratedCert(certKeyPair.getPrivate(), cert);
    }
}
