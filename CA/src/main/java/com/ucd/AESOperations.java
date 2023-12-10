package com.ucd;

import org.javatuples.Pair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESOperations {

    public static String KEY_ALGO = "AES/CBC/PKCS5PADDING";
    public static String SALT = "SALT";
    public static String FACTORY_INSTANCE_TYPE = "PBKDF2WithHmacSHA256";
    public static String KEY_SPEC_TYPE = "AES";
    public static int KEY_LEN = 256;

    public AESOperations(int keyLen, String salt) {
        KEY_LEN = keyLen;
        SALT =  salt;
    }

//    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
//
//        String password = "pw";
//        SecretKey secretKey = getKeyFromPassword(password);
//        IvParameterSpec ivParameterSpec = generateIv();
//
//        System.out.println(secretKey.getEncoded().length);
//        String enctext = encrypt(KEY_ALGO, "hello", secretKey, ivParameterSpec);
//        System.out.println(enctext);
//        System.out.println(decrypt(KEY_ALGO, enctext, secretKey, ivParameterSpec));
//
//        writeTofile(secretKey, ivParameterSpec, "./AESKey.txt");
//        Pair<SecretKey, IvParameterSpec> aesPair = readFromFile("./AESKey.txt");
//
//        System.out.println(secretKey.getEncoded().length);
//        enctext = encrypt(KEY_ALGO, "hello", aesPair.getValue0(), aesPair.getValue1());
//        System.out.println(enctext);
//        System.out.println(decrypt(KEY_ALGO, enctext, aesPair.getValue0(), aesPair.getValue1()));
//    }

    public static SecretKey getKeyFromPassword(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_INSTANCE_TYPE);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), KEY_SPEC_TYPE);
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static void writeTofile(SecretKey key, IvParameterSpec ivParameterSpec, String fileName) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(key.getEncoded());
        fos.write(ivParameterSpec.getIV());
        fos.close();
    }

    public static Pair<SecretKey, IvParameterSpec> readFromFile(String fileName) throws IOException {
        byte[] keybyte = new byte[16];
        byte[] ivbyte = new byte[16];
        FileInputStream fin = new FileInputStream(fileName);
        fin.read(keybyte);
        SecretKey skey = new SecretKeySpec(keybyte, 0, 16, KEY_SPEC_TYPE);
        fin.read(ivbyte);
        IvParameterSpec ivspec = new IvParameterSpec(ivbyte);
        fin.close();
        return new Pair<SecretKey, IvParameterSpec>(skey, ivspec);
    }
}
