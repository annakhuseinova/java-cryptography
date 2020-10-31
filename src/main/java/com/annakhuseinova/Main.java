package com.annakhuseinova;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {

    public static final String ALGORITHM = "AES";
    public static final String CIPHER = "AES/CBC/";

    public static void main(String[] args) {

        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        byte[] initVector = new byte[16];
        secureRandom.nextBytes(initVector);
    }

    public static String encrypt(byte[] key, byte[] initVector, String value) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        byte[] original = cipher.doFinal(value.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(original);
    }

    public static String decrypt(byte[] key, byte[] initVector, String encodedValue) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        byte [] original = cipher.doFinal(Base64.getDecoder().decode(encodedValue));
        return new String(original);
    }
}
