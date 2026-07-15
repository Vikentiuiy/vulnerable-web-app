package com.example.vulnapp.util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

/**
 * Deliberately weak crypto helpers used across the app.
 */
public final class CryptoUtil {

    // VULN:VULN-14:CWE-798 hard-coded credentials / secret key baked into source
    public static final String ADMIN_TOKEN = "s3cr3t-admin-token-2024";
    private static final byte[] AES_KEY = "0123456789abcdef".getBytes(); // hard-coded 128-bit key
    private static final byte[] AES_IV  = "abcdef9876543210".getBytes(); // VULN:VULN-22:CWE-329 static IV

    private CryptoUtil() {}

    /** Unsalted MD5 — used for password hashing. */
    public static String md5(String input) {
        try {
            // VULN:VULN-13:CWE-327 broken/weak hash (MD5) used for passwords
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, digest));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Predictable session/reset token generator. */
    public static String weakToken(long seed) {
        // VULN:VULN-18:CWE-330 java.util.Random is not cryptographically secure; seed is predictable
        Random rng = new Random(seed);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(Integer.toHexString(rng.nextInt(16)));
        }
        return sb.toString();
    }

    public static String encrypt(String plaintext) {
        try {
            // VULN:VULN-23:CWE-327 AES/ECB-like usage with hard-coded key + static IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_KEY, "AES"), new IvParameterSpec(AES_IV));
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-8")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
