package com.example.vulnapp.vulns.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/** AES helper with a hard-coded key and a static IV — deterministic ciphertext. */
public final class AesCipher {
    // VULN:VULN-23:CWE-321:pattern hard-coded 128-bit AES key baked into source
    private static final byte[] AES_KEY = "0123456789abcdef".getBytes();
    // VULN:VULN-22:CWE-329:pattern static IV reused for every CBC encryption
    private static final byte[] AES_IV  = "abcdef9876543210".getBytes();

    private AesCipher() {}

    public static String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_KEY, "AES"), new IvParameterSpec(AES_IV));
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-8")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
