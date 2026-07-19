package com.example.vulnapp.vulns.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;

/** Password hashing helper — deliberately weak (unsalted MD5). */
public final class WeakHash {
    private WeakHash() {}

    /** Unsalted MD5 used for password hashing. */
    public static String md5(String input) {
        try {
            // VULN:VULN-13:CWE-327:pattern broken/weak hash (MD5) used for passwords
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, digest));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
