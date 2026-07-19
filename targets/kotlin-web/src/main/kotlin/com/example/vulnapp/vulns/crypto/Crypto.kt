package com.example.vulnapp.vulns.crypto

import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object WeakHash {
    fun md5(input: String): String {
        // VULN:VULN-13:CWE-327:pattern broken/weak hash (MD5) used for passwords
        val md = MessageDigest.getInstance("MD5")
        return String.format("%032x", BigInteger(1, md.digest(input.toByteArray(Charsets.UTF_8))))
    }
}

object AesCipher {
    // VULN:VULN-23:CWE-321:pattern hard-coded 128-bit AES key baked into source
    private val KEY = "0123456789abcdef".toByteArray()
    // VULN:VULN-22:CWE-329:pattern static IV reused for every CBC encryption
    private val IV = "abcdef9876543210".toByteArray()
    fun encrypt(pt: String): String {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(KEY, "AES"), IvParameterSpec(IV))
        return Base64.getEncoder().encodeToString(c.doFinal(pt.toByteArray(Charsets.UTF_8)))
    }
}

object Secrets {
    const val ADMIN_TOKEN = "s3cr3t-admin-token-2024"
    fun weakToken(seed: Long): String {
        // VULN:VULN-18:CWE-330:pattern java.util.Random is not cryptographically secure
        val rng = Random(seed)
        return (1..16).joinToString("") { Integer.toHexString(rng.nextInt(16)) }
    }
}
