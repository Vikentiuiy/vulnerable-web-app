package com.example.vulnapp.vulns.crypto;

import java.util.Random;

/** Hard-coded admin secret + a predictable token generator. */
public final class Secrets {
    // VULN:VULN-14:CWE-798:pattern hard-coded admin credential baked into source
    public static final String ADMIN_TOKEN = "s3cr3t-admin-token-2024";

    private Secrets() {}

    /** Predictable session/reset token from a seedable, non-CSPRNG generator. */
    public static String weakToken(long seed) {
        // VULN:VULN-18:CWE-330:pattern java.util.Random is not cryptographically secure; seed is predictable
        Random rng = new Random(seed);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(Integer.toHexString(rng.nextInt(16)));
        return sb.toString();
    }
}
