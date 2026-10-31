
package com.frugal.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Objects;

public final class HmacSecurity {

    private static final String ALGORITHM = "HmacSHA512";

    private HmacSecurity() {
        // Prevent object creation
    }

    /**
     * Generates an HMAC-SHA512 signature.
     *
     * Canonical message:
     * rawBody.timestampMicros.saltSequence
     */
    public static String generateMac(
            String rawBody,
            long timestampMicros,
            String saltSequence,
            String secret) {

        Objects.requireNonNull(rawBody, "Body cannot be null");
        Objects.requireNonNull(saltSequence, "Salt cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");

        if (timestampMicros <= 0) {
            throw new IllegalArgumentException(
                    "Timestamp must be positive");
        }

        if (secret.isBlank()) {
            throw new IllegalArgumentException(
                    "Secret cannot be blank");
        }

        String canonicalMessage =
                rawBody + "." + timestampMicros + "." + saltSequence;

        try {
            Mac mac = Mac.getInstance(ALGORITHM);

            SecretKeySpec key = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    ALGORITHM
            );

            mac.init(key);

            byte[] signature = mac.doFinal(
                    canonicalMessage.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(signature);

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "HMAC generation failed",
                    exception
            );
        }
    }

    /**
     * Constant-time signature comparison.
     */
    public static boolean verifyMac(
            String receivedMac,
            String expectedMac) {

        if (receivedMac == null || expectedMac == null) {
            return false;
        }

        return MessageDigest.isEqual(
                receivedMac.getBytes(StandardCharsets.US_ASCII),
                expectedMac.getBytes(StandardCharsets.US_ASCII)
        );
    }
}
