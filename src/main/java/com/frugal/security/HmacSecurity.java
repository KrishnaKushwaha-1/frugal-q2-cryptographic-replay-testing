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
    }

    // Retained for compatibility with existing unit tests.
    public static String generateMac(
            String rawBody,
            long timestampMicros,
            String saltSequence,
            String secret) {

        return generateMac(
                rawBody, timestampMicros, saltSequence,
                "", "", secret);
    }

    /**
     * Canonical message:
     * rawBody.timestamp.salt.challenge.previousChainHash
     */
    public static String generateMac(
            String rawBody,
            long timestampMicros,
            String saltSequence,
            String challengeToken,
            String previousChainHash,
            String secret) {

        Objects.requireNonNull(rawBody, "Body cannot be null");
        Objects.requireNonNull(saltSequence, "Salt cannot be null");
        Objects.requireNonNull(challengeToken, "Challenge cannot be null");
        Objects.requireNonNull(previousChainHash, "Chain hash cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");

        if (timestampMicros <= 0) {
            throw new IllegalArgumentException("Timestamp must be positive");
        }

        if (secret.isBlank()) {
            throw new IllegalArgumentException("Secret cannot be blank");
        }

        String canonicalMessage =
                rawBody + "." + timestampMicros + "."
                        + saltSequence + "." + challengeToken
                        + "." + previousChainHash;

        try {
            Mac mac = Mac.getInstance(ALGORITHM);

            SecretKeySpec key = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    ALGORITHM);

            mac.init(key);

            byte[] signature = mac.doFinal(
                    canonicalMessage.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(signature);

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "HMAC generation failed", exception);
        }
    }

    // SHA-512 hash-chain operation.
    public static String sha512Hex(String value) {

        Objects.requireNonNull(value, "Value cannot be null");

        try {
            byte[] digest = MessageDigest.getInstance("SHA-512")
                    .digest(value.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(digest);

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "SHA-512 hashing failed", exception);
        }
    }

    public static boolean verifyMac(
            String receivedMac,
            String expectedMac) {

        if (receivedMac == null || expectedMac == null) {
            return false;
        }

        return MessageDigest.isEqual(
                receivedMac.getBytes(StandardCharsets.US_ASCII),
                expectedMac.getBytes(StandardCharsets.US_ASCII));
    }

    public static boolean constantTimeEquals(
            String first,
            String second) {

        if (first == null || second == null) {
            return false;
        }

        return MessageDigest.isEqual(
                first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
    }
}