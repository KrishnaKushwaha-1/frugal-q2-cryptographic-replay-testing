
package com.frugal.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class TransactionStore {

    private final ConcurrentHashMap<String, Transaction> transactions =
            new ConcurrentHashMap<>();

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Creates and stores a new transaction with a unique challenge.
     */
    public Transaction createTransaction() {

        String transactionId = "TXN-" + UUID.randomUUID();

        String challengeToken = generateRandomHex(32);

        String saltSequence = generateRandomHex(16);

        long serverTimestampMicros = getCurrentTimestampMicros();

        Transaction transaction = new Transaction(
                transactionId,
                challengeToken,
                serverTimestampMicros,
                saltSequence
        );

        transactions.put(transactionId, transaction);

        return transaction;
    }

    /**
     * Retrieves an existing transaction.
     */
    public Transaction findTransaction(String transactionId) {

        if (transactionId == null) {
            return null;
        }

        return transactions.get(transactionId);
    }

    /**
     * Checks whether the supplied challenge belongs
     * to the specified transaction.
     */
    public boolean matchesChallenge(
            String transactionId,
            String receivedChallenge) {

        Transaction transaction = findTransaction(transactionId);

        if (transaction == null || receivedChallenge == null) {
            return false;
        }

        return MessageDigest.isEqual(
                transaction.getChallengeToken()
                        .getBytes(StandardCharsets.UTF_8),

                receivedChallenge.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Atomically consumes a challenge.
     *
     * Only one request can successfully consume it,
     * even when multiple requests arrive concurrently.
     */
    public boolean consumeChallenge(String transactionId) {

        Transaction transaction = findTransaction(transactionId);

        if (transaction == null) {
            return false;
        }

        return transaction.challengeConsumed
        .compareAndSet(false, true);
    }

    /**
     * Generates a cryptographically secure random hex string.
     */
    private String generateRandomHex(int byteLength) {

        byte[] bytes = new byte[byteLength];

        secureRandom.nextBytes(bytes);

        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Generates the current timestamp in microseconds.
     */
    private long getCurrentTimestampMicros() {

        Instant now = Instant.now();

        return now.getEpochSecond() * 1_000_000L
                + now.getNano() / 1_000L;
    }

    /**
     * Represents a transaction and its security state.
     */
    public static final class Transaction {

        private final String transactionId;

        private final String challengeToken;

        private final long serverTimestampMicros;

        private final String saltSequence;

        private final AtomicBoolean challengeConsumed =
                new AtomicBoolean(false);

        private Transaction(
                String transactionId,
                String challengeToken,
                long serverTimestampMicros,
                String saltSequence) {

            this.transactionId = transactionId;
            this.challengeToken = challengeToken;
            this.serverTimestampMicros = serverTimestampMicros;
            this.saltSequence = saltSequence;
        }

        public String getTransactionId() {
            return transactionId;
        }

        public String getChallengeToken() {
            return challengeToken;
        }

        public long getServerTimestampMicros() {
            return serverTimestampMicros;
        }

        public String getSaltSequence() {
            return saltSequence;
        }

        
    }
}
