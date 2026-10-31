
package com.frugal.security;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class TransactionStore {

    private final Map<String, Transaction> transactions =
            new ConcurrentHashMap<>();

    private final SecureRandom secureRandom = new SecureRandom();

    public Transaction createTransaction() {
        String transactionId = randomHex(16);
        String challengeToken = randomHex(32);
        String saltSequence = randomHex(16);

        long serverTimestampMicros =
                System.currentTimeMillis() * 1_000L;

        String initialChainHash =
                HmacSecurity.sha512Hex(
                        transactionId + "." + challengeToken
                                + "." + saltSequence);

        Transaction transaction = new Transaction(
                transactionId,
                challengeToken,
                saltSequence,
                serverTimestampMicros,
                initialChainHash
        );

        transactions.put(transactionId, transaction);
        return transaction;
    }

    public Transaction getTransaction(String transactionId) {
        return transactions.get(transactionId);
    }

    public Transaction findTransaction(String transactionId) {
    return getTransaction(transactionId);
}

    public boolean matchesChallenge(
            String transactionId,
            String suppliedChallenge) {

        Transaction transaction = getTransaction(transactionId);

        return transaction != null
                && HmacSecurity.constantTimeEquals(
                        transaction.getChallengeToken(),
                        suppliedChallenge);
    }

    // Retained for compatibility with existing tests.
    public boolean consumeChallenge(String transactionId) {
        Transaction transaction = getTransaction(transactionId);

        return transaction != null && transaction.consumeOnly();
    }

    public boolean consumeChallengeAndAdvanceChain(
            String transactionId,
            String previousChainHash,
            String nextChainHash) {

        Transaction transaction = getTransaction(transactionId);

        return transaction != null
                && transaction.consumeAndAdvance(
                        previousChainHash, nextChainHash);
    }

    private String randomHex(int byteCount) {
        byte[] bytes = new byte[byteCount];
        secureRandom.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public static class Transaction {

        private final String transactionId;
        private final String challengeToken;
        private final String saltSequence;
        private final long serverTimestampMicros;

        private final AtomicBoolean consumed = new AtomicBoolean(false);

        private String currentChainHash;

        public Transaction(
                String transactionId,
                String challengeToken,
                String saltSequence,
                long serverTimestampMicros,
                String initialChainHash) {

            this.transactionId = transactionId;
            this.challengeToken = challengeToken;
            this.saltSequence = saltSequence;
            this.serverTimestampMicros = serverTimestampMicros;
            this.currentChainHash = initialChainHash;
        }

        public String getTransactionId() {
            return transactionId;
        }

        public String getChallengeToken() {
            return challengeToken;
        }

        public String getSaltSequence() {
            return saltSequence;
        }

        public long getServerTimestampMicros() {
            return serverTimestampMicros;
        }

        public synchronized String getCurrentChainHash() {
            return currentChainHash;
        }

        public boolean isConsumed() {
            return consumed.get();
        }

        public boolean consumeOnly() {
            return consumed.compareAndSet(false, true);
        }

        public synchronized boolean consumeAndAdvance(
                String previousChainHash,
                String nextChainHash) {

            if (previousChainHash == null || nextChainHash == null) {
                return false;
            }

            if (!HmacSecurity.constantTimeEquals(
                    currentChainHash, previousChainHash)) {
                return false;
            }

            if (!consumed.compareAndSet(false, true)) {
                return false;
            }

            currentChainHash = nextChainHash;
            return true;
        }
    }
}
