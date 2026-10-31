
package com.frugal.security;

import org.junit.jupiter.api.Test;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class TransactionStoreTest {

    private final TransactionStore store = new TransactionStore();

    @Test
    void shouldCreateUniqueTransactions() {

        TransactionStore.Transaction first =
                store.createTransaction();

        TransactionStore.Transaction second =
                store.createTransaction();

        assertNotNull(first.getTransactionId());
        assertNotNull(second.getTransactionId());

        assertNotEquals(
                first.getTransactionId(),
                second.getTransactionId()
        );

        System.out.println("[PASS] Unique transactions generated");
    }

    @Test
    void shouldGenerateUniqueChallengeTokens() {

        var first = store.createTransaction();
        var second = store.createTransaction();

        assertNotEquals(
                first.getChallengeToken(),
                second.getChallengeToken()
        );

        assertEquals(64, first.getChallengeToken().length());

        System.out.println("[PASS] Unique challenge tokens generated");
    }

    @Test
    void shouldValidateCorrectChallenge() {

        var transaction = store.createTransaction();

        assertTrue(
                store.matchesChallenge(
                        transaction.getTransactionId(),
                        transaction.getChallengeToken()
                )
        );

        System.out.println("[PASS] Correct challenge accepted");
    }

    @Test
    void shouldRejectIncorrectChallenge() {

        var transaction = store.createTransaction();

        assertFalse(
                store.matchesChallenge(
                        transaction.getTransactionId(),
                        "incorrect-challenge"
                )
        );

        System.out.println("[PASS] Incorrect challenge rejected");
    }

    @Test
    void shouldConsumeChallengeOnlyOnce() {

        var transaction = store.createTransaction();

        String id = transaction.getTransactionId();

        assertTrue(store.consumeChallenge(id));

        assertFalse(store.consumeChallenge(id));

        System.out.println("[PASS] Duplicate challenge consumption rejected");
    }

    @Test
    void shouldPreventConcurrentChallengeConsumption()
            throws InterruptedException {

        var transaction = store.createTransaction();

        String id = transaction.getTransactionId();

        int threadCount = 20;

        ExecutorService executor =
                Executors.newFixedThreadPool(threadCount);

        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch start = new CountDownLatch(1);

        AtomicInteger successfulRequests = new AtomicInteger(0);

        try {
            for (int i = 0; i < threadCount; i++) {

                executor.submit(() -> {

                    ready.countDown();

                    try {
                        start.await();

                        if (store.consumeChallenge(id)) {
                            successfulRequests.incrementAndGet();
                        }

                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                    }
                });
            }

            assertTrue(ready.await(5, TimeUnit.SECONDS));

            start.countDown();

            executor.shutdown();

            assertTrue(executor.awaitTermination(
                    5, TimeUnit.SECONDS));

            assertEquals(1, successfulRequests.get());

            System.out.println(
                    "[PASS] 20 concurrent requests: only one succeeded"
            );

        } finally {
            executor.shutdownNow();
        }
    }
}
