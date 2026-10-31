
package com.frugal.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class MockApiServer {

    private static final int PORT = 8080;

    // Local development secret only.
    // Never hardcode production secrets.
    private static final String SECRET =
            "local-development-secret-key";

    private static final long MAX_TIMESTAMP_AGE_MICROS =
            TimeUnit.SECONDS.toMicros(30);

    private final TransactionStore transactionStore =
            new TransactionStore();

    private HttpServer server;

    public void start() throws IOException {

        server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", PORT),
                0
        );

        server.createContext("/health", this::handleHealth);
        server.createContext("/transactions", this::handleTransactions);

        server.setExecutor(Executors.newFixedThreadPool(10));

        server.start();

        System.out.println("----------------------------------");
        System.out.println("Frugal Q2 Mock API Server Started");
        System.out.println("Base URL: http://127.0.0.1:" + PORT);
        System.out.println("----------------------------------");
    }

    public void stop() {

        if (server != null) {
            server.stop(1);
        }
    }

    private void handleHealth(HttpExchange exchange)
            throws IOException {

        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJson(exchange, 405,
                    "{\"error\":\"Method not allowed\"}");
            return;
        }

        sendJson(exchange, 200,
                "{\"status\":\"UP\"}");
    }

    private void handleTransactions(HttpExchange exchange)
            throws IOException {

        String method = exchange.getRequestMethod();

        if ("POST".equals(method)) {
            handleCreateTransaction(exchange);
            return;
        }

        if ("PUT".equals(method)) {
            handleUpdateTransaction(exchange);
            return;
        }

        sendJson(exchange, 405,
                "{\"error\":\"Method not allowed\"}");
    }

    private void handleCreateTransaction(HttpExchange exchange)
            throws IOException {

        TransactionStore.Transaction transaction =
                transactionStore.createTransaction();

        String transactionId = transaction.getTransactionId();

        exchange.getResponseHeaders().set(
                "Location",
                "/transactions/" + transactionId
        );

        String response = """
                {
                    "message": "Transaction created",
                    "transactionId": "%s",
                    "challengeToken": "%s",
                    "serverTimestampMicros": %d,
                    "saltSequence": "%s",
                    "initialChainHash": "%s"
                }
                """.formatted(
                transactionId,
                transaction.getChallengeToken(),
                transaction.getServerTimestampMicros(),
                transaction.getSaltSequence(),
                transaction.getCurrentChainHash()
        );

        sendJson(exchange, 201, response);

        System.out.println(
                "[TRANSACTION CREATED] " + transactionId
        );
        System.out.println(
                "[INITIAL CHAIN HASH] "
                        + transaction.getCurrentChainHash()
        );
    }

    private void handleUpdateTransaction(HttpExchange exchange)
            throws IOException {

        String path = exchange.getRequestURI().getPath();

        String prefix = "/transactions/";

        if (!path.startsWith(prefix)
                || path.length() <= prefix.length()) {

            sendJson(exchange, 400,
                    "{\"error\":\"Invalid transaction path\"}");
            return;
        }

        String transactionId = path.substring(prefix.length());

        TransactionStore.Transaction transaction =
                transactionStore.findTransaction(transactionId);

        if (transaction == null) {
            sendJson(exchange, 404,
                    "{\"error\":\"Transaction not found\"}");
            return;
        }

        String challenge = exchange.getRequestHeaders()
                .getFirst("X-Challenge-Token");

        String receivedMac = exchange.getRequestHeaders()
                .getFirst("X-Frugal-Mac");

        String timestampHeader = exchange.getRequestHeaders()
                .getFirst("X-Timestamp-Micros");

        String previousChainHash = exchange.getRequestHeaders()
                .getFirst("X-Frugal-Chain-Hash");

        if (challenge == null
                || receivedMac == null
                || timestampHeader == null
                || previousChainHash == null) {

            sendJson(exchange, 400,
                    "{\"error\":\"Missing security headers\"}");
            return;
        }

        if (!transactionStore.matchesChallenge(
                transactionId, challenge)) {

            sendJson(exchange, 401,
                    "{\"error\":\"Invalid challenge token\"}");
            return;
        }

        long clientTimestamp;

        try {
            clientTimestamp = Long.parseLong(timestampHeader);

        } catch (NumberFormatException exception) {

            sendJson(exchange, 400,
                    "{\"error\":\"Invalid timestamp\"}");
            return;
        }

        long serverNowMicros = Instant.now()
                .getEpochSecond() * 1_000_000L
                + Instant.now().getNano() / 1_000L;

        long timestampDifference;

        try {
            timestampDifference = Math.abs(
                    Math.subtractExact(
                            serverNowMicros,
                            clientTimestamp
                    )
            );

        } catch (ArithmeticException exception) {

            sendJson(exchange, 400,
                    "{\"error\":\"Invalid timestamp range\"}");
            return;
        }

        if (timestampDifference > MAX_TIMESTAMP_AGE_MICROS) {

            sendJson(exchange, 401,
                    "{\"error\":\"Expired timestamp\"}");
            return;
        }

        String rawBody = new String(
                exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8
        );

        if (rawBody.isBlank()) {
            sendJson(exchange, 400,
                    "{\"error\":\"Empty request body\"}");
            return;
        }

        // Verify that the supplied hash is the current chain state.
        if (!HmacSecurity.constantTimeEquals(
                transaction.getCurrentChainHash(),
                previousChainHash)) {

            sendJson(exchange, 409,
                    "{\"error\":\"Invalid or stale chain hash\"}");
            return;
        }

        // HMAC covers the body, timestamp, salt, challenge,
        // and previous hash-chain state.
        String expectedMac = HmacSecurity.generateMac(
                rawBody,
                clientTimestamp,
                transaction.getSaltSequence(),
                challenge,
                previousChainHash,
                SECRET
        );

        if (!HmacSecurity.verifyMac(receivedMac, expectedMac)) {

            sendJson(exchange, 401,
                    "{\"error\":\"Invalid HMAC signature\"}");
            return;
        }

        // Advance the chain only after every security check passes.
        String nextChainHash = HmacSecurity.sha512Hex(
                previousChainHash + "." + receivedMac + "." + rawBody
        );

        // Atomic one-time challenge consumption and chain advancement.
        if (!transactionStore.consumeChallengeAndAdvanceChain(
                transactionId,
                previousChainHash,
                nextChainHash)) {

            System.err.println(
                    "[REPLAY DETECTED] " + transactionId
            );

            sendJson(exchange, 409,
                    "{\"error\":\"Replay attack detected\"}");
            return;
        }

        System.out.println(
                "[TRANSACTION UPDATED] " + transactionId
        );

        System.out.println(
                "[HASH-CHAIN ADVANCED] " + nextChainHash
        );

        String response = """
                {
                    "message": "Transaction updated successfully",
                    "chainAdvanced": true,
                    "nextChainHash": "%s"
                }
                """.formatted(nextChainHash);

        sendJson(exchange, 200, response);
    }

    private void sendJson(
            HttpExchange exchange,
            int status,
            String response) throws IOException {

        byte[] responseBytes =
                response.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set(
                "Content-Type",
                "application/json; charset=UTF-8"
        );

        exchange.getResponseHeaders().set(
                "Cache-Control",
                "no-store"
        );

        exchange.sendResponseHeaders(
                status,
                responseBytes.length
        );

        try (var output = exchange.getResponseBody()) {
            output.write(responseBytes);
        }
    }
}
