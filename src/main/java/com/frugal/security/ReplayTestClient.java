
package com.frugal.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ReplayTestClient {

    private static final String BASE_URL = "http://127.0.0.1:8080";
    private static final String SECRET = "local-development-secret-key";

    public static void main(String[] args) throws Exception {

        StringBuilder report = new StringBuilder();

        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        // 1. Create transaction.
        HttpRequest createRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/transactions"))
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> createResponse = client.send(
                createRequest,
                HttpResponse.BodyHandlers.ofString()
        );

        if (createResponse.statusCode() != 201) {
            throw new IllegalStateException(
                    "Transaction creation failed: "
                            + createResponse.statusCode()
                            + " " + createResponse.body()
            );
        }

        // 2. Extract transaction ID directly from Location.
        String location = createResponse.headers()
                .firstValue("Location")
                .orElseThrow(() ->
                        new IllegalStateException("Location header missing"));

        String transactionId = extractTransactionId(location);

        // 3. Extract server-issued security values.
        String challenge = extract(
                createResponse.body(), "challengeToken");

        String timestamp = extract(
                createResponse.body(), "serverTimestampMicros");

        String salt = extract(
                createResponse.body(), "saltSequence");

        String initialChainHash = extract(
                createResponse.body(), "initialChainHash");

        add(report, "========== FRUGAL Q2 REPLAY TEST ==========");
        add(report, "Execution time: " + LocalDateTime.now());
        add(report, "Transaction ID: " + transactionId);
        add(report, "Location: " + location);
        add(report, "POST status: " + createResponse.statusCode());
        add(report, "Server timestamp (microseconds): " + timestamp);
        add(report, "Initial chain hash: " + initialChainHash);

        // 4. Prepare exact raw request body.
        String rawBody = """
                {"status":"APPROVED","amount":500}
                """.strip();

        // 5. Generate HMAC-SHA512 using the previous chain hash.
        String mac = HmacSecurity.generateMac(
                rawBody,
                Long.parseLong(timestamp),
                salt,
                challenge,
                initialChainHash,
                SECRET
        );

        URI updateUri = URI.create(BASE_URL + location);

        // Build the PUT request once.
        // The exact same immutable request is reused for replay.
        HttpRequest updateRequest = HttpRequest.newBuilder()
                .uri(updateUri)
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .header("X-Challenge-Token", challenge)
                .header("X-Timestamp-Micros", timestamp)
                .header("X-Frugal-Mac", mac)
                .header("X-Frugal-Chain-Hash", initialChainHash)
                .PUT(HttpRequest.BodyPublishers.ofString(rawBody))
                .build();

        // 6. Send original PUT.
        HttpResponse<String> firstResponse = client.send(
                updateRequest,
                HttpResponse.BodyHandlers.ofString()
        );

        long firstCompletedAt = System.nanoTime();

        add(report, "");
        add(report, "========== FIRST PUT ==========");
        add(report, "HTTP status: " + firstResponse.statusCode());
        add(report, "Response: " + firstResponse.body());

        // 7. Immediately replay the exact same request.
        long replayStartedAt = System.nanoTime();

        HttpResponse<String> replayResponse = client.send(
                updateRequest,
                HttpResponse.BodyHandlers.ofString()
        );

        long replayElapsedNanos =
                replayStartedAt - firstCompletedAt;

        double replayElapsedMillis =
                replayElapsedNanos / 1_000_000.0;

        add(report, "");
        add(report, "========== REPLAY PUT ==========");
        add(report, "HTTP status: " + replayResponse.statusCode());
        add(report, "Response: " + replayResponse.body());

        add(report, String.format(
                "Replay sent %.3f ms after first PUT completion",
                replayElapsedMillis
        ));

        // 8. Evaluate assignment requirements.
        boolean firstAccepted =
                firstResponse.statusCode() == 200;

        boolean chainAdvanced =
                firstResponse.body().contains("\"chainAdvanced\": true")
                        || firstResponse.body().contains("\"chainAdvanced\":true");

        boolean replayRejected =
                replayResponse.statusCode() == 409;

        boolean withinWindow =
                replayElapsedNanos >= 0
                        && replayElapsedNanos <= 150_000_000L;

        add(report, "");
        add(report, "========== TEST RESULT ==========");
        add(report, "First PUT accepted: " + firstAccepted);
        add(report, "Hash-chain advanced: " + chainAdvanced);
        add(report, "Replay rejected: " + replayRejected);
        add(report, "Replay within 150 ms: " + withinWindow);

        if (replayResponse.statusCode() == 200
                || replayResponse.statusCode() == 201) {

            add(report,
                    "HIGH-RISK ALERT: REPLAY ACCEPTED. "
                            + "POTENTIAL DATA-MUTATION VULNERABILITY.");
        }

        boolean passed =
                firstAccepted
                        && chainAdvanced
                        && replayRejected
                        && withinWindow;

        add(report, passed
                ? "RESULT: PASS - Replay attack prevented."
                : "RESULT: FAIL - Replay security requirements not satisfied.");

        // 9. Print and persist evidence.
        System.out.println(report);

        Path logDirectory = Path.of("artifacts", "logs");
        Files.createDirectories(logDirectory);

        String fileTimestamp = LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        );

        Path logFile = logDirectory.resolve(
                "replay-test-" + fileTimestamp + ".log"
        );

        Files.writeString(
                logFile,
                report.toString(),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
        );

        System.out.println(
                "\nEvidence saved to: " + logFile.toAbsolutePath()
        );

        if (!passed) {
            throw new IllegalStateException(
                    "Replay security test failed. Check the evidence log."
            );
        }
    }

    private static String extractTransactionId(String location) {

        String normalized = location.replaceAll("/+$", "");

        int lastSlash = normalized.lastIndexOf('/');

        if (lastSlash < 0 || lastSlash == normalized.length() - 1) {
            throw new IllegalStateException(
                    "Invalid transaction Location header: " + location
            );
        }

        return normalized.substring(lastSlash + 1);
    }

    private static void add(StringBuilder report, String line) {
        report.append(line).append(System.lineSeparator());
    }

    private static String extract(String json, String key) {

        Pattern pattern = Pattern.compile(
                "\"" + Pattern.quote(key)
                        + "\"\\s*:\\s*\"?([^\",}]+)\"?"
        );

        Matcher matcher = pattern.matcher(json);

        if (!matcher.find()) {
            throw new IllegalStateException(
                    "Could not extract JSON field: " + key
            );
        }

        return matcher.group(1).trim();
    }
}
