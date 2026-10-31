# Frugal Q2 — Cryptographic Replay Testing

A Java 21 local mock API and replay-testing client demonstrating HMAC-SHA512 request authentication, server-issued challenge tokens, microsecond timestamps, one-time challenge consumption, and duplicate-request replay detection.

> **Scope:** This project uses a locally implemented mock API at `http://127.0.0.1:8080`. It demonstrates the requested security workflow; it is not a security assessment of a production third-party API.

## Features

- Creates transactions and returns a transaction ID, challenge token, server timestamp, and salt sequence.
- Authenticates transaction updates using HMAC-SHA512.
- Signs the exact raw JSON request body together with a microsecond timestamp and salt/challenge sequence.
- Validates challenge tokens and timestamp freshness on the server.
- Atomically consumes each challenge once, preventing concurrent requests from successfully reusing it.
- Replays the identical HTTP request and checks that the server rejects it with `409 Conflict`.
- Measures the delay between completion of the original PUT and start of the replay.
- Writes timestamped test evidence to `artifacts/logs/`.

## Technology Stack

- Java 21
- Maven
- JDK HttpServer and HttpClient
- Java Cryptography Architecture (JCA)
- HMAC-SHA512
- JUnit 5

The project uses Java's built-in HTTP and cryptography APIs; no external runtime framework is required.

## Project Structure

```text
frugal-q2-api-security/
├── pom.xml
├── README.md
├── src/
│   ├── main/
│   │   └── java/com/frugal/security/
│   │       ├── App.java
│   │       ├── HmacSecurity.java
│   │       ├── MockApiServer.java
│   │       ├── ReplayTestClient.java
│   │       └── TransactionStore.java
│   └── test/
│       └── java/com/frugal/security/
│           ├── HmacValidationTest.java
│           └── TransactionStoreTest.java
└── artifacts/
    └── logs/
        └── replay-test-<timestamp>.log