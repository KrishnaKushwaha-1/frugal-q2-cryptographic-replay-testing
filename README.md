# Frugal Q2 — Cryptographic Replay Testing & Stateful Hash-Chain API Security

## Project Overview

This project implements a local mock REST API and an automated security testing client to demonstrate cryptographic request authentication, stateful hash-chain validation, and replay attack prevention.

The implementation uses Java 21, Maven, JUnit 5, HMAC-SHA512, and SHA-512.

## Key Features

- **Transaction creation:** Creates a transaction using POST and returns its resource URI through the `Location` response header.
- **Server-issued challenge:** Generates a unique challenge token for each transaction.
- **Timestamp validation:** Rejects requests with timestamps outside the configured 30-second validity window.
- **HMAC-SHA512 authentication:** Authenticates the raw request body, timestamp, salt sequence, challenge token, and previous chain hash.
- **Stateful hash-chain:** Advances the chain after a successfully authenticated transaction update.
- **Atomic replay protection:** Uses atomic challenge consumption and synchronized chain-state transitions to prevent duplicate processing.
- **Replay attack simulation:** Resends the exact same immutable HTTP PUT request.
- **Evidence generation:** Saves replay-test results in `artifacts/logs/`.

## Technology Stack

| Technology | Purpose |
|---|---|
| Java 21 | Application implementation |
| Maven | Build and dependency management |
| JUnit 5 | Automated testing |
| JDK HttpServer | Local mock REST API |
| Java HttpClient | HTTP security testing |
| HMAC-SHA512 | Request authentication |
| SHA-512 | Hash-chain state generation |

## Project Structure

```text
frugal-q2-api-security/
├── pom.xml
├── README.md
├── .gitignore
├── src/
│   ├── main/
│   │   └── java/com/frugal/security/
│   │       ├── App.java
│   │       ├── HmacSecurity.java
│   │       ├── TransactionStore.java
│   │       ├── MockApiServer.java
│   │       └── ReplayTestClient.java
│   └── test/
│       └── java/com/frugal/security/
│           ├── HmacValidationTest.java
│           └── TransactionStoreTest.java
└── artifacts/
    └── logs/
```

## API Workflow

### 1. Create a transaction

```http
POST /transactions
```

The server responds with HTTP `201 Created` and provides:

- Transaction ID in the `Location` header
- Challenge token
- Server timestamp in microseconds
- Salt sequence
- Initial SHA-512 chain hash

### 2. Authenticate the update

The client creates an HMAC-SHA512 signature over the canonical message:

```text
rawBody.timestampMicros.saltSequence.challengeToken.previousChainHash
```

The PUT request includes:

```text
X-Challenge-Token
X-Timestamp-Micros
X-Frugal-Mac
X-Frugal-Chain-Hash
```

### 3. Advance the hash-chain

After successful validation, the server calculates:

```text
nextChainHash = SHA-512(
    previousChainHash + "." + receivedMac + "." + rawBody
)
```

The server atomically consumes the challenge and advances the chain state.

### 4. Replay the original request

The client immediately resends the exact same PUT request, retaining its original timestamp, MAC, challenge, body, and previous chain hash.

The server rejects the replay with HTTP `409 Conflict`.

## Running the Project

### Requirements

- Java 21 or later
- Maven 3.9 or later

### Step 1: Run automated tests

```powershell
mvn clean test
```

### Step 2: Start the mock API server

```powershell
java -cp target\classes com.frugal.security.App
```

### Step 3: Check server health

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8080/health" -Method Get
```

Expected response:

```json
{"status":"UP"}
```

### Step 4: Run the replay security client

Open another terminal:

```powershell
java -cp target\classes com.frugal.security.ReplayTestClient
```

## Automated Test Results

Latest verified test execution:

| Test suite | Tests | Failures |
|---|---:|---:|
| HmacValidationTest | 6 | 0 |
| TransactionStoreTest | 9 | 0 |
| **Total** | **15** | **0** |

Test coverage includes:

- HMAC-SHA512 generation and verification
- Tampered MAC rejection
- Payload integrity validation
- SHA-512 hash determinism
- Previous chain hash authentication
- Unique transaction and challenge generation
- Initial chain hash validation
- Successful chain advancement
- Stale chain hash rejection
- Concurrent challenge consumption
- Concurrent hash-chain advancement

## Verified End-to-End Replay Test

The latest successful execution demonstrated:

| Operation | HTTP status |
|---|---:|
| Transaction creation | 201 |
| Original PUT | 200 |
| Duplicate PUT | 409 |

Additional verified results:

- Hash-chain advanced: `true`
- Replay rejected: `true`
- Replay delay: `0.151 ms`
- Replay timing requirement: Passed

Evidence log:

```text
artifacts/logs/replay-test-20261031-113649.log
```

## Security Scope and Limitations

This implementation demonstrates a one-time stateful hash-chain transition per transaction. Each transaction uses a single-use challenge, so it does not currently implement multiple successive authenticated PUT updates.

The local development secret is hardcoded for demonstration purposes only. Production deployments must use secure secret management and appropriate key rotation.

## Author

Developed as part of the Frugal Testing Q2 API Security Assignment.