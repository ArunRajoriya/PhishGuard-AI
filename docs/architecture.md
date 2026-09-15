# PhishGuard AI — Architecture

## High-Level Architecture

```text
React / TypeScript
       │
       │ HTTPS
       ▼
    FastAPI
       │
       ├──────────────► JWT Authentication
       │
       ├──────────────► Redis
       │                  ├── Cache
       │                  ├── Rate Limiting
       │                  └── Async Job State
       │
       ├──────────────► PostgreSQL
       │                  ├── Users
       │                  └── Scan History
       │
       ▼
Background Processing
       │
       ├──────────────► URL Feature Extraction
       │
       ├──────────────► XGBoost URL Model
       │
       ├──────────────► VirusTotal
       │
       └──────────────► Trusted Domain Protection
                         │
                         ▼
                    Risk Engine
                         │
               ┌─────────┼─────────┐
               ▼         ▼         ▼
             SAFE   SUSPICIOUS  PHISHING
```

## Scan Lifecycle

1. Client submits a URL.
2. FastAPI authenticates the request.
3. URL is normalized and validated.
4. Redis cache is checked.
5. URL features are extracted.
6. The URL ML model generates a prediction.
7. Threat intelligence is queried.
8. Trusted-domain protection is evaluated.
9. Signals are combined by the risk engine.
10. The result is stored in PostgreSQL.
11. The result is cached in Redis.
12. The API returns the classification.

## Async Lifecycle

For asynchronous scans, FastAPI returns HTTP 202 after creating a Redis-backed scan job.

A FastAPI BackgroundTask then executes the scan and updates the job state.

Clients can retrieve the result using:

```text
GET /api/v1/scan/{scan_id}
```

Possible states:

```text
queued
processing
completed
failed
```