# PhishGuard AI — Deployment

## Production Architecture

```text
Internet
   │
   ├──► Vercel
   │      └── React Frontend
   │
   └──► Render
          └── FastAPI Backend
                 │
                 ├── PostgreSQL
                 ├── Redis
                 └── VirusTotal API
```

## Frontend

Platform:

Vercel

Production URL:

https://phish-guard-ai-gamma.vercel.app/

Frontend environment variable:

```text
VITE_API_BASE_URL=https://phishguard-ai-g1pz.onrender.com
```

## Backend

Platform:

Render

Production URL:

https://phishguard-ai-g1pz.onrender.com/

The backend is containerized using Docker.

## Database

PostgreSQL is used for persistent application data and scan history.

## Redis

Redis is used for:

- Scan result caching
- Rate limiting
- Async scan job state

The production Redis connection uses TLS where required by the hosted provider.

## Environment Variables

Production secrets must be configured through the hosting platform.

Example:

```env
DATABASE_URL=
REDIS_URL=
JWT_SECRET_KEY=
VIRUSTOTAL_API_KEY=
APP_ENV=
```

Never commit these values to Git.

## Deployment Flow

```text
Git Push
   │
   ▼
GitHub
   │
   ├──────────────► Vercel
   │                  │
   │                  ▼
   │              Frontend
   │
   └──────────────► Render
                      │
                      ▼
                  Docker Build
                      │
                      ▼
                  FastAPI API
```

## Production Verification

Validated production functionality includes:

- Frontend deployment
- Backend deployment
- CORS
- JWT authentication
- PostgreSQL connectivity
- Redis connectivity
- Synchronous scanning
- Asynchronous scanning
- ML inference
- Threat intelligence integration
- Rate limiting
- Redis failure tolerance
- Input validation
- Security headers