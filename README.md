<<<<<<< HEAD
# pr-security-reviewer
=======
# PR Security Reviewer

A GitHub App that automatically scans pull requests for security vulnerabilities and posts inline comments with fixes.

## Features

- ✅ Detects hardcoded secrets (AWS keys, GitHub tokens, API keys)
- ✅ Finds SQL injection vulnerabilities
- ✅ Checks for missing security headers (helmet)
- ✅ Identifies dangerous code execution (eval, exec)
- ✅ Detects missing CSRF protection in Flask apps
- ✅ Posts line-level PR comments
- ✅ Creates check run summaries

## Architecture
```
GitHub PR → Webhook → ngrok → API Server → Redis Queue → Worker → Scan Code → Post Comments
```

## Technologies

- **Backend:** Node.js, TypeScript, Express
- **Database:** PostgreSQL (Prisma ORM)
- **Queue:** Redis + BullMQ
- **GitHub:** GitHub App + REST API

## Setup

### Prerequisites
- Node.js 18+
- Docker & Docker Compose
- ngrok account
- GitHub App

### Installation

1. Clone repository:
```bash
git clone https://github.com/YOUR_USERNAME/pr-security-reviewer.git
cd pr-security-reviewer
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env with your GitHub App credentials
```

4. Start services:
```bash
docker-compose up -d
npm run dev:api    # Terminal 1
npm run dev:worker # Terminal 2
ngrok http 3000    # Terminal 3
```

5. Update GitHub App webhook URL with ngrok URL

6. Install app on a repository and create a PR to test!

## Security Rules

| ID | Language | Rule | Severity |
|----|----------|------|----------|
| SEC-001 | JS/TS | Hardcoded secrets | High |
| SEC-002 | JS/TS | SQL injection | High |
| SEC-003 | JS/TS | Missing helmet | Medium |
| SEC-004 | JS/TS | Dangerous eval/exec | High |
| SEC-005 | Python | Missing CSRF | Medium |

## Adding New Rules

See `src/rules/engine.ts` and existing rule files for examples.

## License

MIT
>>>>>>> a62e95f (Initial commit: PR Security Reviewer MVP)
