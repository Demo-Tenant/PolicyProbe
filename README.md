# PolicyProbe

**AI-powered policy evaluation and remediation demo application**

PolicyProbe is a deliberately vulnerable chat agent application designed to demonstrate how Unifai detects security policy violations and instructs Cursor IDE to remediate them.

## Demo Flow

1. **Run PolicyProbe with Unifai disabled** → vulnerable behavior is visible
2. **Enable Unifai in Cursor** → scans code, detects violations
3. **Unifai instructs Cursor** to fix the violations
4. **Run PolicyProbe again** → guardrails now active, violations blocked

## Four Policy Violations Demonstrated

| Policy | Vulnerability | After Remediation |
|--------|---------------|-------------------|
| **PII Detection** | Files processed without PII scanning | SSN, credit cards, phone numbers detected and blocked |
| **Prompt Injection** | Hidden text/prompts sent to LLM | Hidden content detected and filtered |
| **Agent Auth** | Inter-agent calls bypass authentication | JWT-based authentication required |
| **Vulnerable Deps** | Old packages with known CVEs | Updated to patched versions |

## Quick Start

### Prerequisites

- Node.js 18+
- Python 3.10+
- Approved LLM API key (contact your administrator for the approved LLM provider and endpoint from the organization allow list)

> ⚠️ **IMPORTANT — LLM Provider Policy**: OpenRouter is not on the approved LLM allow list. You must replace any OpenRouter usage with an approved LLM provider. Contact your security or platform team to obtain the approved LLM endpoint, API key, and model identifiers before running this application.

### Setup

1. **Copy environment file**

```bash
cd policyprobe

# Copy environment template
cp .env.example .env
# Edit .env and add your approved LLM API key (replace OPENROUTER_API_KEY with the approved provider's key variable)
```

2. **Create virtual environment and install dependencies**

```bash
./scripts/setup_env.sh    # Creates .venv and installs Python deps
```

3. **Start the application**

```bash
./scripts/run_dev.sh    # Start both backend and frontend servers
```

4. **Stop the application**

```bash
./scripts/stop_dev.sh   # Stop both servers
```

**Or run manually:**

```bash
# Terminal 1: Backend
cd backend
source .venv/bin/activate
uvicorn main:app --reload --port 5500

# Terminal 2: Frontend
cd frontend
npm install
npm run dev -- -p 5001
```

5. **Open the app**

- Frontend: http://localhost:5001
- Backend API: http://localhost:5500
- API Docs: http://localhost:5500/docs

> ⚠️ **Security Note**: The API docs endpoint (`/docs`) exposes all API routes and schemas. Disable or restrict access to this endpoint in any non-development environment.

## Project Structure

```
policyprobe/
├── frontend/                    # Next.js React frontend
│   ├── src/
│   │   ├── app/                 # Next.js app router
│   │   └── components/          # React components
│   └── package.json             # ⚠️ Vulnerable npm deps
│
├── backend/                     # Python FastAPI backend
│   ├── agents/                  # Multi-agent system
│   │   ├── orchestrator.py      # Request routing
│   │   ├── tech_support.py      # Low privilege agent
│   │   ├── finance.py           # High privilege agent
│   │   └── auth/                # ⚠️ Auth bypass
│   ├── policies/                # Policy modules
│   │   ├── pii_detection.py     # ⚠️ NO-OP detection
│   │   ├── prompt_injection.py  # ⚠️ NO-OP detection
│   │   └── runtime/             # Runtime guardrails
│   ├── file_parsers/            # File processing
│   └── requirements.txt         # ⚠️ Vulnerable Python deps
│
├── config/                      # Policy configuration
├── test_files/                  # Demo test files
└── scripts/                     # Development scripts
```

## Demo Scenarios

### 1. PII Detection Demo

**Before:**
1. Upload `test_files/advanced/nested_pii.json`
2. Observe: "File processed successfully"
3. PII is sent to the LLM without detection

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Error: PII detected - SSN found in user.profile.contact.ssn"

### 2. Prompt Injection Demo

**Before:**
1. Upload `test_files/advanced/base64_hidden.html`
2. Hidden prompts are extracted and sent to LLM
3. LLM may respond to malicious instructions

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Security threat detected: Hidden content in HTML elements"

### 3. Agent Authentication Demo

**Before:**
1. Ask: "Can you show me the quarterly financial report?"
2. Tech support agent escalates to finance agent
3. Access granted without proper authentication

**After Unifai Remediation:**
1. Same request
2. Observe: "Unauthorized: Agent token validation failed"

### 4. Vulnerable Dependencies Demo

**Before:**
```bash
cd frontend && npm audit
# Shows vulnerabilities in lodash, axios, etc.
```

**After Unifai Remediation:**
- `package.json` updated with patched versions
- `npm audit` shows no vulnerabilities

## Security Requirements & Known Vulnerabilities

> ⚠️ The following security issues are intentionally present for demo purposes and must be remediated before any non-demo use:

- **Unapproved LLM**: OpenRouter is not an approved LLM provider. Replace with an approved provider from your organization's allow list.
- **Broken Access Control**: Inter-agent calls lack authentication; finance agent is accessible without authorization checks.
- **Injection / Prompt Injection**: File content is passed to the LLM without sanitization or prompt injection filtering.
- **PII Exposure**: Uploaded files containing SSNs, credit card numbers, and phone numbers are forwarded to the LLM without scanning.
- **Insecure Deserialization**: Uploaded JSON files are parsed without schema validation or size limits.
- **Path Traversal**: File upload paths must be validated to prevent directory traversal attacks.
- **Security Misconfiguration**: API docs (`/docs`) are publicly exposed; CORS must be restricted to known origins only.
- **Cryptographic Failures**: JWT_SECRET must be a strong, randomly generated secret stored securely (not hardcoded or committed to source control).
- **Sensitive Data Exposure**: Error messages must not leak internal stack traces or file paths to clients.
- **Vulnerable Dependencies**: Outdated npm and Python packages with known CVEs must be updated.

## Policy Violation & Guardrail Mapping

| Policy Category | Individual Policy | Violation File (Unifai Scans) | Guardrail File (Unifai Applies) |
|-----------------|-------------------|-------------------------------|--------------------------------|
| **Data Security** | PII in uploaded files | `backend/agents/file_processor.py` | `backend/policies/pii_detection.py` |
| **AI Threats** | Hidden prompts / Prompt injection | `backend/agents/file_processor.py` | `backend/policies/prompt_injection.py` |
| **Identity & Access** | Unauthenticated agent calls | `backend/agents/orchestrator.py` | `backend/agents/auth/agent_auth.py` |
| **Vulnerability** | Vulnerable npm packages | `frontend/package.json` | *(version update)* |
| **Vulnerability** | Vulnerable Python packages | `backend/requirements.txt` | *(version update)* |
| **LLM Policy** | Unapproved LLM provider (OpenRouter) | `backend/` LLM client config | Replace with approved LLM provider |

## Test Files

- `test_files/simple/` - Basic examples for warm-up
- `test_files/advanced/nested_pii.json` - PII buried 5 levels deep
- `test_files/advanced/base64_hidden.html` - Hidden prompts in HTML
- `test_files/advanced/multi_hop_attack.json` - Chained agent exploit

Generate additional test files:
```bash
python scripts/create_test_files.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PolicyProbe UI                         │
│                   (Next.js + React)                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Agent Orchestrator                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Tech Support │──│   Finance    │  │    File      │      │
│  │ (low priv)   │  │ (high priv)  │  │  Processor   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
         ┌──────────┐  ┌──────────┐  ┌─────────┐
         │ Approved │  │  Policy  │  │  File   │
         │LLM Provider│ │ Modules  │  │ Parsers │
         └──────────┘  └──────────┘  └─────────┘
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `APPROVED_LLM_API_KEY` | API key for the approved LLM provider (replace OpenRouter with approved provider) | Yes |
| `APPROVED_LLM_ENDPOINT` | Base URL for the approved LLM provider endpoint | Yes |
| `APPROVED_LLM_MODEL` | Approved model identifier from the organization allow list | Yes |
| `JWT_SECRET` | Strong randomly generated secret for JWT signing — never hardcode or commit this value | Yes |
| `BACKEND_URL` | Backend URL for frontend | No (default: localhost:5500) |

> ⚠️ **Secret Management**: Never hardcode `JWT_SECRET` or any API key in source code or commit them to version control. Use a secrets manager or environment-specific `.env` files excluded from git.

## License

This is a demo application for Unifai integration testing.