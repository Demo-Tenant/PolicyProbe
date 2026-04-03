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
- Approved LLM API key (NOTE: OpenRouter is not on the approved LLM allow list. You must use an approved LLM provider such as your organization's sanctioned Azure OpenAI endpoint or other approved provider. Contact your security team for the current allow list and credentials.)

### Setup

1. **Copy environment file**

```bash
cd policyprobe

# Copy environment template
cp .env.example .env
# Edit .env and add your approved LLM API key
# WARNING: Never hardcode secrets or API keys in source files
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

## Project Structure

```
policyprobe/
├── frontend/                    # Next.js React frontend
│   ├── src/
│   │   ├── app/                 # Next.js app router
│   │   └── components/          # React components
│   └── package.json             # ⚠️ Vulnerable npm deps (remediate with approved, patched versions)
│
├── backend/                     # Python FastAPI backend
│   ├── agents/                  # Multi-agent system
│   │   ├── orchestrator.py      # Request routing
│   │   ├── tech_support.py      # Low privilege agent
│   │   ├── finance.py           # High privilege agent
│   │   └── auth/                # ⚠️ Auth bypass (remediate: enforce JWT validation)
│   ├── policies/                # Policy modules
│   │   ├── pii_detection.py     # ⚠️ NO-OP detection (remediate: implement real PII scanning)
│   │   ├── prompt_injection.py  # ⚠️ NO-OP detection (remediate: implement real injection filtering)
│   │   └── runtime/             # Runtime guardrails
│   ├── file_parsers/            # File processing (remediate: enforce path traversal protection and input validation)
│   └── requirements.txt         # ⚠️ Vulnerable Python deps (remediate with patched versions)
│
├── config/                      # Policy configuration
├── test_files/                  # Demo test files
└── scripts/                     # Development scripts
```

## Security Notes

- **Approved LLM Only:** Replace any reference to OpenRouter with your organization's approved LLM provider. Using unapproved LLMs violates policy and may expose sensitive data.
- **No Hardcoded Secrets:** All API keys, JWT secrets, and credentials must be loaded from environment variables. Never commit secrets to source control.
- **Input Validation:** All file uploads and user inputs must be validated and sanitized to prevent injection, path traversal, and XSS attacks.
- **Authentication:** All inter-agent calls must use JWT-based authentication. Unauthenticated calls must be rejected.
- **Output Encoding:** All data rendered in the frontend must be properly encoded to prevent XSS.
- **Error Handling:** Do not expose stack traces or internal error details to end users.
- **Dependency Management:** Keep all dependencies updated to patched versions. Run `npm audit` and `pip-audit` regularly.

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

## Policy Violation & Guardrail Mapping

| Policy Category | Individual Policy | Violation File (Unifai Scans) | Guardrail File (Unifai Applies) |
|-----------------|-------------------|-------------------------------|--------------------------------|
| **Data Security** | PII in uploaded files | `backend/agents/file_processor.py` | `backend/policies/pii_detection.py` |
| **AI Threats** | Hidden prompts / Prompt injection | `backend/agents/file_processor.py` | `backend/policies/prompt_injection.py` |
| **Identity & Access** | Unauthenticated agent calls | `backend/agents/orchestrator.py` | `backend/agents/auth/agent_auth.py` |
| **Vulnerability** | Vulnerable npm packages | `frontend/package.json` | *(version update)* |
| **Vulnerability** | Vulnerable Python packages | `backend/requirements.txt` | *(version update)* |
| **Approved LLM** | Unapproved LLM provider (OpenRouter) | `backend/` LLM client config | Replace with approved LLM provider |

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
         │   LLM    │  │ Modules  │  │ Parsers │
         └──────────┘  └──────────┘  └─────────┘
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `APPROVED_LLM_API_KEY` | API key for your organization's approved LLM provider (do NOT use OpenRouter) | Yes |
| `JWT_SECRET` | Secret for JWT signing — must be set via environment variable, never hardcoded | Yes |
| `BACKEND_URL` | Backend URL for frontend | No (default: localhost:5500) |

## License

This is a demo application for Unifai integration testing.