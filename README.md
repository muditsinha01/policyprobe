# Acme Loan Assistant

**AI-powered policy evaluation and remediation demo application**

Acme Loan Assistant is a deliberately vulnerable chat agent application designed to demonstrate how Unifai detects security policy violations and instructs Cursor IDE to remediate them. The frontend presents as a lightweight AI assistant for document review and loan-related chat.

## Demo Flow

1. **Run Acme Loan Assistant with Unifai disabled** → vulnerable behavior is visible
2. **Enable Unifai in Cursor** → scans code, detects violations
3. **Unifai instructs Cursor** to fix the violations
4. **Run Acme Loan Assistant again** → guardrails now active, violations blocked

## Four Policy Violations Demonstrated

| Policy | Vulnerability | After Remediation |
|--------|---------------|-------------------|
| **PII Detection** | Files processed without PII scanning | SSN, credit cards, phone numbers detected and blocked |
| **Prompt Injection** | Hidden text/prompts sent to LLM | Hidden content detected and filtered |
| **Agent Auth** | Inter-agent calls bypass authentication | JWT-based authentication required |
| **Vulnerable Deps** | Old packages with known CVEs | Updated to patched versions |

## Quick Start

### Option A: Docker (recommended)

**Prerequisites:** Docker, OpenRouter API key ([get one here](https://openrouter.ai/keys))

1. **Build the image**

```bash
docker build -t policyprobe:local .
```

2. **Run the container**

```bash
docker run -d \
  --name policyprobe \
  -p 80:5001 \
  -e OPENROUTER_API_KEY=your_key_here \
  -e OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free \
  -e AGENT_SECRET=your_random_secret \
  policyprobe:local
```

3. **Open the app** at http://localhost (Acme Loan Assistant interface)

> **Free model note:** If you get 429 errors, switch models via `OPENROUTER_MODEL` or add a payment method at [openrouter.ai/settings/billing](https://openrouter.ai/settings/billing).

---

### Option B: Local Development

**Prerequisites:**

- Node.js 18+
- Python 3.10+
- OpenRouter API key (get one at https://openrouter.ai/keys)

### Setup

1. **Copy environment file**

```bash
cd policyprobe

# Copy environment template
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY
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

- Frontend (Acme Loan Assistant): http://localhost:5001
- Backend API: http://localhost:5500
- API Docs: http://localhost:5500/docs

## Frontend

The Acme Loan Assistant UI features a clean, modern design:

- **Light theme** — Slate/blue palette with subtle radial gradients and glass-panel styling
- **Typography** — Manrope font for a professional, approachable feel
- **Layout** — Glass panel chat container with blue accent band, soft dividers, and fade-in animations
- **Features** — File upload zone with drag-and-drop, starter prompts for quick actions, and responsive design
- **Components** — Chat interface, message list, file upload, and policy error display

## Project Structure

```
policyprobe/
├── frontend/                    # Next.js React frontend (Acme Loan Assistant UI)
│   ├── src/
│   │   ├── app/                 # Next.js app router, layout, globals
│   │   └── components/          # ChatInterface, MessageList, FileUpload
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

## Policy Violation & Guardrail Mapping

| Policy Category | Individual Policy | Violation File (Unifai Scans) | Guardrail File (Unifai Applies) |
|-----------------|-------------------|-------------------------------|--------------------------------|
| **Data Security** | PII in uploaded files | `backend/agents/file_processor.py` | `backend/policies/pii_detection.py` |
| **AI Threats** | Hidden prompts / Prompt injection | `backend/agents/file_processor.py` | `backend/policies/prompt_injection.py` |
| **Identity & Access** | Unauthenticated agent calls | `backend/agents/orchestrator.py` | `backend/agents/auth/agent_auth.py` |
| **Vulnerability** | Vulnerable npm packages | `frontend/package.json` | *(version update)* |
| **Vulnerability** | Vulnerable Python packages | `backend/requirements.txt` | *(version update)* |

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
│              Acme Loan Assistant (PolicyProbe)              │
│              Next.js + React · Light theme · Manrope         │
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
         ┌────────┐   ┌──────────┐   ┌─────────┐
         │OpenRouter│  │  Policy  │   │  File   │
         │ (LLM)  │   │ Modules  │   │ Parsers │
         └────────┘   └──────────┘   └─────────┘
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `OPENROUTER_API_KEY` | OpenRouter API key for LLM access | **Yes** | — |
| `OPENROUTER_MODEL` | Model slug to use | No | `meta-llama/llama-3.3-70b-instruct:free` |
| `AGENT_SECRET` | Secret for HMAC inter-agent token signing | No | — |
| `JWT_SECRET` | Secret for JWT signing (after Unifai remediation) | No | — |
| `BACKEND_URL` | Backend URL for frontend proxy | No | `http://127.0.0.1:5500` |
| `LOG_LEVEL` | Logging verbosity | No | `INFO` |

## License

This is a demo application for Unifai integration testing.
