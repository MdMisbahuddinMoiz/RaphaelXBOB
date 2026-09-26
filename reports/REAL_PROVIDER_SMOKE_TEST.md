MODEL: 2
ROLE: Real Provider Smoke-Test Specialist
STATUS: BLOCKED
FILES CREATED:
- /home/moiz/raphael-2.0-rbsv2r/reports/REAL_PROVIDER_SMOKE_TEST.md
FILES INSPECTED:
- /home/moiz/raphael-2.0-rbsv2r/raphael_ibm_bob/harness/model.py
- /home/moiz/raphael-2.0-rbsv2r/raphael_ibm_bob/harness/model_run.py
- /home/moiz/raphael-2.0-rbsv2r/raphael_ibm_bob/harness/providers/openai_compat.py
- /home/moiz/raphael-2.0-rbsv2r/raphael_ibm_bob/harness/providers/__init__.py
REQUIRED ENV VARS: 
- RAPHAEL_MODEL_ENDPOINT: required — no default
- RAPHAEL_MODEL_NAME: required — no default
- RAPHAEL_MODEL_API_KEY: optional — default: empty string (not required)
- RAPHAEL_MODEL_TIMEOUT: optional — default: 30.0 (seconds)
- RAPHAEL_MODEL_MAX_TOKENS: optional — default: 512
- RAPHAEL_MODEL_TEMPERATURE: optional — default: 0.0
- RAPHAEL_MODEL_EXTRA_BODY: optional — default: empty dict
- RAPHAEL_MODEL_OPENCODE_HEADERS: optional — default: None (auto-detect: True for OpenCode Go hosts, False otherwise)
CREDENTIAL LEAK PATHS FOUND: none
GOVERNANCE PRESERVED AFTER PROVIDER: YES + evidence: model_run.py:runtime.submit -> broker.submit -> policy.consult (see model_run.py line ~200: result = runtime.submit(request, mission))
VERDICT: BLOCKED — credentials unavailable
BLOCKERS:
- Missing required environment variables: RAPHAEL_MODEL_ENDPOINT and RAPHAEL_MODEL_NAME are unset.
- No .env file with credentials present (only .env.example and .env.tier2.template, which are placeholders).
- No local OpenAI-compatible endpoint listening on localhost:20128 (HTTP 000).
RECOMMENDATION TO INTEGRATOR:
To enable live provider testing, set RAPHAEL_MODEL_ENDPOINT and RAPHAEL_MODEL_NAME to point to an OpenAI-compatible service (e.g., OpenAI, OpenRouter, Ollama, vLLM, LM Studio). If the service requires authentication, set RAPHAEL_MODEL_API_KEY. Optional tuning variables can be adjusted as needed. The provider will then engage the model through the governed Runtime -> Broker -> Policy path, ensuring no bypass of Raphael's safety checks.