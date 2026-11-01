# v0.8 Provider routing and trust boundaries

- **Configured choices only:** `GET /api/v1/ai/status` publishes server-approved provider identifiers and model strings. No secrets or endpoint URLs appear in the response.
- **Per-request selector:** `POST /api/v1/findings/{id}/ai/analyze` can include `provider_id` and `model`; omitted fields preserve the v0.7 default. Unconfigured provider IDs and model IDs not in the published list are rejected before any model call.
- **Credentials remain server-side:** `CLOUDSENTINEL_AI_{GROQ|OPENAI|GEMINI|ANTHROPIC}_API_KEY`, legacy default-only `CLOUDSENTINEL_AI_API_KEY`; private API credentials use `CLOUDSENTINEL_PRIVATE_AI_API_KEY`.
- **Private endpoint:** `CLOUDSENTINEL_PRIVATE_AI_BASE_URL`, `CLOUDSENTINEL_PRIVATE_AI_MODEL`. User-supplied URLs are not accepted in the API. Only HTTPS or local loopback HTTP is accepted by default. Explicit private-IP HTTP opt-in is available for isolated development networks. No redirects, no trust in environment proxies, TLS verification remains on.
- **Prompt contents:** redacted bounded metadata only, sent by explicit human opt-in. Redaction is *best effort* and may not remove every identifier. Do not analyze sensitive findings on untrusted hosted models.
- **Cache:** provider and model are part of the fingerprint; changing the operator-configured private base URL also invalidates cached private advice. History stores only validated output + provider/model label, not prompts or API keys.
- **Responses:** provider output must satisfy the validated remediation schema. Groq GPT-OSS uses strict structured JSON, while other models or private hosts may generate invalid JSON and fail closed.
- **Security boundary:** current FastAPI/Next.js dev setup is localhost-only with a write token but **not user authentication**. This is unsuitable for shared hosting / public exposure or for allowing untrusted users to configure provider destinations.

Supported external adapters currently include Groq, OpenAI, Gemini and Anthropic. The private adapter is compatible with Ollama/vLLM/other `/v1/chat/completions` endpoints subject to model features, but no live private-host test has been performed here.
