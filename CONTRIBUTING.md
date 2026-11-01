# Contributing

1. Open an issue explaining the proposed change, especially if it changes detection semantics or cloud permissions.
2. Never commit secrets, `.env`, raw cloud findings, real AWS logs or SQLite data.
3. Add local deterministic tests and run `python -m pytest -q`.
4. Keep detector and correlator logic separate from AI explanation; make assumptions and false-positive implications explicit.
5. Use least-privilege AWS credentials and verify TLS for network integrations.

Contributions are not automatically assumed to be safe for production deployment.
