# AI Settings

Open `/settings` to save provider credentials and choose a default provider/model. Finding pages display that selection, link back to Settings and retain per-analysis consent. Changing a default does not rewrite saved model responses or their provider/model cache identity.

## Credentials and persistence

- Credentials are sent only to the same-origin local API when Save is pressed. Input is masked, cleared after each attempt, never placed in browser storage, and never returned by the API.
- Saving is local only: it does not call a provider or prove a key is valid. Model lists remain the backend's approved catalog. Private endpoint URLs/models remain operator-configured; the browser cannot supply URLs.
- Linux/WSL stores Fernet-encrypted settings at `~/.config/cloudsentinel-ai/settings.enc` with a separate `master.key`. The directory is 0700 and both files are 0600. `CLOUDSENTINEL_AI_SETTINGS_DIR` is an optional server-only path override; keep it on a private Linux filesystem outside the project.
- The master key and encrypted file must be backed up together in private storage. They are intentionally not part of source-code ZIPs or the findings database. Losing the master key requires re-entering credentials. Do not publish either file.
- Encryption plus file permissions protects the files from casual disclosure and other unprivileged OS users; it does **not** protect against the same OS account or an administrator reading both files. This remains a trusted local, single-user app without login/RBAC. Keep all services loopback-only.
- Corrupt ciphertext or unsafe file permissions fail closed. Native Windows browser-based persistence is currently disabled; environment credentials continue to work there. The current deployment uses Ubuntu-24.04.
- Server environment credentials take precedence and are shown as server-managed. The page rejects attempts to replace/remove those credentials. Local saved keys can be replaced or removed, with no effect on other providers.
- Explicitly save a default after configuring credentials. A saved default that becomes unavailable is not silently rerouted to another provider.

## API

- `GET /api/v1/settings/ai`: configuration booleans, non-secret credential source, approved models and effective/saved defaults.
- `PUT /api/v1/settings/ai/credential`: `{provider, action: "save" | "remove", api_key?}`. Key length is bounded; errors omit submitted values. No key is echoed on success or failure.
- `PUT /api/v1/settings/ai/default`: `{provider, model}` validated against configured providers and approved models.

Both writes retain the backend write token and the Next.js origin/host checks. Unexpected request fields are rejected, and validation errors do not include input bodies. Saving or removing keys never changes AWS resources.

## Verification

Offline tests cover encrypted storage and permissions, response/error non-disclosure, credential precedence/removal, default persistence/routing, corrupt-storage handling and concurrent updates. No real credentials or paid AI requests are used. Native Windows uses environment configuration; storage tests run in Ubuntu-24.04.
