"""Anthropic (Claude) provider."""

from __future__ import annotations

from ai_module.providers.base import BaseProvider, CompletionResult, ProviderInfo


class AnthropicProvider(BaseProvider):
    info = ProviderInfo(
        id="anthropic",
        display_name="Anthropic (Claude)",
        requires_api_key=True,
        models=[
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-5",
            "claude-opus-4-5",
        ],
        default_model="claude-haiku-4-5-20251001",
        api_key_help="Get a key at console.anthropic.com — new accounts get $5 free credit.",
        homepage="https://console.anthropic.com",
        pricing_note="Haiku ~$1 / 1M input tokens. Sonnet ~$3. Opus ~$15.",
    )

    def _ensure_client(self) -> None:
        if self._client is None:
            from anthropic import Anthropic  # lazy import so we don't crash if not installed
            self._client = Anthropic(api_key=self.api_key)

    def complete(self, prompt: str, max_tokens: int = 1024) -> CompletionResult:
        self._throttle()
        try:
            self._ensure_client()
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(
                b.text for b in resp.content if getattr(b, "type", "") == "text"
            )
            return CompletionResult(
                text=text,
                input_tokens=getattr(resp.usage, "input_tokens", 0),
                output_tokens=getattr(resp.usage, "output_tokens", 0),
                model=self.model,
            )
        except Exception as e:  # noqa: BLE001
            return CompletionResult(text="", model=self.model, error=str(e))
