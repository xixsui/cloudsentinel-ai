"""OpenAI provider (GPT-4o family + newer)."""

from __future__ import annotations

from ai_module.providers.base import BaseProvider, CompletionResult, ProviderInfo


class OpenAIProvider(BaseProvider):
    info = ProviderInfo(
        id="openai",
        display_name="OpenAI (GPT)",
        requires_api_key=True,
        models=[
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4-turbo",
        ],
        default_model="gpt-4o-mini",
        api_key_help="Get a key at platform.openai.com — requires billing setup.",
        homepage="https://platform.openai.com/api-keys",
        pricing_note="gpt-4o-mini ~$0.15 / 1M input tokens. gpt-4o ~$2.50.",
    )

    def _ensure_client(self) -> None:
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)

    def complete(self, prompt: str, max_tokens: int = 1024) -> CompletionResult:
        self._throttle()
        try:
            self._ensure_client()
            resp = self._client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.choices[0].message.content or ""
            usage = getattr(resp, "usage", None)
            return CompletionResult(
                text=text,
                input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
                output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
                model=self.model,
            )
        except Exception as e:  # noqa: BLE001
            return CompletionResult(text="", model=self.model, error=str(e))
