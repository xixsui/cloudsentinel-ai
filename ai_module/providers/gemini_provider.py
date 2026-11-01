"""Google Gemini provider — generous free tier, great for student projects."""

from __future__ import annotations

from ai_module.providers.base import BaseProvider, CompletionResult, ProviderInfo


class GeminiProvider(BaseProvider):
    info = ProviderInfo(
        id="gemini",
        display_name="Google Gemini",
        requires_api_key=True,
        models=[
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
            "gemini-2.5-pro",
        ],
        default_model="gemini-2.5-flash",
        api_key_help="Get a free key at aistudio.google.com — Flash models have a free tier.",
        homepage="https://aistudio.google.com/apikey",
        pricing_note="Flash-Lite ~$0.10 / 1M input. Flash ~$0.30. Free tier available.",
    )

    def _ensure_client(self) -> None:
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)

    def complete(self, prompt: str, max_tokens: int = 2048) -> CompletionResult:
        self._throttle()
        try:
            self._ensure_client()
            from google.genai import types

            # Gemini 2.5 Flash is a "thinking" model — it can spend a large
            # fraction of its output budget on internal reasoning tokens that
            # are never returned to us. If the max_tokens is small, thinking
            # eats the entire budget and the visible response is empty. Set
            # thinking_budget=0 (or a small value) so we get actual content.
            gen_config = types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                response_mime_type="application/json",
                thinking_config=types.ThinkingConfig(thinking_budget=0),
            )
            resp = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=gen_config,
            )
            text = resp.text or ""
            # Usage metadata sits under usage_metadata in the SDK response.
            usage = getattr(resp, "usage_metadata", None)
            return CompletionResult(
                text=text,
                input_tokens=getattr(usage, "prompt_token_count", 0) if usage else 0,
                output_tokens=getattr(usage, "candidates_token_count", 0) if usage else 0,
                model=self.model,
            )
        except Exception as e:  # noqa: BLE001
            return CompletionResult(text="", model=self.model, error=str(e))
