"""
Groq provider — fastest inference, generous free tier, runs open-source models.

Great as a fallback when your Anthropic/OpenAI credit runs out, or for high-
volume testing without burning paid credits.
"""

from __future__ import annotations

from ai_module.providers.base import BaseProvider, CompletionResult, ProviderInfo


class GroqProvider(BaseProvider):
    info = ProviderInfo(
        id="groq",
        display_name="Groq (Hosted Models)",
        requires_api_key=True,
        models=[
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "llama-3.1-8b-instant",
        ],
        default_model="openai/gpt-oss-120b",
        api_key_help="Get a free key at console.groq.com — no credit card required.",
        homepage="https://console.groq.com/keys",
        pricing_note="Free tier: 30 req/min, 1000 req/day. Paid: ~$0.59/1M input on 70B.",
    )

    def _ensure_client(self) -> None:
        if self._client is None:
            from groq import Groq
            self._client = Groq(api_key=self.api_key)

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

    def complete_structured(self, prompt: str, schema: dict, max_tokens: int = 4096) -> CompletionResult:
        """Request strictly validated JSON for GPT-OSS remediation outputs.

        Other Groq models retain the legacy path for compatibility. Strict
        schema is supported by Groq GPT-OSS 20B and 120B as of Oct 2026.
        No raw prompt/response is logged or returned in error messages.
        """
        if self.model not in ("openai/gpt-oss-20b", "openai/gpt-oss-120b"):
            return self.complete(prompt, max_tokens=max_tokens)

        self._throttle()
        try:
            self._ensure_client()
            resp = self._client.chat.completions.create(
                model=self.model,
                max_completion_tokens=max_tokens,
                reasoning_effort="low",
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "cloudsentinel_remediation",
                        "strict": True,
                        "schema": schema,
                    },
                },
                messages=[{"role": "user", "content": prompt}],
            )
            choice = resp.choices[0]
            if getattr(choice, "finish_reason", None) == "length":
                return CompletionResult(text="", model=self.model, error="truncated_output")
            usage = getattr(resp, "usage", None)
            return CompletionResult(
                text=choice.message.content or "",
                input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
                output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
                model=self.model,
            )
        except Exception:  # Provider details may include secrets; never surface them.
            return CompletionResult(text="", model=self.model, error="provider_request_failed")
