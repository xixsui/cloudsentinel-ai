"""
LLM Provider abstraction.

Each provider (Anthropic, OpenAI, Gemini, Groq) implements a tiny common
interface. The analyzer calls Provider.complete(prompt) without caring which
backend it is. Adding a new provider = one new file in this folder.

Each provider also declares:
- a list of supported model IDs (so the UI can show a dropdown)
- whether it needs an API key (for the Settings page UX)
- a way to test the credentials (so the Settings page can run a connection test)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class CompletionResult:
    """Standard return type for every provider's complete() call."""
    text: str                         # the model's raw text output
    input_tokens: int = 0             # for usage tracking on the Settings page
    output_tokens: int = 0
    model: str = ""
    error: Optional[str] = None       # set if the call failed


@dataclass
class ProviderInfo:
    """Static metadata about a provider — used by the Settings UI."""
    id: str                            # e.g. "anthropic"
    display_name: str                  # e.g. "Anthropic (Claude)"
    requires_api_key: bool
    models: list[str]                  # selectable model IDs, default first
    default_model: str
    api_key_help: str                  # short instruction shown next to the input
    homepage: str                      # where the user gets a key
    pricing_note: str = ""             # short hint shown in UI


class BaseProvider:
    """All providers inherit from this. Override complete() and test()."""

    info: ProviderInfo  # subclasses must set this

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 rate_limit_seconds: float = 1.0):
        self.api_key = api_key
        self.model = model or self.info.default_model
        self.rate_limit_seconds = rate_limit_seconds
        self._last_call = 0.0
        self._client = None

    def _throttle(self) -> None:
        """Client-side rate limit so we never burst."""
        elapsed = time.time() - self._last_call
        if elapsed < self.rate_limit_seconds:
            time.sleep(self.rate_limit_seconds - elapsed)
        self._last_call = time.time()

    def complete(self, prompt: str, max_tokens: int = 1024) -> CompletionResult:
        """Call the LLM. Subclasses must override."""
        raise NotImplementedError

    def test(self) -> tuple[bool, str]:
        """
        Quick credential / connectivity check used by the Settings page.
        Returns (ok, message).
        """
        try:
            r = self.complete("Respond with exactly the word: OK", max_tokens=10)
            if r.error:
                return False, r.error
            return True, f"OK — model responded ({r.output_tokens} output tokens)"
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Registry — discovered at import time. Settings page reads this for the
# backend dropdown and per-provider metadata.
# ---------------------------------------------------------------------------
from ai_module.providers.anthropic_provider import AnthropicProvider  # noqa: E402
from ai_module.providers.openai_provider import OpenAIProvider        # noqa: E402
from ai_module.providers.gemini_provider import GeminiProvider        # noqa: E402
from ai_module.providers.groq_provider import GroqProvider            # noqa: E402
from ai_module.providers.private_provider import PrivateProvider      # noqa: E402

PROVIDERS: dict[str, type[BaseProvider]] = {
    GeminiProvider.info.id:    GeminiProvider,
    OpenAIProvider.info.id:    OpenAIProvider,
    AnthropicProvider.info.id: AnthropicProvider,
    GroqProvider.info.id:      GroqProvider,
    PrivateProvider.info.id:   PrivateProvider,
}


def get_provider(provider_id: str, api_key: Optional[str] = None,
                 model: Optional[str] = None, **kwargs) -> BaseProvider:
    """Factory used by the analyzer and the Settings page."""
    if provider_id not in PROVIDERS:
        raise ValueError(
            f"Unknown provider '{provider_id}'. Available: {list(PROVIDERS)}"
        )
    cls = PROVIDERS[provider_id]
    return cls(api_key=api_key, model=model, **kwargs)


def list_providers() -> list[ProviderInfo]:
    """Settings page calls this to render the backend dropdown."""
    return [cls.info for cls in PROVIDERS.values()]
