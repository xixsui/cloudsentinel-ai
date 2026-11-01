"""Server-defined OpenAI-compatible endpoint (Ollama, vLLM, internal gateways).

The URL is ONLY supplied by operator environment configuration, never by a
browser request. TLS verification remains enabled. No fallback to remote
providers occurs if this profile fails.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

from ai_module.providers.base import BaseProvider, CompletionResult, ProviderInfo


class PrivateEndpointConfigurationError(ValueError):
    pass


def validate_private_base_url(url: str) -> str:
    """Validate a server operator-configured /v1 endpoint.

    HTTPS is required unless the destination is loopback. Plain HTTP to a
    private IP is an explicit opt-in for isolated development networks only.
    This does not make an untrusted endpoint safe; operators must control it.
    """
    if not url or len(url) > 350 or any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise PrivateEndpointConfigurationError("Private model URL is missing or invalid")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname or \
                parsed.username is not None or parsed.password is not None or \
                parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/v1":
            raise ValueError("Invalid endpoint structure")
        hostname = parsed.hostname
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            ip = None
        loopback = hostname == "localhost" or (ip is not None and ip.is_loopback)
        allow_http_private = (
            os.getenv("CLOUDSENTINEL_PRIVATE_ALLOW_HTTP", "").strip().lower()
            in ("1", "true", "yes")
        )
        if parsed.scheme == "http" and not loopback:
            if not (allow_http_private and ip is not None and ip.is_private and not ip.is_link_local):
                raise ValueError("Plain HTTP requires loopback or explicit private-IP opt-in")
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise ValueError("Invalid endpoint port")
        if parsed.hostname in ("169.254.169.254", "metadata.google.internal"):
            raise ValueError("Metadata endpoints forbidden")
        return url.rstrip("/")
    except (ValueError, TypeError) as exc:
        raise PrivateEndpointConfigurationError(
            "Private model URL must be an operator-approved /v1 endpoint using HTTPS, "
            "or loopback HTTP (private-IP HTTP requires explicit opt-in)"
        ) from exc


class PrivateProvider(BaseProvider):
    info = ProviderInfo(
        id="private", display_name="Self-hosted / Private API",
        requires_api_key=False, models=[], default_model="",
        api_key_help="Set CLOUDSENTINEL_PRIVATE_AI_BASE_URL and CLOUDSENTINEL_PRIVATE_AI_MODEL on the server.",
        homepage="https://docs.ollama.com/openai",
        pricing_note="Local model hardware and endpoint policies apply.",
    )

    def __init__(self, api_key=None, model=None, rate_limit_seconds=1.0, base_url=None):
        super().__init__(api_key=api_key, model=model, rate_limit_seconds=rate_limit_seconds)
        self.base_url = validate_private_base_url(base_url or "")

    def _ensure_client(self):
        if self._client is None:
            from openai import OpenAI
            import httpx
            # OpenAI-compatible SDK requires an API key even when the local
            # Ollama endpoint ignores it. Never put this placeholder in a log.
            self._client = OpenAI(
                api_key=self.api_key or "local-placeholder-not-a-secret",
                base_url=self.base_url,
                timeout=60.0,
                max_retries=0,
                # Reject redirects and environment proxy routing to keep the
                # configured internal destination fixed for each request.
                http_client=httpx.Client(follow_redirects=False, trust_env=False, timeout=60.0),
            )

    def complete(self, prompt: str, max_tokens: int = 4096) -> CompletionResult:
        self._throttle()
        try:
            self._ensure_client()
            resp = self._client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
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
        except Exception:
            return CompletionResult(text="", model=self.model, error="provider_request_failed")
