"""raphael_ibm_bob.harness.providers — model provider adapters.

Only the boundary the Harness needs: env-driven configuration plus
ONE real provider (OpenAI-compatible HTTP, stdlib `urllib` — no new
dependencies). No routing, marketplace, fallback orchestration, or
multi-provider platform.

Credential discipline (enforced by tests):
- Keys come ONLY from the environment, never code or tests.
- The key is sent as an HTTP header and NEVER appears in
  exceptions, logs, evidence payloads, or returned objects.
- `.env` files are never read by this module; no secret is written
  anywhere. Missing configuration fails loudly before any request.

If no endpoint/credentials exist in an environment, nothing here can
run live — that is reported as BLOCKED, never faked.
"""
from raphael_ibm_bob.harness.providers.config import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_PROVIDER,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    PROVIDER_DEFAULT_ENDPOINTS,
    ProviderBuilder,
    ProviderConfig,
    ProviderRegistry,
    build_provider_config,
    default_provider_registry,
    provider_default_endpoint,
)

from raphael_ibm_bob.harness.providers.openai_compat import (
    DoneSignal,
    OpenAICompatAdapter,
    OpenAICompatConfig,
    ProviderCancelled,
    ProviderConfigError,
    ProviderError,
    ProviderTimeout,
    StructuredProposalError,
    provider_from_env,
)

__all__ = [
    "DEFAULT_MAX_TOKENS",
    "PROVIDER_DEFAULT_ENDPOINTS",
    "DEFAULT_PROVIDER",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_TIMEOUT_SECONDS",
    "DoneSignal",
    "OpenAICompatAdapter",
    "OpenAICompatConfig",
    "ProviderBuilder",
    "ProviderCancelled",
    "ProviderConfig",
    "ProviderConfigError",
    "ProviderError",
    "ProviderRegistry",
    "ProviderTimeout",
    "StructuredProposalError",
    "build_provider_config",
    "default_provider_registry",
    "provider_default_endpoint",
    "provider_from_env",
]
