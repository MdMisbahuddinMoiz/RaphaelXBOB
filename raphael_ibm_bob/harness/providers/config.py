"""raphael_ibm_bob.harness.providers.config — normalized provider config.

One internal, vendor-neutral representation of "which model, where,
with which credential" that every entry point (Web UI, HTTP API, CLI,
demo) builds. Provider-specific wire formats live entirely inside the
adapter; the planner and the governed loop only ever see a
`ModelAdapter` produced by :func:`create_adapter`.

Design invariants:

- **Normalized**: a `ProviderConfig` is the single shape the rest of
  Raphael consumes. Adding a provider is a registration, not a branch
  in the planner.
- **Credential write-only**: the API key is never rendered. `repr()`,
  `str()`, and :meth:`ProviderConfig.redacted` all report `"set"` /
  `"unset"`, never the value. `ProviderConfigError` messages name the
  missing *field*, never its content.
- **No ambient authority**: a `ProviderConfig` grants no permission.
  A model built from it still proposes an `ActionRequest` that must
  cross Runtime → Broker → Policy.

`os.environ` is never mutated here. Operator-supplied values are held
per-run in memory so one operator's credential cannot leak into another
operator's concurrent run.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Mapping, Optional

from raphael_ibm_bob.harness.providers.openai_compat import ProviderConfigError

#: The provider id used when an operator selects nothing. The adapter
#: is vendor-neutral (any OpenAI-compatible HTTP endpoint), so this is a
#: wire-format name, not a vendor name.
DEFAULT_PROVIDER = "openai-compatible"

#: Bounded request knobs. Kept here so every provider shares the same
#: normalized envelope instead of each inventing its own defaults.
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_TOKENS = 512
DEFAULT_TEMPERATURE = 0.0


@dataclass(frozen=True, repr=False)
class ProviderConfig:
    """Vendor-neutral model provider configuration.

    `api_key` is deliberately excluded from the generated `__repr__`
    (`repr=False` plus the explicit `__repr__` below): an accidental
    `print(config)`, traceback, or logger call can never render a
    credential. Use :meth:`redacted` when a serializable form is needed.
    """

    provider: str = DEFAULT_PROVIDER
    endpoint: str = ""
    model: str = ""
    api_key: str = field(default="", repr=False)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    extra_body: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ProviderConfigError("provider is required")
        object.__setattr__(self, "provider", self.provider.strip())
        object.__setattr__(self, "endpoint", str(self.endpoint or "").strip())
        object.__setattr__(self, "model", str(self.model or "").strip())
        if self.timeout_seconds <= 0:
            raise ProviderConfigError("timeout_seconds must be positive")
        if self.max_tokens < 1:
            raise ProviderConfigError("max_tokens must be positive")
        if not 0.0 <= self.temperature <= 2.0:
            raise ProviderConfigError(
                "temperature must be within 0.0..2.0")

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def redacted(self) -> Dict[str, Any]:
        """Serializable view safe to return to a UI or log.

        Reports only whether a credential is present. The value, its
        length, and any prefix are all intentionally omitted.
        """
        return {
            "provider": self.provider,
            "endpoint": self.endpoint,
            "model": self.model,
            "timeout_seconds": self.timeout_seconds,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "api_key": "set" if self.has_api_key else "unset",
        }

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return ("ProviderConfig(provider=%r, endpoint=%r, model=%r, "
                "api_key=%r, timeout_seconds=%r, max_tokens=%r, "
                "temperature=%r)" % (
                    self.provider, self.endpoint, self.model,
                    "<redacted>" if self.has_api_key else "",
                    self.timeout_seconds, self.max_tokens,
                    self.temperature))

    __str__ = __repr__


def with_api_key(config: ProviderConfig, api_key: str) -> ProviderConfig:
    """Return a copy of `config` carrying `api_key` (frozen dataclass)."""
    return replace(config, api_key=api_key)


def default_provider_registry() -> ProviderRegistry:
    """A fresh registry carrying every provider Raphael ships.

    A NEW instance per call (no shared mutable global). Adding a
    provider is one `registry.register(...)` line here — never a branch
    in the planner, the agent loop, or an HTTP route.

    The builder imports `openai_compat` lazily to keep this module
    importable from the adapter it configures.
    """
    from raphael_ibm_bob.harness.providers.openai_compat import build_adapter

    registry = ProviderRegistry()
    registry.register(DEFAULT_PROVIDER, build_adapter)
    return registry


#: A builder turns a normalized config into a live `ModelAdapter`.
ProviderBuilder = Callable[[ProviderConfig], Any]


class ProviderRegistry:
    """Provider-id → adapter-builder registry.

    Explicit construction (dependency injection); no module-level
    mutable global. The planner never names a provider — it receives
    whatever `ModelAdapter` :meth:`create_adapter` returns.
    """

    def __init__(self) -> None:
        self._builders: Dict[str, ProviderBuilder] = {}

    def register(self, provider: str, builder: ProviderBuilder) -> None:
        key = (provider or "").strip()
        if not key:
            raise ProviderConfigError("provider id is required")
        if key in self._builders:
            raise ProviderConfigError(f"duplicate provider: {key!r}")
        if not callable(builder):
            raise ProviderConfigError(
                f"provider builder for {key!r} is not callable")
        self._builders[key] = builder

    def __contains__(self, provider: object) -> bool:
        return isinstance(provider, str) and provider.strip() in self._builders

    def __len__(self) -> int:
        return len(self._builders)

    def provider_ids(self) -> tuple:
        """Registered provider ids, sorted (stable for UI rendering)."""
        return tuple(sorted(self._builders))

    def create(self, config: ProviderConfig, registry=None):
        """Build the adapter for `config.provider` (or fail closed)."""
        try:
            builder = self._builders[config.provider]
        except KeyError:
            raise ProviderConfigError(
                f"unknown provider: {config.provider!r}; available: "
                f"{', '.join(self.provider_ids()) or 'none'}") from None
        return builder(config, registry)


#: Provider-declared default endpoints, used when the operator supplies
#: neither an endpoint field nor a server environment variable. Without
#: this, selecting a provider in the Agent UI and pasting a key still
#: failed with "RAPHAEL_MODEL_ENDPOINT is not set" — naming a variable
#: the operator never touched. The default is a FALLBACK only: an
#: explicit field or environment value always wins.
PROVIDER_DEFAULT_ENDPOINTS: Dict[str, str] = {
    "openai-compatible": "https://openrouter.ai/api/v1",
}


def provider_default_endpoint(provider: object) -> str:
    """The declared default endpoint for a provider, or "" if none."""
    key = provider.strip() if isinstance(provider, str) else ""
    return PROVIDER_DEFAULT_ENDPOINTS.get(key, "")


def _resolve(value: Optional[str], env_name: str,
             environ: Mapping[str, str], *, field: str = "",
             default: str = "") -> str:
    """Operator value > environment > provider default > raise.

    The error names the FORM FIELD an operator actually fills, with the
    environment variable as a secondary hint. It never names a value,
    so it is safe to surface in an HTTP response.
    """
    text = value.strip() if isinstance(value, str) else ""
    if text:
        return text
    from_env = (environ.get(env_name) or "").strip()
    if from_env:
        return from_env
    if default:
        return default
    label = field or env_name
    raise ProviderConfigError(
        f"{label} is required: fill it in the Agent console, or set "
        f"{env_name} in the server environment")


def _optional_int(value: Any, env_name: str, default: int,
                  environ: Mapping[str, str]) -> int:
    if value in (None, ""):
        raw = environ.get(env_name)
        if raw in (None, ""):
            return default
    else:
        raw = value
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        raise ProviderConfigError(f"{env_name} must be an integer") from None
    if parsed < 1:
        raise ProviderConfigError(f"{env_name} must be positive")
    return parsed


def _optional_float(value: Any, env_name: str, default: float,
                    environ: Mapping[str, str]) -> float:
    if value in (None, ""):
        raw = environ.get(env_name)
        if raw in (None, ""):
            return default
    else:
        raw = value
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        raise ProviderConfigError(f"{env_name} must be numeric") from None
    return parsed


def build_provider_config(
        provider: Optional[str] = None,
        *,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Any = None,
        max_tokens: Any = None,
        temperature: Any = None,
        environ: Optional[Mapping[str, str]] = None,
) -> ProviderConfig:
    """Normalize operator + environment input into a `ProviderConfig`.

    Operator-supplied fields take precedence; anything omitted falls
    back to the ``RAPHAEL_MODEL_*`` server environment, so an operator
    who configured the server once can leave the UI blank. Missing
    endpoint/model raise `ProviderConfigError` naming the field, before
    any network call is attempted.
    """
    from raphael_ibm_bob.harness.providers.openai_compat import (
        API_KEY_ENV,
        ENDPOINT_ENV,
        MODEL_ENV,
    )

    env = os.environ if environ is None else environ
    resolved_provider = (provider or "").strip() or DEFAULT_PROVIDER
    return ProviderConfig(
        provider=resolved_provider,
        endpoint=_resolve(
            endpoint, ENDPOINT_ENV, env,
            field="API endpoint",
            default=provider_default_endpoint(resolved_provider)),
        model=_resolve(model, MODEL_ENV, env, field="model"),
        # A credential is OPTIONAL: local and self-hosted
        # OpenAI-compatible endpoints authenticate with nothing. Only a
        # blank operator field falls back to the environment.
        api_key=(api_key.strip() if isinstance(api_key, str)
                 else (env.get(API_KEY_ENV) or "").strip()),
        timeout_seconds=_optional_float(
            timeout_seconds, "RAPHAEL_MODEL_TIMEOUT",
            DEFAULT_TIMEOUT_SECONDS, env),
        max_tokens=_optional_int(
            max_tokens, "RAPHAEL_MODEL_MAX_TOKENS", DEFAULT_MAX_TOKENS, env),
        temperature=_optional_float(
            temperature, "RAPHAEL_MODEL_TEMPERATURE",
            DEFAULT_TEMPERATURE, env),
    )


def with_api_key(config: ProviderConfig, api_key: str) -> ProviderConfig:
    """Return a copy of `config` carrying `api_key` (frozen dataclass)."""
    return replace(config, api_key=api_key)


__all__ = [
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_PROVIDER",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_TIMEOUT_SECONDS",
    "ProviderBuilder",
    "ProviderConfig",
    "ProviderRegistry",
    "build_provider_config",
    "default_provider_registry",
    "with_api_key",
]
