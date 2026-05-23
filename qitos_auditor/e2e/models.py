"""Model endpoint definitions for auditor e2e testing.

Defines 6 LLM endpoints with their API keys, base URLs, model names,
family presets, and thinking-mode configurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ModelEndpoint:
    """A specific LLM endpoint configuration."""

    name: str
    base_url: str
    api_key: str
    model: str
    family_id: str
    default_request_kwargs: Dict[str, Any] = field(default_factory=dict)
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 300
    context_window: Optional[int] = None


MODEL_ENDPOINTS: Dict[str, ModelEndpoint] = {
    "deepseek-v4-pro": ModelEndpoint(
        name="DeepSeek-V4-Pro",
        base_url="https://o8kjqm58o8ogcm5ek8aggddkb5ggk8dp.openapi-sj.sii.edu.cn/v1",
        api_key="MajUa5noC1OtfZ3RxznY23AZYWYisTPGc4MKZJyXB9Q=",
        model="ds-v4-pro",
        family_id="deepseek",
        default_request_kwargs={"chat_template_kwargs": {"thinking": True}},
    ),
    "deepseek-v4-flash": ModelEndpoint(
        name="DeepSeek-V4-Flash",
        base_url="https://ds-v4-flash-w8a8-vllm-ascend.openapi-sj.sii.edu.cn/v1",
        api_key="stpmj/4hRawPjQCf0fk70W6HnObgXtkonX3qHCCNsPc=",
        model="ds-v4-flash",
        family_id="deepseek",
        default_request_kwargs={"chat_template_kwargs": {"thinking": True}},
    ),
    "glm-5.1": ModelEndpoint(
        name="GLM-5.1",
        base_url="https://cbpecq8oomh5cpbbk9gm5ck85cbpoaoe.openapi-sj.sii.edu.cn/v1",
        api_key="stpmj/4hRawPjQCf0fk70W6HnObgXtkonX3qHCCNsPc=",
        model="glm5.1-w4a8-4maas",
        family_id="glm",
        # Thinking ON by default; no kwargs needed to enable it
        default_request_kwargs={},
    ),
    "kimi-k2.6": ModelEndpoint(
        name="Kimi-K2.6",
        base_url="https://jqdmppbopbaacp9ajcaqem88gqobcd9m.openapi-sj.sii.edu.cn/v1",
        api_key="PXD1xpmXaRQthNTPHJZJYv0nMl3YBcf/mDZJ+dg2lU8=",
        model="kimi-k2.6-w4a8",
        family_id="kimi",
        # Thinking ON by default; no kwargs needed to enable it
        default_request_kwargs={},
    ),
    "qwen3.5-397b": ModelEndpoint(
        name="Qwen3.5-397b",
        base_url="https://poa8q9p9be88cde9kaggb5occdmgcdam.openapi-sj.sii.edu.cn/v1",
        api_key="stpmj/4hRawPjQCf0fk70W6HnObgXtkonX3qHCCNsPc=",
        model="Qwen3.5-397B-A17B-w4a8-mtp",
        family_id="qwen",
        # Thinking ON by default; no kwargs needed to enable it
        default_request_kwargs={},
    ),
    "minimax-m2.7": ModelEndpoint(
        name="MiniMax-M2.7",
        base_url="https://hqdaoabjb89cc5gkkp59me9h9e5dpkhm.openapi-sj.sii.edu.cn/v1",
        api_key="EnlfIIG26Oo7LPZTmjSqdvx8gf57VSsaUnpXT8CuYRc=",
        model="MiniMax-M2.7-w8a8",
        family_id="minimax",
        default_request_kwargs={},
    ),
}


def build_llm_for_endpoint(endpoint_name: str) -> Any:
    """Build an LLM instance for a named model endpoint.

    Uses the harness system to resolve presets, protocols, and tool policies,
    then injects default_request_kwargs for chat_template_kwargs support.
    """
    from qitos.harness import build_model_for_preset

    if endpoint_name not in MODEL_ENDPOINTS:
        raise ValueError(
            f"Unknown model endpoint: {endpoint_name}. "
            f"Available: {list(MODEL_ENDPOINTS.keys())}"
        )

    ep = MODEL_ENDPOINTS[endpoint_name]
    llm = build_model_for_preset(
        model_name=ep.model,
        family_id=ep.family_id,
        api_key=ep.api_key,
        base_url=ep.base_url,
        temperature=ep.temperature,
        max_tokens=ep.max_tokens,
        timeout=ep.timeout,
        context_window=ep.context_window,
        default_request_kwargs=ep.default_request_kwargs or None,
    )
    # Ensure default_request_kwargs is set (in case adapter doesn't pass it through)
    if ep.default_request_kwargs:
        existing = getattr(llm, "default_request_kwargs", None) or {}
        existing.update(ep.default_request_kwargs)
        llm.default_request_kwargs = existing

    return llm
