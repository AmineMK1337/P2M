import logging
import os

logger = logging.getLogger(__name__)


class _AnthropicClient:
    def __init__(self, client, model: str):
        self._client = client
        self._model = model

    def invoke(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text if msg.content else ""


class _OpenAIClient:
    def __init__(self, client, model: str):
        self._client = client
        self._model = model

    def invoke(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=512,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""


def build_llm_client(provider: str | None = None, model: str | None = None, **kwargs):
    """
    Build an LLM client from env config.

    Reads LLM_PROVIDER and LLM_MODEL env vars; both can be overridden via args.
    Returns an object with .invoke(prompt: str) -> str, or None on failure.

    Supported providers: anthropic, openai, ollama
    kwargs:
        ollama_base_url: override OLLAMA_BASE_URL for the ollama provider
    """
    provider = (provider or os.getenv("LLM_PROVIDER", "anthropic")).strip().lower()
    model = model or os.getenv("LLM_MODEL", "")

    try:
        if provider == "anthropic":
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY", "")
            if not model:
                model = "claude-haiku-4-5-20251001"
            client = anthropic.Anthropic(api_key=api_key)
            logger.info("[LLMClient] Anthropic client ready (model=%s)", model)
            return _AnthropicClient(client, model)

        if provider == "openai":
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY", "")
            if not model:
                model = "gpt-4o-mini"
            client = OpenAI(api_key=api_key)
            logger.info("[LLMClient] OpenAI client ready (model=%s)", model)
            return _OpenAIClient(client, model)

        if provider == "ollama":
            from langchain_ollama import OllamaLLM
            base_url = (
                kwargs.get("ollama_base_url")
                or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            )
            if not model:
                model = "llama3.1"
            llm = OllamaLLM(model=model, base_url=base_url, temperature=0.1, num_predict=512)
            logger.info("[LLMClient] Ollama client ready (model=%s)", model)
            return llm

        logger.warning("[LLMClient] Unknown provider %r — returning None", provider)
        return None

    except Exception as exc:
        logger.warning("[LLMClient] Failed to build LLM client (provider=%s): %s", provider, exc)
        return None
