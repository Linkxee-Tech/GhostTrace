import os
import time

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None


def _generate_text(client, model: str, prompt: str, max_tokens: int) -> str:
    if hasattr(client, "responses"):
        resp = client.responses.create(model=model, input=prompt, max_output_tokens=max_tokens)
        return (getattr(resp, "output_text", "") or "").strip()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
    )
    return ((resp.choices[0].message.content if resp and resp.choices else "") or "").strip()


def _is_rate_limited(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    if "ratelimit" in name:
        return True
    status = getattr(exc, "status_code", None)
    if status == 429:
        return True
    return "429" in str(exc)


def generate_with_fallback(prompt: str, max_tokens: int = 220, primary_model: str = "gpt-4.1-mini") -> str | None:
    if OpenAI is None:
        return None

    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    providers = []
    if openai_key:
        try:
            providers.append(
                (
                    "openai",
                    OpenAI(api_key=openai_key),
                    [os.getenv("OPENAI_MODEL", "").strip() or primary_model, "gpt-4o-mini"],
                )
            )
        except Exception:
            pass
    if groq_key:
        try:
            providers.append(
                (
                    "groq",
                    OpenAI(api_key=groq_key, base_url="https://api.groq.com/openai/v1"),
                    [os.getenv("GROQ_MODEL", "").strip() or "llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
                )
            )
        except Exception:
            pass

    for _, client, models in providers:
        seen = set()
        for model in models:
            if model in seen:
                continue
            seen.add(model)
            for attempt in range(3):
                try:
                    text = _generate_text(client, model, prompt, max_tokens=max_tokens)
                    if text:
                        return text
                except Exception as exc:
                    if _is_rate_limited(exc) and attempt < 2:
                        time.sleep(1.2 * (attempt + 1))
                        continue
                    break
    return None
