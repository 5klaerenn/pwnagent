import json
import httpx


class LLMClient:
    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.base_url = "http://localhost:11434"

    def complete(self, prompt: str) -> dict:
        """Envoie un prompt a Ollama et retourne une réponse en JSON"""
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
            },
            timeout=120,
        )
        response.raise_for_status()

        raw_text = response.json()["response"]

        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            cleaned = (
                raw_text.strip().removeprefix("```json").removesuffic("```").strip()
            )
            return json.loads(cleaned)
