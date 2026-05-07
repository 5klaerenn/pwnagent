from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """Résultat standardisé retourné par chaque outil"""

    tool_name: str
    raw_output: str
    parsed: dict = field(default_factory=dict)
    success: bool = True
    error: str | None = None


class Tool(ABC):
    """Interface commune pour tous les outils de l'agent."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Identifiant de l'outil"""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Description pour le LLM : quand et pourquoi utiliser cet outil"""
        ...

    @abstractmethod
    def run(self, binary_path: str, **kwargs) -> ToolResult:
        """Éxecute l'outil sur le binaire et retour ToolResult"""
        ...
