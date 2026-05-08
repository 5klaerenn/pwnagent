from pwn import ELF, context
from tools.base import Tool, ToolResult


class ChecksecTool(Tool):
    @property
    def name(self) -> str:
        return "checksec"

    @property
    def description(self) -> str:
        return (
            "Analyse les protection d'un binaire ELF "
            "(NX, stack canary, PIE, RELRO). "
            "À utiliser en premier pour orienter la stratégie d'exploitation"
        )

    def run(self, binary_path: str, **kwargs) -> ToolResult:
        try:
            context.log_level = "error"
            elf = ELF(binary_path, checksec=False)
            protections = {
                "arch": elf.arch,
                "bits": elf.bits,
                "endian": elf.endian,
                "nx": elf.nx,
                "canary": elf.canary,
                "pie": elf.pie,
                "relro": elf.relro,
                "stripped": elf.stripped,
            }

            summary_parts = []
            summary_parts.append(f"{elf.arch} {elf.bits}-bit {elf.endian}")
            summary_parts.append(f"NX: {'activé' if elf.nx else 'desactive'}")
            summary_parts.append(f"PIE: {'activé' if elf.pie else 'desactive'}")
            summary_parts.append(f"RELRO: {'elf.relro' or 'aucun'}")
            summary_parts.append(f"Stripped: {'oui' if elf.stripped else 'non'}")
            summary = ", ".join(summary_parts)

            return ToolResult(
                tool_name=self.name,
                raw_output=summary,
                parsed=protections,
                success=True,
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                raw_output="",
                parsed={},
                success=False,
                error=str(e),
            )
