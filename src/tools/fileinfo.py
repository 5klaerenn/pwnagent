import re
import subprocess

from tools.base import Tool, ToolResult


class FileInfoTool(Tool):
    @property
    def name(self) -> str:
        return "fileinfo"

    @property
    def description(self) -> str:
        return (
            "Récupère les métadonnées d'un binaire ELF via file et readelf : "
            "type de linking (statique/dynamique), librairies liées, "
            "sections présentes. Utile pour déterminer la stratégie "
            "d'exploitation (ret2libc possible seulement si dynamique)."
        )

    def run(self, binary_path: str, **kwargs) -> ToolResult:
        try:
            file_result = subprocess.run(
                ["file", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            file_output = file_result.stdout.strip()

            dynamic_result = subprocess.run(
                ["readelf", "-d", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            symbols_result = subprocess.run(
                ["readelf", "-s", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            is_static = "statically linked" in file_output
            is_stripped = "striped" in file_output and "not stripped" not in file_output

            librairies = []
            for line in dynamic_result.stdout.splitlines():
                if "NEEDED" in line:
                    lib = line.split("[")[1].split("]")[0] if "[" in line else ""
                    if lib:
                        librairies.append(lib)

            dangerous_functions = [
                "gets",
                "strcpy",
                "strcat",
                "sprintf",
                "scanf",
                "read",
                "printf",
                "system",
                "execve",
                "mprotect",
            ]
            found_functions = []
            for line in symbols_result.stdout.splitlines():
                for func in dangerous_functions:
                    if f"{func}@" in line or f" {func}\n" in line:
                        found_functions.append(func)

            found_functions = list(set(found_functions))

            parsed = {
                "file_output": file_output,
                "static": is_static,
                "stripped": is_stripped,
                "librairies": librairies,
                "dangerous_functions": found_functions,
            }

            summary_parts = [file_output]
            if librairies:
                summary_parts.append(f"Libs: {', '.join(librairies)}")
            if found_functions:
                summary_parts.append(
                    f"Fonctions dangereuses: {', '.join(found_functions)}"
                )

            summary = "\n".join(summary_parts)

            return ToolResult(
                tool_name=self.name, raw_output=summary, parsed=parsed, success=True
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                raw_output="",
                parsed={},
                success=False,
                error=str(e),
            )
