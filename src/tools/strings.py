from ast import pattern
import re
import subprocess

from tools.base import Tool, ToolResult


class StringsTool(Tool):
    @property
    def name(self) -> str:
        return "strings"

    @property
    def description(self) -> str:
        return (
            "Extrait les chaînes de caractères intéressantes du binaire : "
            "messages utilisateur, chemins de fichiers, format strings, "
            "références à /bin/sh ou flag. Utile pour comprendre le "
            "comportement du programme sans décompiler."
        )

    def run(self, binary_path: str, **kwargs) -> ToolResult:
        try:
            result = subprocess.run(
                ["strings", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            all_strings = result.stdout.splitlines()

            patterns = {
                "shell": re.compile(r"/bin/sh|/bin/bash|/bin/cat"),
                "flag": re.compile(r"flag|FLAG|ctf|CTF"),
                "format_string": re.compile(r"%[0-9]*[sdxnp]"),
                "path": re.compile(r"^/[a-z]", re.IGNORECASE),
                "password": re.compile(r"pass|secret|key|admin", re.IGNORECASE),
                "network": re.compile(r"socket|connect|bind|listen"),
                "dangerouns_func": re.compile(
                    r"^(gets|strcpy|strcat|sprintf|scanf|system|execve)$"
                ),
            }

            flag_format = kwargs.get("flag_format")
            if flag_format:
                patterns["flag"] = re.compile(rf"{re.escape(flag_format)}\{{.*\}}")

            categorized = {category: [] for category in patterns}
            other_interest = []

            for s in all_strings:
                if len(s) < 4 or len(s) > 200:
                    continue

                matched = False
                for category, pattern in patterns.items():
                    if pattern.search(s):
                        categorized[category].append(s)
                        matched = True
                        break

                if not matched and re.search(r"[A-Z].*[a-z]|[a-z].*[A-Z]", s):
                    if len(s) > 10:
                        other_interest.append(s)

            for category in categorized:
                categorized[category] = categorized[category][:10]
            other_interest = other_interest[:15]

            parsed = {
                "total_strings": len(all_strings),
                "categorized": categorized,
                "other_interest": other_interest,
            }

            summary_parts = [f"{len(all_strings)} strings trouvées"]
            for category, strings in categorized.items():
                if strings:
                    summary_parts.append(f"{category}: {strings}")

            if other_interest:
                summary_parts.append(f"Autres: {other_interest[:5]}")

            summary = "\n".join(summary_parts)

            return ToolResult(
                tool_name=self.name,
                raw_output=summary,
                parsed=parsed,
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
