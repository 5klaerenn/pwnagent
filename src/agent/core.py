import argparse
import json
import sys
from pathlib import Path

from agent.llm import LLMClient
from agent.prompts import REACT_PROMPT
from tools.checksec import ChecksecTool
from tools.fileinfo import FileInfoTool
from tools.strings import StringsTool

MAX_ITERATIONS = 8


def run_agent(
    binary_path: str, llm: LLMClient, tools: dict, flag_format: str | None = None
):
    """Boucle ReAct : think -> act -> observe, jusqu'à conclusion."""

    history = []

    for iteration in range(1, MAX_ITERATIONS + 1):
        tools_desc = "\n".join(
            f"- {name}: {tool.description}" for name, tool in tools.items()
        )

        history_text = ""
        if history:
            for step in history:
                history_text += f"\n### Étape {step['iteration']}\n"
                history_text += f"Raisonnement: {step['reasoning']}\n"
                history_text += f"Outil: {step['tool']}"
                history_text += f"Résultat: {json.dumps(step['result'], indent=2, ensure_ascii=False)}\n"
        else:
            history_text = "(aucune observation pour le moment)"

        prompt = REACT_PROMPT.format(
            binary_path=binary_path,
            tools=tools_desc,
            history=history_text,
            iteration=iteration,
            max_iterations=MAX_ITERATIONS,
        )

        print(f"\n[*] Itération {iteration}/{MAX_ITERATIONS} - En réflexion ...")

        try:
            decision = llm.complete(prompt)
        except Exception as e:
            print(f"[-] Erreur LLM : {e}")
            break

        # Conclusion
        if decision.get("action") == "conclude":
            print(f"\n[+] Conclusion (iteration {iteration}):")
            conclusion = decision.get("conclusion", {})
            print(f"    Vulnérabilité : {conclusion.get('vulnerability_type', '?')}")
            print(f"    Confiance : {conclusion.get('confidence', '?')}")
            print(f"    Vecteur: {conclusion.get('attack_vector', '?')}")
            print(f"    Approche exploit: {conclusion.get('exploit_approach', '?')}")
            findings = conclusion.get("key_findings", [])
            if findings:
                print(f"    Decouvertes:")
                for f in findings:
                    print(f"    - {f}")
            return conclusion

        if decision.get("action") == "use_tool":
            tool_name = decision.get("tool", "")
            reasoning = decision.get("reasoning", "")

            print(f"    Raisonnement : {reasoning}")
            print(f"    Outil choisi : {tool_name}")

            if tool_name not in tools:
                print(f"[-] Outil inconnu : {tool_name}")
                history.append(
                    {
                        "iteration": iteration,
                        "reasoning": reasoning,
                        "tool": tool_name,
                        "result": {"error": f"Outil '{tool_name}' n'existe pas"},
                    }
                )
                continue

            tool = tools[tool_name]
            kwargs = {}
            if tool_name == "strings" and flag_format:
                kwargs["flag_format"] = flag_format

            result = tool.run(binary_path, **kwargs)

            if result.success:
                print(f"[+] {tool_name} : OK")
            else:
                print(f"[-] {tool_name} : {result.error}")

            history.append(
                {
                    "iteration": iteration,
                    "reasoning": reasoning,
                    "tool": tool_name,
                    "result": result.parsed
                    if result.success
                    else {"error": result.error},
                }
            )
            continue

        print(f"[-] Réponse LLM invalide : {decision}")
        break

    print("\n[-] Nombre max d'iterations atteint sans conclusion.")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Agent IA pour la triage de challenges CTF pwn"
    )
    parser.add_argument(
        "binary",
        type=Path,
        help="Chemin vers le binaire ELF à analyser",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="llama3.1:8b",
        help="Modèle Ollama à utiliser (defaut : llama3.1:8b)",
    )
    parser.add_argument(
        "--flag-format",
        type=str,
        default=None,
        help="Préfixe du flag",
    )

    args = parser.parse_args()

    if not args.binary.exists():
        print(f"Erreur : fichier introuvage - {args.binary}")
        sys.exit(1)

    with open(args.binary, "rb") as f:
        magic = f.read(4)
    if magic != b"\x7fELF":
        print(f"Erreur : {args.binary} n'est pas un binaire ELF")
        sys.exit(1)

    print(f"Cible : {args.binary}")
    print(f"Modèle : {args.model}")

    llm = LLMClient(model=args.model)

    tools = {}
    for tool_class in [ChecksecTool, FileInfoTool, StringsTool]:
        tool = tool_class()
        tools[tool.name] = tool

    print(f"[*] Outils disponiobles : {', '.join(tools.keys())}")
    print("[*] Lancement de l'analyse ... \n")

    run_agent(str(args.binary), llm, tools, flag_format=args.flag_format)


if __name__ == "__main__":
    main()
