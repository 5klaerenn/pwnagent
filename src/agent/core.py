import argparse
import sys
from pathlib import Path
from tools.checksec import ChecksecTool


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
    print("Analyse en cours ...")

    checksec = ChecksecTool()
    result = checksec.run(str(args.binary))

    if result.success:
        print(f"\n[+] checksec : {result.raw_output}")
        for key, value in result.parsed.items():
            print(f"    {key}: {value}")
    else:
        print(f"\n[-] checksec a échoué : {result.error}")


if __name__ == "__main__":
    main()
