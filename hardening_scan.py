"""Prototipo extendido: escaneo generico de invariantes de endurecimiento.

No depende de C2-DECT. Escanea cualquier directorio. Incluye 7 reglas,
severidades, resumen, baseline_type ratchet (nuevos vs. corregidos) e informe
JSON. Disenado para ser un gate de CI con baseline 0.

Reglas
------
HARD-01 secreto de desarrollo hardcodeado        (critical)
HARD-02 clave privada versionada                  (high)
HARD-03 bind por defecto en 0.0.0.0               (high)
HARD-04 variable de entorno obligatoria no doc.   (medium)
HARD-05 escape hatch sin aviso visible            (medium)
HARD-06 verificacion TLS deshabilitada            (high)
HARD-07 dependencias sin fijar en requirements    (low)
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SEVERITY = {
    "HARD-01": "critical",
    "HARD-02": "high",
    "HARD-03": "high",
    "HARD-04": "medium",
    "HARD-05": "medium",
    "HARD-06": "high",
    "HARD-07": "low",
}

FORBIDDEN_TOKENS = (
    "dev-secret-change-me",
    "secret-key-change-me",
    "changeme-secret",
)
TEXT_EXTENSIONS = {".go", ".py", ".kt", ".cs", ".js", ".ts", ".java", ".yml", ".yaml"}
KEY_EXTENSIONS = {".key", ".pem", ".pfx", ".p12"}
BIND_RE = re.compile(r'(?:defaultAddr|bind|listen)\s*[:=]\s*["\']0\.0\.0\.0')
ESCAPE_RE = re.compile(r"(?:C2_ALLOW_|ALLOW_[A-Z_]+\s*=\s*1)")
TLS_OFF_RE = re.compile(r"(?:verify\s*=\s*False|InsecureSkipVerify|verify_ssl\s*=\s*False)")


def _finding(rule: str, path: str, line: int, detail: str) -> dict:
    return {
        "rule": rule,
        "severity": SEVERITY[rule],
        "path": path,
        "line": line,
        "detail": detail,
    }


def scan(root: str | Path, env_var: str = "C2_FRAME_SECRET") -> list[dict]:
    root = Path(root)
    findings: list[dict] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        text = (
            path.read_text(encoding="utf-8", errors="replace")
            if path.suffix.lower() in TEXT_EXTENSIONS
            or path.name.startswith(".env")
            or path.name.startswith("requirements")
            else ""
        )

        if path.suffix.lower() in KEY_EXTENSIONS:
            findings.append(_finding("HARD-02", rel, 0, "clave privada versionada"))

        if path.name.startswith(".env"):
            if env_var not in text:
                findings.append(_finding("HARD-04", rel, 0, f"{env_var} no documentado"))

        if path.name.startswith("requirements") and path.suffix == ".txt":
            for lineno, line in enumerate(text.splitlines(), 1):
                value = line.strip()
                if not value or value.startswith(("#", "-", "git+")):
                    continue
                if "==" not in value:
                    findings.append(_finding("HARD-07", rel, lineno, f"sin fijar: {value}"))

        if path.suffix.lower() in TEXT_EXTENSIONS:
            has_warning = re.search(r"(?:warn|aviso|advert)", text, re.IGNORECASE)
            for lineno, line in enumerate(text.splitlines(), 1):
                for token in FORBIDDEN_TOKENS:
                    if token in line:
                        findings.append(_finding("HARD-01", rel, lineno, token))
                if BIND_RE.search(line):
                    findings.append(_finding("HARD-03", rel, lineno, "bind 0.0.0.0"))
                if ESCAPE_RE.search(line) and not has_warning:
                    findings.append(_finding("HARD-05", rel, lineno, "escape hatch sin aviso"))
                if TLS_OFF_RE.search(line):
                    findings.append(_finding("HARD-06", rel, lineno, "TLS deshabilitado"))

    return findings


def summarize(findings: list[dict]) -> dict:
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in findings:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    return {
        "total": len(findings),
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "verdict": "FAIL" if findings else "PASS",
    }


def make_baseline(findings: list[dict]) -> list[str]:
    return sorted({f"{f['rule']}:{f['path']}" for f in findings})


def diff_baseline(findings: list[dict], baseline: list[str]) -> dict:
    current = set(make_baseline(findings))
    old = set(baseline)
    return {"new": sorted(current - old), "fixed": sorted(old - current)}


def load_baseline(path: str | Path) -> list[str]:
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--env-var", default="C2_FRAME_SECRET")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--baseline")
    parser.add_argument("--write-baseline")
    args = parser.parse_args()

    findings = scan(args.root, args.env_var)
    report = {"summary": summarize(findings), "findings": findings}
    if args.baseline:
        report["baseline_diff"] = diff_baseline(findings, load_baseline(args.baseline))

    if args.write_baseline:
        Path(args.write_baseline).write_text(
            "\n".join(make_baseline(findings)) + "\n", encoding="utf-8"
        )

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print(f"[{f['severity'].upper()}] {f['rule']} {f['path']}:{f['line']} {f['detail']}")
        print(json.dumps(report["summary"], ensure_ascii=False))

    blocking = report["summary"]["total"] > 0
    if args.baseline:
        blocking = bool(report["baseline_diff"]["new"])
    raise SystemExit(1 if blocking else 0)


if __name__ == "__main__":
    main()
