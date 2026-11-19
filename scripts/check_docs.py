"""Check the maintainer documentation, local links, and release version."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md",
    "SECURITY.md",
    "RELEASE_NOTES.md",
    "docs/README.md",
    "docs/PROJECT_LEDGER.md",
    "docs/ARCHITECTURE.md",
    "docs/PROTOCOL_COMPATIBILITY.md",
    "docs/SECURITY_MODEL.md",
    "docs/DEVELOPMENT.md",
    "docs/OPERATIONS.md",
    "docs/RELEASING.md",
    "docs/HANDOFF.md",
)
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def check() -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED:
        file = ROOT / relative
        if not file.is_file():
            errors.append(f"Missing required document: {relative}")
            continue
        text = file.read_text(encoding="utf-8")
        if not text.strip():
            errors.append(f"Empty document: {relative}")
        for match in LINK.finditer(text):
            target = match.group(1).strip().split(maxsplit=1)[0]
            if target.startswith(("#", "//")) or re.match(r"^[a-zA-Z][\w+.-]*:", target):
                continue
            local_path = unquote(target.split("#", 1)[0].split("?", 1)[0])
            if not local_path:
                continue
            resolved = (file.parent / local_path).resolve()
            if not resolved.is_relative_to(ROOT) or not resolved.exists():
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"Broken local link: {relative}:{line}: {target}")

    project_file = ROOT / "pyproject.toml"
    package_file = ROOT / "rdheadless" / "__init__.py"
    if project_file.is_file() and package_file.is_file():
        version = tomllib.loads(project_file.read_text(encoding="utf-8"))["project"]["version"]
        source = package_file.read_text(encoding="utf-8")
        match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", source, re.MULTILINE)
        if match is None or match.group(1) != version:
            errors.append("pyproject.toml and rdheadless/__init__.py have different versions")
        notes = ROOT / "RELEASE_NOTES.md"
        if notes.is_file() and f"v{version}" not in notes.read_text(encoding="utf-8"):
            errors.append("RELEASE_NOTES.md must describe the current version")
        ledger = ROOT / "docs" / "PROJECT_LEDGER.md"
        if ledger.is_file() and version not in ledger.read_text(encoding="utf-8"):
            errors.append("docs/PROJECT_LEDGER.md must mention the current version")
    else:
        errors.append("Missing application version metadata")
    return errors


if __name__ == "__main__":
    failures = check()
    if failures:
        print("\n".join(failures), file=sys.stderr)
        raise SystemExit(1)
    print("Documentation links and release metadata: OK")
