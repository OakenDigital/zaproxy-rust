#!/usr/bin/env python3
"""Choose CodeQL languages for one diff.

Rust paths never select Java, JavaScript, or Python. A change to this
script or codeql.yml selects all three so the workflow itself is scanned.
Any other path that is not Java, JavaScript, or Python selects none.
"""

from __future__ import annotations

import os
import subprocess
import sys

JAVA_EXACT = {
    "gradlew",
    "gradlew.bat",
    "gradle.properties",
    "build.gradle.kts",
    "settings.gradle.kts",
}
JAVA_PREFIXES = ("zap/", "buildSrc/", "gradle/")
JAVA_SUFFIXES = (".java", ".kt", ".kts", ".gradle")
JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs")
PY_PREFIXES = ("python/",)
WORKFLOW_FILES = {
    ".github/workflows/codeql.yml",
    ".github/workflows/codeql_paths.py",
}


def classify(paths: list[str]) -> dict[str, bool]:
    java = javascript = python = False
    for raw in paths:
        path = raw.strip()
        if not path or path.startswith("rust/"):
            continue
        if path in WORKFLOW_FILES:
            java = javascript = python = True
            continue
        if path.startswith(JAVA_PREFIXES) or path in JAVA_EXACT or path.endswith(JAVA_SUFFIXES):
            java = True
        if path.endswith(JS_SUFFIXES):
            javascript = True
        if path.endswith(".py") or path.startswith(PY_PREFIXES):
            python = True
    return {"java": java, "javascript": javascript, "python": python}


def changed_files() -> list[str]:
    event = os.environ.get("EVENT_NAME", "")
    if event == "pull_request":
        base = os.environ["BASE_SHA"]
        diff = subprocess.check_output(
            ["git", "diff", "--name-only", f"{base}...HEAD"],
            text=True,
        )
    elif event == "push":
        before = os.environ.get("BEFORE_SHA", "")
        if not before or set(before) <= {"0"}:
            diff = subprocess.check_output(["git", "ls-files"], text=True)
        else:
            head = os.environ.get("HEAD_SHA") or "HEAD"
            diff = subprocess.check_output(
                ["git", "diff", "--name-only", before, head],
                text=True,
            )
    else:
        raise SystemExit(f"unsupported EVENT_NAME {event!r}")
    return [line for line in diff.splitlines() if line]


def main() -> int:
    result = classify(changed_files())
    for key in ("java", "javascript", "python"):
        print(f"{key}={'true' if result[key] else 'false'}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            for key in ("java", "javascript", "python"):
                handle.write(f"{key}={'true' if result[key] else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
