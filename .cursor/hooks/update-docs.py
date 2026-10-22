"""Follow up when code changes land without the project docs."""

from __future__ import annotations

import json
import subprocess
import sys

DOC_FILES = {"README.md", "documentation.md"}


def changed_paths() -> list[str]:
    output = subprocess.check_output(
        ["git", "status", "--porcelain"],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    paths: list[str] = []
    for line in output.splitlines():
        path = line[3:].strip().strip('"')
        if " -> " in path:
            path = path.split(" -> ", 1)[1].strip()
        paths.append(path.replace("\\", "/"))
    return paths


def main() -> None:
    try:
        sys.stdin.read()
    except Exception:
        pass
    try:
        paths = changed_paths()
    except Exception:
        print("{}")
        return
    code_changed = any(
        path.startswith("proxy_chain/") or path.startswith("tests/") or path.endswith(".py")
        for path in paths
    )
    docs_changed = any(path in DOC_FILES for path in paths)
    if code_changed and not docs_changed:
        print(
            json.dumps(
                {
                    "followup_message": (
                        "Code changed and README.md or documentation.md was not updated. "
                        "Update both files so they match the current modes, proxy list, CLI, "
                        "and control API. Do not write real proxy usernames or passwords into the docs."
                    )
                }
            )
        )
        return
    print("{}")


if __name__ == "__main__":
    main()
