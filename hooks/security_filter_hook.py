#!/usr/bin/env python3
"""
Claude Code PreToolUse hook for opencode-security-filter.

Reads tool invocation JSON from stdin, extracts file paths,
and checks each against SecurityFilter. Blocks the tool call
if any path is denied.
"""

import json
import os
import shlex
import sys

# Add the opencode-security-filter source to sys.path so the import works
# without needing pip install. CLAUDE_PLUGIN_ROOT is set by Claude Code.
_plugin_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_src_dir = os.path.join(_plugin_root, "opencode-security-filter", "src")
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from opencode_security.filter import SecurityFilter


def extract_paths(tool_name: str, tool_input: dict) -> list[str]:
    """Extract file paths from tool input based on tool type."""
    paths: list[str] = []

    if tool_name in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = tool_input.get("file_path", "")
        if fp:
            paths.append(fp)
        for edit in tool_input.get("edits", []):
            fp = edit.get("file_path", "")
            if fp:
                paths.append(fp)

    elif tool_name in ("Glob", "Grep"):
        p = tool_input.get("path", "")
        if p:
            paths.append(p)

    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            paths.extend(_paths_from_bash(command))

    return paths


def _paths_from_bash(command: str) -> list[str]:
    """Best-effort path extraction from a bash command string.

    Extracts tokens that look like file paths (contain / or ~).
    The security filter decides what's actually blocked.
    """
    paths: list[str] = []
    try:
        tokens = shlex.split(command)
    except ValueError:
        return paths

    for token in tokens:
        if token.startswith("-"):
            continue
        if "/" in token or token.startswith("~"):
            paths.append(token)

    return paths


def main() -> None:
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    paths = extract_paths(tool_name, tool_input)
    if not paths:
        sys.exit(0)

    security_filter = SecurityFilter()

    for path in paths:
        result = security_filter.check(path)
        if result.decision == "deny":
            print(
                f"SECURITY BLOCK: Access to {path} denied. {result.reason}",
                file=sys.stderr,
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
